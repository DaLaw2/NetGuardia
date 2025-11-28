use std::collections::HashMap;
use std::ffi::CString;
use std::io::Write;
use std::num::NonZero;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use aya::Ebpf;
use aya::maps::{MapData, XskMap};
use crossbeam::channel::{Receiver, Sender, bounded};
use crossbeam::queue::SegQueue;
use macros::log;
use parking_lot::Mutex;
use tokio::sync::oneshot;
use xsk_rs::config::{BindFlags, FrameSize, Interface, LibxdpFlags, QueueSize, SocketConfig, UmemConfig};
use xsk_rs::{CompQueue, FillQueue, FrameDesc, RxQueue, Socket, TxQueue, Umem};

use crate::core::infrastructure::app_config::AppConfig;
use crate::ml::detection_manager::DetectionManager;
use crate::model::config::Config;
use crate::model::error::Error;
use crate::model::error::ebpf::EbpfError;
use crate::model::error::system::SystemError;
use crate::model::log::ebpf::EbpfLog;
use crate::utils::packet_parser;

const CHANNEL_SIZE: usize = 4096;
const ML_CHANNEL_SIZE: usize = 1024;

pub struct XskManager {
    app_config: Arc<AppConfig>,
    xsk_map: Mutex<XskMap<MapData>>,
    detection_manager: Option<Arc<DetectionManager>>,
    shutdowns: SegQueue<oneshot::Sender<()>>,
    ml_shutdowns: SegQueue<oneshot::Sender<()>>,
}

impl XskManager {
    pub fn new(
        app_config: Arc<AppConfig>,
        ebpf: &mut Ebpf,
        detection_manager: Option<Arc<DetectionManager>>,
    ) -> Result<Self, Error> {
        let map = ebpf.take_map("XSKS_MAP").ok_or(EbpfError::MapNotFound)?;
        let xsk_map = XskMap::try_from(map).map_err(EbpfError::MapOperationError)?;

        Ok(Self {
            app_config,
            xsk_map: Mutex::new(xsk_map),
            detection_manager,
            shutdowns: SegQueue::new(),
            ml_shutdowns: SegQueue::new(),
        })
    }

    pub fn run(&self) -> Result<(), Error> {
        let config = self.app_config.config.clone();
        let combined_queue_count = config.combined_queue_count;

        for queue_id in 0..combined_queue_count {
            let (ingress_to_egress_tx, ingress_to_egress_rx) = bounded(CHANNEL_SIZE);
            let (egress_to_ingress_tx, egress_to_ingress_rx) = bounded(CHANNEL_SIZE);

            let (ingress_xsk, ingress_ml_shutdown) = XskPair::new(
                config.clone(),
                queue_id,
                &config.ingress_ifname,
                &config.egress_ifname,
                Direction::Ingress,
                self.detection_manager.clone(),
            )?;

            let (egress_xsk, egress_ml_shutdown) = XskPair::new(
                config.clone(),
                queue_id,
                &config.egress_ifname,
                &config.ingress_ifname,
                Direction::Egress,
                self.detection_manager.clone(),
            )?;

            if let Some(shutdown) = ingress_ml_shutdown {
                self.ml_shutdowns.push(shutdown);
            }
            if let Some(shutdown) = egress_ml_shutdown {
                self.ml_shutdowns.push(shutdown);
            }

            let mut xsk_map = self.xsk_map.lock();
            let ingress_fd = ingress_xsk.rx.fd().as_raw_fd();
            xsk_map
                .set(queue_id, ingress_fd, 0)
                .map_err(EbpfError::AfXdpSetFailed)?;
            drop(xsk_map);

            let ingress_shutdown = ingress_xsk.run(ingress_to_egress_tx, egress_to_ingress_rx);
            self.shutdowns.push(ingress_shutdown);

            let egress_shutdown = egress_xsk.run(egress_to_ingress_tx, ingress_to_egress_rx);
            self.shutdowns.push(egress_shutdown);

            log!(EbpfLog::QueuePairStarted(queue_id));
        }

        Ok(())
    }

    pub fn shutdown(&self) {
        while let Some(sender) = self.ml_shutdowns.pop() {
            if sender.send(()).is_err() {
                tracing::warn!("Failed to send ML shutdown signal");
            }
        }

        while let Some(sender) = self.shutdowns.pop() {
            if sender.send(()).is_err() {
                log!(SystemError::ShutdownSignalFailed);
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Direction {
    Ingress,
    Egress,
}

pub struct XskPair {
    direction: Direction,
    umem: Arc<Umem>,
    fill_queue: FillQueue,
    comp_queue: CompQueue,
    tx: TxQueue,
    rx: RxQueue,
    frame_pool: Arc<Mutex<Vec<FrameDesc>>>,
    ml_channel: Option<Sender<Vec<u8>>>,
}

impl XskPair {
    pub fn new(
        config: Config,
        queue_id: u32,
        rx_ifname: &str,
        tx_ifname: &str,
        direction: Direction,
        detection_manager: Option<Arc<DetectionManager>>,
    ) -> Result<(Self, Option<oneshot::Sender<()>>), Error> {
        let rx_ifname_c = CString::new(rx_ifname).map_err(|_| SystemError::UnknownError)?;

        let fill_queue_size = QueueSize::new(config.fill_queue_size).map_err(|_| SystemError::InvalidConfig)?;
        let comp_queue_size = QueueSize::new(config.comp_queue_size).map_err(|_| SystemError::InvalidConfig)?;
        let tx_queue_size = QueueSize::new(config.tx_queue_size).map_err(|_| SystemError::InvalidConfig)?;
        let rx_queue_size = QueueSize::new(config.rx_queue_size).map_err(|_| SystemError::InvalidConfig)?;
        let frame_size = FrameSize::new(config.frame_size).map_err(|_| SystemError::InvalidConfig)?;
        let frame_count = NonZero::new(config.frame_count).ok_or(SystemError::InvalidConfig)?;

        let umem_config = UmemConfig::builder()
            .fill_queue_size(fill_queue_size)
            .comp_queue_size(comp_queue_size)
            .frame_size(frame_size)
            .frame_headroom(0)
            .build()
            .map_err(EbpfError::UmemSetFailed)?;

        let (umem, frame_descs) = Umem::new(umem_config, frame_count, false).map_err(EbpfError::UmemSetFailed)?;

        let socket_config = SocketConfig::builder()
            .tx_queue_size(tx_queue_size)
            .rx_queue_size(rx_queue_size)
            .bind_flags(BindFlags::XDP_ZEROCOPY)
            .libxdp_flags(LibxdpFlags::XSK_LIBXDP_FLAGS_INHIBIT_PROG_LOAD)
            .build();

        let interface = Interface::new(rx_ifname_c);

        let (tx, rx, queue) = unsafe {
            Socket::new(socket_config, &umem, &interface, queue_id)
                .map_err(EbpfError::SocketSetFailed)?
        };

        let (mut fill_queue, comp_queue) = queue.ok_or(EbpfError::UnknownError)?;

        let total_frames = frame_descs.len();
        let fill_frames_count = (total_frames / 2).min(config.fill_queue_size as usize);

        let fill_frames: Vec<FrameDesc> = frame_descs.iter().take(fill_frames_count).copied().collect();

        let submitted = unsafe { fill_queue.produce(&fill_frames) };
        if submitted != fill_frames.len() {
            log!(EbpfLog::QueueInitIncomplete);
        }

        let pool_frames: Vec<FrameDesc> = frame_descs.iter().skip(fill_frames_count).copied().collect();

        let (ml_channel, ml_shutdown) = if let Some(dm) = detection_manager {
            let (ml_tx, ml_rx) = bounded::<Vec<u8>>(ML_CHANNEL_SIZE);
            let (shutdown_tx, shutdown_rx) = oneshot::channel();

            let dm_clone = dm.clone();
            let dir = direction;
            thread::Builder::new()
                .name(format!("ml-processor-{:?}-{}", direction, queue_id))
                .spawn(move || {
                    let mut shutdown_rx = Some(shutdown_rx);
                    let mut processed_count = 0u64;

                    loop {
                        if let Some(ref mut rx) = shutdown_rx {
                            if rx.try_recv().is_ok() {
                                tracing::info!(
                                    "{:?} ML processor shutting down (processed {} packets)",
                                    dir,
                                    processed_count
                                );
                                break;
                            }
                        }

                        match ml_rx.recv_timeout(Duration::from_millis(100)) {
                            Ok(packet_data) => {
                                if let Some(event) = packet_parser::parse_packet(&packet_data) {
                                    dm_clone.process_event(&event);
                                    processed_count += 1;
                                }
                            }
                            Err(crossbeam::channel::RecvTimeoutError::Timeout) => {
                                // Timeout, continue looping to check shutdown
                                continue;
                            }
                            Err(crossbeam::channel::RecvTimeoutError::Disconnected) => {
                                tracing::warn!("{:?} ML channel disconnected", dir);
                                break;
                            }
                        }
                    }
                })
                .map_err(EbpfError::AfXdpSetFailed)?;

            (Some(ml_tx), Some(shutdown_tx))
        } else {
            (None, None)
        };

        tracing::info!(
            "{:?} queue {}: Initialized with {} total frames ({} for fill queue, {} for TX pool){}",
            direction,
            queue_id,
            total_frames,
            fill_frames_count,
            pool_frames.len(),
            if ml_channel.is_some() { " + ML processing" } else { "" }
        );

        let xsk_pair = Self {
            direction,
            umem: Arc::new(umem),
            fill_queue,
            comp_queue,
            tx,
            rx,
            frame_pool: Arc::new(Mutex::new(pool_frames)),
            ml_channel,
        };

        Ok((xsk_pair, ml_shutdown))
    }

    pub fn run(mut self, forward_tx: Sender<Vec<u8>>, forward_rx: Receiver<Vec<u8>>) -> oneshot::Sender<()> {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        thread::Builder::new()
            .name(format!("xsk-{:?}", self.direction))
            .spawn(move || {
                let mut shutdown_rx = Some(shutdown_rx);

                loop {
                    if let Some(ref mut rx) = shutdown_rx {
                        if rx.try_recv().is_ok() {
                            break;
                        }
                    }

                    let _ = self.process_comp_queue();

                    let _ = self.process_rx_queue(&forward_tx);

                    let _ = self.process_tx_queue(&forward_rx);

                    thread::sleep(Duration::from_micros(1));
                }

                tracing::info!("{:?} XSK thread shutting down", self.direction);
            })
            .expect("Failed to spawn XSK thread");

        shutdown_tx
    }

    fn process_comp_queue(&mut self) -> Result<(), EbpfError> {
        let mut comp_descs = vec![FrameDesc::default(); 256];

        let nb_completed = unsafe { self.comp_queue.consume(&mut comp_descs) };

        if nb_completed > 0 {
            let mut pool = self.frame_pool.lock();
            let pool_size_before = pool.len();

            for desc in comp_descs.iter().take(nb_completed) {
                pool.push(*desc);
            }

            tracing::trace!(
                "{:?}: Recycled {} frames to pool (pool: {} -> {})",
                self.direction,
                nb_completed,
                pool_size_before,
                pool.len()
            );
        }

        Ok(())
    }

    fn process_rx_queue(&mut self, forward_tx: &Sender<Vec<u8>>) -> Result<(), EbpfError> {
        let mut rx_descs = vec![FrameDesc::default(); 64];
        let rx_count = unsafe { self.rx.consume(&mut rx_descs) };

        if rx_count > 0 {
            for rx_desc in rx_descs.iter().take(rx_count) {
                let lengths = rx_desc.lengths();
                let packet_len = lengths.data() as usize;

                let data = unsafe { self.umem.data(rx_desc) };
                let packet_data = data.contents()[..packet_len].to_vec();

                if let Some(ref ml_tx) = self.ml_channel {
                    match ml_tx.try_send(packet_data.clone()) {
                        Ok(_) => {
                            tracing::trace!("{:?}: Sent packet to ML channel", self.direction);
                        }
                        Err(crossbeam::channel::TrySendError::Full(_)) => {
                            tracing::trace!("{:?}: ML channel full, skipping packet", self.direction);
                        }
                        Err(crossbeam::channel::TrySendError::Disconnected(_)) => {
                            tracing::warn!("{:?}: ML channel disconnected", self.direction);
                        }
                    }
                }

                if let Err(e) = forward_tx.send(packet_data) {
                    tracing::warn!("{:?}: Failed to forward packet: {}", self.direction, e);
                }
            }

            unsafe {
                self.fill_queue.produce(&rx_descs[..rx_count]);
            }

            tracing::debug!("{:?}: Received {} packets", self.direction, rx_count);
        }

        Ok(())
    }

    fn process_tx_queue(&mut self, forward_rx: &Receiver<Vec<u8>>) -> Result<(), EbpfError> {
        let mut packets_to_send = Vec::with_capacity(64);
        while let Ok(packet) = forward_rx.try_recv() {
            packets_to_send.push(packet);
            if packets_to_send.len() >= 64 {
                break;
            }
        }

        if packets_to_send.is_empty() {
            return Ok(());
        }

        let _ = self.process_comp_queue();

        let pool_size = {
            let pool = self.frame_pool.lock();
            pool.len()
        };

        if pool_size == 0 {
            tracing::warn!(
                "{:?}: Frame pool exhausted! Pending TX: {} packets",
                self.direction,
                packets_to_send.len()
            );
            return Ok(());
        }

        let mut frames = Vec::with_capacity(packets_to_send.len());
        {
            let mut pool = self.frame_pool.lock();
            let available = pool.len().min(packets_to_send.len());

            for _ in 0..available {
                if let Some(frame) = pool.pop() {
                    frames.push(frame);
                }
            }

            if frames.len() < packets_to_send.len() {
                tracing::debug!(
                    "{:?}: Pool has {} frames, requested {}, allocated {}",
                    self.direction,
                    pool_size,
                    packets_to_send.len(),
                    frames.len()
                );
            }
        }

        if frames.is_empty() {
            tracing::warn!("{:?}: No frames available for TX", self.direction);
            return Ok(());
        }

        for (frame, packet) in frames.iter_mut().zip(packets_to_send.iter()) {
            unsafe {
                self.umem
                    .data_mut(frame)
                    .cursor()
                    .write_all(packet)
                    .map_err(EbpfError::AfXdpSetFailed)?;
            }
        }

        let nb_submitted = unsafe { self.tx.produce(&frames) };

        tracing::debug!(
            "{:?}: Submitted {}/{} packets to TX queue",
            self.direction,
            nb_submitted,
            frames.len()
        );

        if let Err(e) = self.tx.wakeup() {
            if e.kind() != std::io::ErrorKind::WouldBlock {
                tracing::warn!("{:?}: TX wakeup failed: {}", self.direction, e);
            }
        }

        Ok(())
    }
}
