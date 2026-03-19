use std::ffi::CString;
use std::io::Write;
use std::num::NonZero;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use aya::maps::{MapData, XskMap};
use aya::Ebpf;
use crossbeam::channel::{bounded, Receiver, Sender};
use crossbeam::queue::SegQueue;
use macros::log;
use parking_lot::Mutex;
use tokio::sync::oneshot;
use xsk_rs::config::{BindFlags, FrameSize, Interface, LibxdpFlags, QueueSize, SocketConfig, UmemConfig};
use xsk_rs::{CompQueue, FillQueue, FrameDesc, RxQueue, Socket, TxQueue, Umem};

use crate::core::infrastructure::app_config::AppConfig;
use crate::core::ml::engine::Engine;
use crate::core::ml::flow_tracker::FlowTracker;
use crate::model::config::NetworkConfig;
use crate::model::direction::Direction;
use crate::model::error::ebpf::EbpfError;
use crate::model::error::system::SystemError;
use crate::model::error::Error;
use crate::model::log::ebpf::EbpfLog;

pub struct XskManager {
    app_config: Arc<AppConfig>,
    xsk_map: Mutex<XskMap<MapData>>,
    egress_xsk_map: Mutex<XskMap<MapData>>,
}

impl XskManager {
    pub fn new(app_config: Arc<AppConfig>, ingress_ebpf: &mut Ebpf, egress_ebpf: &mut Ebpf) -> Result<Self, Error> {
        let map = ingress_ebpf
            .take_map("INGRESS_XSKS_MAP")
            .ok_or(EbpfError::MapNotFound)?;
        let xsk_map = XskMap::try_from(map).map_err(EbpfError::MapOperationError)?;

        let egress_map = egress_ebpf.take_map("EGRESS_XSKS_MAP").ok_or(EbpfError::MapNotFound)?;
        let egress_xsk_map = XskMap::try_from(egress_map).map_err(EbpfError::MapOperationError)?;

        Ok(Self {
            app_config,
            xsk_map: Mutex::new(xsk_map),
            egress_xsk_map: Mutex::new(egress_xsk_map),
        })
    }

    pub fn run(&self, ml_engine: Option<Arc<Engine>>, shutdowns: &SegQueue<oneshot::Sender<()>>) -> Result<(), Error> {
        let network = self.app_config.network.clone();
        let combined_queue_count = network.combined_queue_count;

        for queue_id in 0..combined_queue_count {
            let (ingress_to_egress_tx, ingress_to_egress_rx) = bounded(network.channel_size);
            let (egress_to_ingress_tx, egress_to_ingress_rx) = bounded(network.channel_size);

            let tracker = ml_engine.as_ref().map(|engine| engine.tracker(queue_id).clone());

            let ingress_xsk = XskPair::new(
                network.clone(),
                queue_id,
                &network.ingress_ifname,
                &network.egress_ifname,
                Direction::Ingress,
                tracker.clone(),
            )?;

            let egress_xsk = XskPair::new(
                network.clone(),
                queue_id,
                &network.egress_ifname,
                &network.ingress_ifname,
                Direction::Egress,
                tracker,
            )?;

            let mut xsk_map = self.xsk_map.lock();
            let mut egress_xsk_map = self.egress_xsk_map.lock();

            let ingress_fd = ingress_xsk.rx.fd().as_raw_fd();
            xsk_map
                .set(queue_id, ingress_fd, 0)
                .map_err(EbpfError::AfXdpSetFailed)?;

            let egress_fd = egress_xsk.rx.fd().as_raw_fd();
            egress_xsk_map
                .set(queue_id, egress_fd, 0)
                .map_err(EbpfError::AfXdpSetFailed)?;

            drop(xsk_map);
            drop(egress_xsk_map);

            let ingress_shutdown = ingress_xsk.run(ingress_to_egress_tx, egress_to_ingress_rx)?;
            shutdowns.push(ingress_shutdown);

            let egress_shutdown = egress_xsk.run(egress_to_ingress_tx, ingress_to_egress_rx)?;
            shutdowns.push(egress_shutdown);

            log!(EbpfLog::QueuePairStarted(queue_id));
        }

        Ok(())
    }
}

pub struct XskPair {
    direction: Direction,
    umem: Arc<Umem>,
    fill_queue: FillQueue,
    comp_queue: CompQueue,
    tx: TxQueue,
    rx: RxQueue,
    frame_pool: Arc<Mutex<Vec<FrameDesc>>>,
    tracker: Option<Arc<Mutex<FlowTracker>>>,
}

impl XskPair {
    pub fn new(
        config: NetworkConfig,
        queue_id: u32,
        rx_ifname: &str,
        _tx_ifname: &str,
        direction: Direction,
        tracker: Option<Arc<Mutex<FlowTracker>>>,
    ) -> Result<Self, Error> {
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
            .bind_flags(BindFlags::XDP_COPY)
            .libxdp_flags(LibxdpFlags::XSK_LIBXDP_FLAGS_INHIBIT_PROG_LOAD)
            .build();

        let interface = Interface::new(rx_ifname_c);

        // SAFETY: Interface and umem are valid and outlive the socket
        let (tx, rx, queue) =
            unsafe { Socket::new(socket_config, &umem, &interface, queue_id).map_err(EbpfError::SocketSetFailed)? };

        let (mut fill_queue, comp_queue) = queue.ok_or(EbpfError::UnknownError)?;

        let total_frames = frame_descs.len();
        let fill_frames_count = (total_frames / 2).min(config.fill_queue_size as usize);

        let fill_frames: Vec<FrameDesc> = frame_descs.iter().take(fill_frames_count).copied().collect();

        // SAFETY: Frame descriptors are valid and owned by this UMEM
        let submitted = unsafe { fill_queue.produce(&fill_frames) };
        if submitted != fill_frames.len() {
            return Err(EbpfError::FillQueueInitFailed.into());
        }

        let pool_frames: Vec<FrameDesc> = frame_descs.iter().skip(fill_frames_count).copied().collect();

        let xsk_pair = Self {
            direction,
            umem: Arc::new(umem),
            fill_queue,
            comp_queue,
            tx,
            rx,
            frame_pool: Arc::new(Mutex::new(pool_frames)),
            tracker,
        };

        Ok(xsk_pair)
    }

    pub fn run(
        mut self,
        forward_tx: Sender<Vec<u8>>,
        forward_rx: Receiver<Vec<u8>>,
    ) -> Result<oneshot::Sender<()>, EbpfError> {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let thread_name = format!("xsk-{:?}", self.direction);

        thread::Builder::new()
            .name(thread_name.clone())
            .spawn(move || {
                let mut shutdown_rx = Some(shutdown_rx);
                let mut idle_count: u32 = 0;

                loop {
                    // Non-blocking shutdown check: try_recv avoids blocking the hot loop.
                    // The idle backoff below (sleep_us) ensures we don't busy-spin when idle,
                    // which also bounds how quickly we detect shutdown to at most 100us.
                    if let Some(ref mut rx) = shutdown_rx {
                        match rx.try_recv() {
                            Ok(_) | Err(oneshot::error::TryRecvError::Closed) => {
                                break;
                            }
                            Err(oneshot::error::TryRecvError::Empty) => {}
                        }
                    }

                    let mut total_activity = 0;

                    match self.process_comp_queue() {
                        Ok(count) => total_activity += count,
                        Err(e) => log!(EbpfLog::CompQueueError(format!("{:?}", e))),
                    }

                    match self.process_rx_queue(&forward_tx) {
                        Ok(count) => total_activity += count,
                        Err(e) => log!(EbpfLog::RXQueueError(format!("{:?}", e))),
                    }

                    match self.process_tx_queue(&forward_rx) {
                        Ok(count) => total_activity += count,
                        Err(e) => log!(EbpfLog::TXQueueError(format!("{:?}", e))),
                    }

                    if total_activity == 0 {
                        idle_count = idle_count.saturating_add(1);
                    } else {
                        idle_count = 0;
                    }

                    let sleep_us = match idle_count {
                        0..=10 => 1,
                        11..=100 => 10,
                        _ => 100,
                    };

                    thread::sleep(Duration::from_micros(sleep_us));
                }

                log!(EbpfLog::XSKShutdown);
            })
            .map(|_| shutdown_tx)
            .map_err(|e| {
                log!(EbpfLog::ThreadSpawnFailed(thread_name.clone(), e.to_string()));
                EbpfError::ThreadSpawnFailed(e)
            })
    }

    fn process_comp_queue(&mut self) -> Result<usize, EbpfError> {
        let mut comp_descs = vec![FrameDesc::default(); 256];

        let nb_completed = unsafe { self.comp_queue.consume(&mut comp_descs) };

        if nb_completed > 0 {
            let mut pool = self.frame_pool.lock();

            for desc in comp_descs.iter().take(nb_completed) {
                pool.push(*desc);
            }
        }

        Ok(nb_completed)
    }

    fn process_rx_queue(&mut self, forward_tx: &Sender<Vec<u8>>) -> Result<usize, EbpfError> {
        let mut rx_descs = vec![FrameDesc::default(); 64];
        // SAFETY: rx_descs buffer is large enough for consume
        let rx_count = unsafe { self.rx.consume(&mut rx_descs) };

        if rx_count > 0 {
            for rx_desc in rx_descs.iter().take(rx_count) {
                let lengths = rx_desc.lengths();
                let packet_len = lengths.data() as usize;

                // SAFETY: rx_desc is valid and belongs to this UMEM
                let data = unsafe { self.umem.data(rx_desc) };
                let contents = data.contents();
                if packet_len > contents.len() {
                    log!(EbpfLog::InvalidPacketLength);
                    continue;
                }
                let packet_data = contents[..packet_len].to_vec();

                if let Some(ref tracker) = self.tracker {
                    Engine::process_packet(tracker, &packet_data, self.direction == Direction::Ingress);
                }

                if let Err(e) = forward_tx.try_send(packet_data) {
                    match e {
                        crossbeam::channel::TrySendError::Full(_) => {
                            log!(EbpfLog::ForwardChannelFull);
                        }
                        crossbeam::channel::TrySendError::Disconnected(_) => {
                            log!(EbpfLog::ForwardChannelDisconnected);
                        }
                    }
                }
            }

            unsafe {
                let produced = self.fill_queue.produce(&rx_descs[..rx_count]);
                if produced != rx_count {
                    log!(EbpfLog::FillQueueIncomplete(produced, rx_count));
                }
            }
        }

        Ok(rx_count)
    }

    fn process_tx_queue(&mut self, forward_rx: &Receiver<Vec<u8>>) -> Result<usize, EbpfError> {
        let mut packets_to_send = Vec::with_capacity(64);
        while let Ok(packet) = forward_rx.try_recv() {
            packets_to_send.push(packet);
            if packets_to_send.len() >= 64 {
                break;
            }
        }

        if packets_to_send.is_empty() {
            return Ok(0);
        }

        if let Err(e) = self.process_comp_queue() {
            log!(EbpfLog::CompQueueError(format!("{:?}", e)));
        }

        let pool_size = {
            let pool = self.frame_pool.lock();
            pool.len()
        };

        if pool_size == 0 {
            log!(EbpfLog::FramePoolExhausted(packets_to_send.len()));
            return Ok(0);
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
        }

        if frames.is_empty() {
            log!(EbpfLog::NoFramesAvailable);
            return Ok(0);
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

        // SAFETY: Frames contain valid packet data written above
        let nb_submitted = unsafe { self.tx.produce(&frames) };

        if let Err(e) = self.tx.wakeup() {
            if e.kind() != std::io::ErrorKind::WouldBlock {
                log!(EbpfLog::TXWakeupFailed(e.to_string()));
            }
        }

        Ok(nb_submitted)
    }
}
