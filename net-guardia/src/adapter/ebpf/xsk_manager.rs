use std::ffi::CString;
use std::io::{ErrorKind, Write};
use std::num::NonZero;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use aya::Ebpf;
use aya::maps::{MapData, XskMap};
use crossbeam::channel::{Receiver, Sender, TrySendError, bounded};
use crossbeam::queue::SegQueue;
use macros::log;
use net_guardia_abi::define::drop_reason::DROP_REASON_DNS_BLACKLIST;
use parking_lot::Mutex;
use tokio::sync::oneshot::{self, error::TryRecvError};
use xsk_rs::config::{BindFlags, FrameSize, Interface, LibxdpFlags, QueueSize, SocketConfig, UmemConfig};
use xsk_rs::{CompQueue, FillQueue, FrameDesc, RxQueue, Socket, TxQueue, Umem};

use crate::adapter::ebpf::drop_monitor::DropMonitor;
use crate::common::error::Error;
use crate::common::error::system::SystemError;
use crate::common::utils::packet_parser::parse_packet_at;
use crate::domain::common::config::AppConfig;
use crate::domain::common::config::ebpf::EbpfConfig;
use crate::domain::data_plane::direction::Direction;
use crate::domain::data_plane::error::EbpfError;
use crate::domain::data_plane::log::EbpfLog;
use crate::interface::data_plane::dns_query_filter::DnsQueryFilter;
use crate::interface::data_plane::packet_sink::{PacketSink, PacketSinkFactory};

struct BufferPool {
    buffers: Vec<Vec<u8>>,
    buffer_size: usize,
    max_capacity: usize,
}

impl BufferPool {
    fn new(capacity: usize, buffer_size: usize) -> Self {
        let buffers = (0..capacity).map(|_| Vec::with_capacity(buffer_size)).collect();
        Self {
            buffers,
            buffer_size,
            max_capacity: capacity * 2,
        }
    }

    fn get(&mut self) -> Vec<u8> {
        self.buffers
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(self.buffer_size))
    }

    fn put(&mut self, mut buf: Vec<u8>) {
        buf.clear();
        if self.buffers.len() < self.max_capacity {
            self.buffers.push(buf);
        }
    }
}

pub struct XskManager {
    app_config: Arc<ArcSwap<AppConfig>>,
    ingress_xsk_map: Mutex<Option<XskMap<MapData>>>,
    egress_xsk_map: Mutex<Option<XskMap<MapData>>>,
}

impl XskManager {
    pub fn new(
        app_config: Arc<ArcSwap<AppConfig>>,
        ingress_ebpf: &mut Ebpf,
        egress_ebpf: &mut Ebpf,
    ) -> Result<Self, Error> {
        let ingress_map = ingress_ebpf
            .take_map("INGRESS_XSKS_MAP")
            .ok_or(EbpfError::MapNotFound)?;
        let ingress_xsk_map = XskMap::try_from(ingress_map).map_err(EbpfError::MapOperationError)?;

        let egress_map = egress_ebpf.take_map("EGRESS_XSKS_MAP").ok_or(EbpfError::MapNotFound)?;
        let egress_xsk_map = XskMap::try_from(egress_map).map_err(EbpfError::MapOperationError)?;

        Ok(Self {
            app_config,
            ingress_xsk_map: Mutex::new(Some(ingress_xsk_map)),
            egress_xsk_map: Mutex::new(Some(egress_xsk_map)),
        })
    }

    pub fn unavailable(app_config: Arc<ArcSwap<AppConfig>>) -> Self {
        Self {
            app_config,
            ingress_xsk_map: Mutex::new(None),
            egress_xsk_map: Mutex::new(None),
        }
    }

    pub fn run(
        &self,
        sinks: Option<Arc<dyn PacketSinkFactory>>,
        dns_filter: Option<Arc<dyn DnsQueryFilter>>,
        drop_monitor: Option<Arc<DropMonitor>>,
        shutdowns: &SegQueue<oneshot::Sender<()>>,
    ) -> Result<(), Error> {
        if self.ingress_xsk_map.lock().is_none() || self.egress_xsk_map.lock().is_none() {
            return Ok(());
        }

        let network = self.app_config.load().ebpf.clone();
        let combined_queue_count = network.combined_queue_count;

        for queue_id in 0..combined_queue_count {
            let (ingress_to_egress_tx, ingress_to_egress_rx) = bounded(network.channel_size);
            let (egress_to_ingress_tx, egress_to_ingress_rx) = bounded(network.channel_size);

            let sink = sinks.as_ref().and_then(|f| f.sink_for_queue(queue_id));

            let ingress_xsk = XskPair::new(
                network.clone(),
                queue_id,
                &network.ingress_ifname,
                Direction::Ingress,
                sink.clone(),
                dns_filter.clone(),
                drop_monitor.clone(),
            )?;

            let egress_xsk = XskPair::new(
                network.clone(),
                queue_id,
                &network.egress_ifname,
                Direction::Egress,
                sink,
                None,
                drop_monitor.clone(),
            )?;

            let mut ingress_guard = self.ingress_xsk_map.lock();
            let mut egress_guard = self.egress_xsk_map.lock();
            let ingress_xsk_map = ingress_guard.as_mut().ok_or(EbpfError::NotLoaded)?;
            let egress_xsk_map = egress_guard.as_mut().ok_or(EbpfError::NotLoaded)?;

            let ingress_fd = ingress_xsk.rx.fd().as_raw_fd();
            ingress_xsk_map
                .set(queue_id, ingress_fd, 0)
                .map_err(EbpfError::AfXdpSetFailed)?;

            let egress_fd = egress_xsk.rx.fd().as_raw_fd();
            egress_xsk_map
                .set(queue_id, egress_fd, 0)
                .map_err(EbpfError::AfXdpSetFailed)?;

            drop(ingress_guard);
            drop(egress_guard);

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
    frame_pool: Vec<FrameDesc>,
    sink: Option<Arc<dyn PacketSink>>,
    dns_filter: Option<Arc<dyn DnsQueryFilter>>,
    drop_monitor: Option<Arc<DropMonitor>>,
    packet_buffer_size: usize,
    buffer_pool_capacity: usize,
    completion_batch_size: usize,
    rx_batch_size: usize,
    tx_batch_size: usize,
    tx_packet_buf: Vec<Vec<u8>>,
    tx_frame_buf: Vec<FrameDesc>,
}

impl XskPair {
    pub fn new(
        config: EbpfConfig,
        queue_id: u32,
        rx_ifname: &str,
        direction: Direction,
        sink: Option<Arc<dyn PacketSink>>,
        dns_filter: Option<Arc<dyn DnsQueryFilter>>,
        drop_monitor: Option<Arc<DropMonitor>>,
    ) -> Result<Self, Error> {
        let ifname_field = match direction {
            Direction::Ingress => "ebpf.ingress_ifname",
            Direction::Egress => "ebpf.egress_ifname",
        };
        let rx_ifname_c = CString::new(rx_ifname).map_err(|_| SystemError::InvalidConfigField(ifname_field))?;

        let fill_queue_size = QueueSize::new(config.fill_queue_size)
            .map_err(|_| SystemError::InvalidConfigField("ebpf.fill_queue_size"))?;
        let comp_queue_size = QueueSize::new(config.comp_queue_size)
            .map_err(|_| SystemError::InvalidConfigField("ebpf.comp_queue_size"))?;
        let tx_queue_size =
            QueueSize::new(config.tx_queue_size).map_err(|_| SystemError::InvalidConfigField("ebpf.tx_queue_size"))?;
        let rx_queue_size =
            QueueSize::new(config.rx_queue_size).map_err(|_| SystemError::InvalidConfigField("ebpf.rx_queue_size"))?;
        let frame_size =
            FrameSize::new(config.frame_size).map_err(|_| SystemError::InvalidConfigField("ebpf.frame_size"))?;
        let frame_count =
            NonZero::new(config.frame_count).ok_or(SystemError::InvalidConfigField("ebpf.frame_count"))?;

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

        let (tx, rx, queue) =
            unsafe { Socket::new(socket_config, &umem, &interface, queue_id).map_err(EbpfError::SocketSetFailed)? };

        let (mut fill_queue, comp_queue) = queue.ok_or(EbpfError::AfXdpQueueUnavailable(direction, queue_id))?;

        let total_frames = frame_descs.len();
        let fill_frames_count = (total_frames / 2).min(config.fill_queue_size as usize);

        let fill_frames: Vec<FrameDesc> = frame_descs.iter().take(fill_frames_count).copied().collect();

        let submitted = unsafe { fill_queue.produce(&fill_frames) };
        if submitted != fill_frames.len() {
            Err(EbpfError::FillQueueInitIncomplete(submitted, fill_frames.len()))?;
        }

        let pool_frames: Vec<FrameDesc> = frame_descs.iter().skip(fill_frames_count).copied().collect();

        let xsk_pair = Self {
            direction,
            umem: Arc::new(umem),
            fill_queue,
            comp_queue,
            tx,
            rx,
            frame_pool: pool_frames,
            sink,
            dns_filter,
            drop_monitor,
            packet_buffer_size: config.packet_buffer_size,
            buffer_pool_capacity: config.buffer_pool_capacity,
            completion_batch_size: config.xsk_completion_batch_size,
            rx_batch_size: config.xsk_rx_batch_size,
            tx_batch_size: config.xsk_tx_batch_size,
            tx_packet_buf: Vec::with_capacity(config.xsk_tx_batch_size),
            tx_frame_buf: Vec::with_capacity(config.xsk_tx_batch_size),
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
                let mut buffer_pool = BufferPool::new(self.buffer_pool_capacity, self.packet_buffer_size);
                let mut comp_descs = vec![FrameDesc::default(); self.completion_batch_size];
                let mut rx_descs = vec![FrameDesc::default(); self.rx_batch_size];

                loop {
                    if let Some(ref mut rx) = shutdown_rx {
                        match rx.try_recv() {
                            Ok(_) | Err(TryRecvError::Closed) => {
                                break;
                            }
                            Err(TryRecvError::Empty) => {}
                        }
                    }

                    let mut total_activity = 0;

                    match self.process_comp_queue(&mut comp_descs) {
                        Ok(count) => total_activity += count,
                        Err(e) => log!(EbpfLog::CompQueueError(format!("{:?}", e))),
                    }

                    match self.process_rx_queue(&forward_tx, &mut buffer_pool, &mut rx_descs) {
                        Ok(count) => total_activity += count,
                        Err(e) => log!(EbpfLog::RXQueueError(format!("{:?}", e))),
                    }

                    match self.process_tx_queue(&forward_rx, &mut buffer_pool, &mut comp_descs) {
                        Ok(count) => total_activity += count,
                        Err(e) => log!(EbpfLog::TXQueueError(format!("{:?}", e))),
                    }

                    if total_activity == 0 {
                        idle_count = idle_count.saturating_add(1);
                    } else {
                        idle_count = 0;
                    }

                    if idle_count > 0 {
                        let sleep_us = match idle_count {
                            1..=10 => 1,
                            11..=100 => 10,
                            _ => 100,
                        };
                        thread::sleep(Duration::from_micros(sleep_us));
                    }
                }

                log!(EbpfLog::XSKShutdown);
            })
            .map(|_| shutdown_tx)
            .map_err(|e| {
                log!(EbpfLog::ThreadSpawnFailed(thread_name.clone(), e.to_string()));
                EbpfError::ThreadSpawnFailed(e)
            })
    }

    fn process_comp_queue(&mut self, comp_descs: &mut [FrameDesc]) -> Result<usize, EbpfError> {
        let nb_completed = unsafe { self.comp_queue.consume(comp_descs) };

        if nb_completed > 0 {
            for desc in comp_descs.iter().take(nb_completed) {
                self.frame_pool.push(*desc);
            }
        }

        Ok(nb_completed)
    }

    fn process_rx_queue(
        &mut self,
        forward_tx: &Sender<Vec<u8>>,
        buffer_pool: &mut BufferPool,
        rx_descs: &mut [FrameDesc],
    ) -> Result<usize, EbpfError> {
        let rx_count = unsafe { self.rx.consume(rx_descs) };

        if rx_count > 0 {
            let is_ingress = self.direction == Direction::Ingress;
            let timestamp_us = current_timestamp_us();

            for rx_desc in rx_descs.iter().take(rx_count) {
                let lengths = rx_desc.lengths();
                let packet_len = lengths.data();

                let data = unsafe { self.umem.data(rx_desc) };
                let contents = data.contents();
                if packet_len > contents.len() {
                    log!(EbpfLog::InvalidPacketLength);
                    continue;
                }

                let raw = &contents[..packet_len];
                if let Some(ref dns) = self.dns_filter
                    && dns.is_query_blacklisted(raw)
                {
                    if let Some(ref monitor) = self.drop_monitor {
                        monitor.record_drop_count(DROP_REASON_DNS_BLACKLIST);
                    }
                    continue;
                }
                if let Some(ref sink) = self.sink
                    && let Some((packet_info, _)) = parse_packet_at(raw, timestamp_us)
                {
                    sink.process_packet(packet_info, is_ingress);
                }
                let mut buf = buffer_pool.get();
                buf.extend_from_slice(raw);
                if let Err(e) = forward_tx.try_send(buf) {
                    match e {
                        TrySendError::Full(returned) => {
                            buffer_pool.put(returned);
                            log!(EbpfLog::ForwardChannelFull);
                        }
                        TrySendError::Disconnected(returned) => {
                            buffer_pool.put(returned);
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

    fn process_tx_queue(
        &mut self,
        forward_rx: &Receiver<Vec<u8>>,
        buffer_pool: &mut BufferPool,
        comp_descs: &mut [FrameDesc],
    ) -> Result<usize, EbpfError> {
        self.tx_packet_buf.clear();
        while let Ok(packet) = forward_rx.try_recv() {
            self.tx_packet_buf.push(packet);
            if self.tx_packet_buf.len() >= self.tx_batch_size {
                break;
            }
        }

        if self.tx_packet_buf.is_empty() {
            return Ok(0);
        }

        if let Err(e) = self.process_comp_queue(comp_descs) {
            log!(EbpfLog::CompQueueError(format!("{:?}", e)));
        }

        let total_packets = self.tx_packet_buf.len();

        if self.frame_pool.is_empty() {
            for pkt in self.tx_packet_buf.drain(..) {
                buffer_pool.put(pkt);
            }
            log!(EbpfLog::FramePoolExhausted(total_packets));
            return Ok(0);
        }

        let available = self.frame_pool.len().min(total_packets);
        self.tx_frame_buf.clear();
        self.tx_frame_buf
            .extend(self.frame_pool.drain(self.frame_pool.len() - available..));

        if self.tx_frame_buf.is_empty() {
            for pkt in self.tx_packet_buf.drain(..) {
                buffer_pool.put(pkt);
            }
            log!(EbpfLog::NoFramesAvailable);
            return Ok(0);
        }

        for (frame, packet) in self.tx_frame_buf.iter_mut().zip(self.tx_packet_buf.iter()) {
            unsafe {
                self.umem
                    .data_mut(frame)
                    .cursor()
                    .write_all(packet)
                    .map_err(EbpfError::AfXdpSetFailed)?;
            }
        }

        let nb_submitted = unsafe { self.tx.produce(&self.tx_frame_buf) };
        if nb_submitted < self.tx_frame_buf.len() {
            for frame in self.tx_frame_buf[nb_submitted..].iter() {
                self.frame_pool.push(*frame);
            }
        }

        if let Err(e) = self.tx.wakeup()
            && e.kind() != ErrorKind::WouldBlock
        {
            log!(EbpfLog::TXWakeupFailed(e.to_string()));
        }
        let dropped = total_packets - nb_submitted;
        if dropped > 0 {
            log!(EbpfLog::FramePoolExhausted(dropped));
        }
        for pkt in self.tx_packet_buf.drain(..) {
            buffer_pool.put(pkt);
        }

        Ok(nb_submitted)
    }
}

fn current_timestamp_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}
