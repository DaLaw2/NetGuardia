use std::ffi::CString;
use std::num::NonZero;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use aya::maps::{MapData, XskMap};
use aya::Ebpf;
use crossbeam::queue::SegQueue;
use macros::log;
use parking_lot::Mutex;
use tokio::select;
use tokio::sync::oneshot;
use tokio::time::sleep;
use xsk_rs::config::{BindFlags, FrameSize, Interface, QueueSize, SocketConfig, UmemConfig};
use xsk_rs::{CompQueue, FillQueue, FrameDesc, RxQueue, Socket, TxQueue, Umem};

use crate::core::infrastructure::app_config::AppConfig;
use crate::model::config::Config;
use crate::model::error::ebpf::EbpfError;
use crate::model::error::system::SystemError;
use crate::model::error::Error;
use crate::model::log::ebpf::EbpfLog;

pub struct XskManager {
    app_config: Arc<AppConfig>,
    xsk_map: Mutex<XskMap<MapData>>,
    shutdowns: SegQueue<oneshot::Sender<()>>,
}

impl XskManager {
    pub fn new(app_config: Arc<AppConfig>, ebpf: &mut Ebpf) -> Result<Self, Error> {
        let map = ebpf.take_map("XSKS_MAP").ok_or(EbpfError::MapNotFound)?;
        let xsk_map = XskMap::try_from(map).map_err(EbpfError::MapOperationError)?;

        Ok(Self {
            app_config,
            xsk_map: Mutex::new(xsk_map),
            shutdowns: SegQueue::new(),
        })
    }

    pub fn run(&self) -> Result<(), Error> {
        let config = self.app_config.config.clone();
        let combined_queue_count = config.combined_queue_count;

        let mut xsk_map = self.xsk_map.lock();
        for queue_id in 0..combined_queue_count {
            let xsk = Xsk::new(config.clone(), &mut xsk_map, queue_id)?;
            let shutdown = xsk.run();
            self.shutdowns.push(shutdown);
        }

        Ok(())
    }

    pub fn shutdown(&self) {
        while let Some(sender) = self.shutdowns.pop() {
            if sender.send(()).is_err() {
                log!(SystemError::ShutdownSignalFailed);
            }
        }
    }
}

pub struct Xsk {
    umem: Umem,
    fill_queue: FillQueue,
    comp_queue: CompQueue,
    tx: TxQueue,
    rx: RxQueue,
}

impl Xsk {
    pub fn new(config: Config, xsk_map: &mut XskMap<MapData>, queue_id: u32) -> Result<Self, Error> {
        let ifname = CString::new(config.ingress_ifname.as_str()).map_err(|_| SystemError::UnknownError)?;
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
            .bind_flags(BindFlags::empty())
            .build();

        let interface = Interface::new(ifname);
        let (tx, rx, queue) =
            Socket::new(socket_config, &umem, &interface, queue_id).map_err(EbpfError::SocketSetFailed)?;

        let (mut fill_queue, comp_queue) = queue.ok_or(EbpfError::UnknownError)?;

        let socket_fd = rx.fd().as_raw_fd();

        xsk_map.set(queue_id, socket_fd, 0).map_err(EbpfError::AfXdpSetFailed)?;

        let frames: Vec<FrameDesc> = frame_descs
            .iter()
            .take(config.fill_queue_size as usize)
            .copied()
            .collect();

        let submitted = unsafe { fill_queue.produce(&frames) };
        if submitted != frames.len() {
            log!(EbpfLog::QueueInitIncomplete);
        }

        Ok(Self {
            umem,
            fill_queue,
            comp_queue,
            tx,
            rx,
        })
    }

    pub fn run(mut self) -> oneshot::Sender<()> {
        let (sender, receiver) = oneshot::channel();
        tokio::spawn(async move {
            let mut receiver = receiver;
            loop {
                select! {
                    biased;
                    _ = &mut receiver => break,
                    _ = self.process_events() => {},
                }
            }
        });
        sender
    }

    async fn process_events(&mut self) {
        let mut comp_descs = vec![FrameDesc::default(); 64];
        let comp_count = unsafe { self.comp_queue.consume(&mut comp_descs) };

        if comp_count > 0 {
            let submitted = unsafe { self.fill_queue.produce(&comp_descs[..comp_count]) };
            if submitted != comp_count {
                log!(EbpfLog::QueueRefillIncomplete);
            }
        }

        let mut packet_count = 0;
        let mut tx_descs = Vec::with_capacity(64);
        let mut rx_descs = vec![FrameDesc::default(); 64];

        let rx_count = unsafe { self.rx.consume(&mut rx_descs) };

        for rx_desc in &rx_descs[..rx_count] {
            let data = unsafe { self.umem.data(rx_desc) };
            let packet_data = &data.contents()[..rx_desc.lengths().data()];

            let packet_copy = packet_data.to_vec();

            Self::print_packet_info(&packet_copy);

            tx_descs.push(*rx_desc);
            packet_count += 1;
        }

        if !tx_descs.is_empty() {
            let tx_submitted = unsafe { self.tx.produce(&tx_descs) };
            if tx_submitted != tx_descs.len() {
                log!(EbpfLog::QueueRefillIncomplete);
                for desc in &tx_descs[tx_submitted..] {
                    unsafe {
                        let _ = self.fill_queue.produce(&[*desc]);
                    }
                }
            } else {
                if let Err(err) = self.tx.wakeup() {
                    log!(EbpfError::WakeupTXFailed(err))
                }
            }
        }

        if packet_count > 0 {
            println!("Processed {} packets", packet_count);
        }

        if packet_count == 0 {
            sleep(Duration::from_millis(1)).await;
        }
    }

    fn print_packet_info(packet_data: &[u8]) {
        if packet_data.len() < 14 {
            println!("Packet too small: {} bytes", packet_data.len());
            return;
        }

        println!("Received packet: {} bytes", packet_data.len());

        let print_len = std::cmp::min(64, packet_data.len());
        print!("Data: ");
        for i in 0..print_len {
            print!("{:02x} ", packet_data[i]);
            if (i + 1) % 16 == 0 {
                print!("\n      ");
            }
        }
        println!();

        let dst_mac = &packet_data[0..6];
        let src_mac = &packet_data[6..12];
        let eth_type = u16::from_be_bytes([packet_data[12], packet_data[13]]);

        println!(
            "Ethernet: src={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, dst={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, type=0x{:04x}",
            src_mac[0],
            src_mac[1],
            src_mac[2],
            src_mac[3],
            src_mac[4],
            src_mac[5],
            dst_mac[0],
            dst_mac[1],
            dst_mac[2],
            dst_mac[3],
            dst_mac[4],
            dst_mac[5],
            eth_type
        );

        match eth_type {
            0x0800 => {
                println!("  -> IPv4 packet");
                if packet_data.len() >= 34 {
                    let src_ip = &packet_data[26..30];
                    let dst_ip = &packet_data[30..34];
                    println!(
                        "     IP: {}.{}.{}.{} -> {}.{}.{}.{}",
                        src_ip[0], src_ip[1], src_ip[2], src_ip[3], dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]
                    );
                }
            }
            0x86DD => println!("  -> IPv6 packet"),
            0x0806 => println!("  -> ARP packet"),
            _ => println!("  -> Unknown protocol"),
        }

        println!("---");
    }
}
