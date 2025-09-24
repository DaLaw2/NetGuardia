use std::sync::Arc;
use std::time::Duration;

use aya::maps::{MapData, RingBuf, XskMap};
use aya::Ebpf;
use tokio::select;
use tokio::sync::{oneshot, RwLock};
use tokio::time::sleep;
use common::model::event::{IPv4Event, IPv6Event};
use crate::model::error::ebpf::EbpfError;
use crate::model::error::Error;
use xsk_rs::{Socket, Umem};
use xsk_rs::config::{SocketConfig, UmemConfig};

pub struct RingBuffer {
    xsk_socket: Socket,
    umem: Umem,
}

impl RingBuffer {
    pub fn new(ebpf: &mut Ebpf, interface_name: &str, queue_id: u32) -> Result<Self, Error> {
        // 建立 UMEM
        let umem_config = UmemConfig {
            fill_size: 2048,
            comp_size: 2048,
            frame_size: 2048,
            frame_count: 4096,
            frame_headroom: 0,
            flags: 0,
        };

        let umem = Umem::new(umem_config, false)
            .map_err(|e| Error::XdpError(format!("Failed to create UMEM: {}", e)))?;

        // 建立 XSK socket
        let socket_config = SocketConfig {
            rx_size: 2048,
            tx_size: 2048,
            bind_flags: 0,
        };

        let xsk_socket = Socket::new(
            umem.clone(),
            interface_name,
            queue_id,
            socket_config,
        ).map_err(|e| Error::XdpError(format!("Failed to create socket: {}", e)))?;

        // 註冊到 XskMap
        let socket_fd: RawFd = xsk_socket.as_raw_fd();
        let mut xsk_map = XskMap::try_from(ebpf.take_map("XSKS_MAP")
            .ok_or(EbpfError::MapNotFound)?
        ).map_err(EbpfError::MapOperationError)?;

        xsk_map.set(queue_id, socket_fd, 0)?;

        Ok(Self { xsk_socket, umem })
    }

    pub fn run(self: Arc<Self>) -> oneshot::Sender<()> {
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

    async fn process_events(&self) {
        let mut rx_ring = self.xsk_socket.rx();
        let mut fill_ring = self.umem.fill_q();
        let mut comp_ring = self.umem.comp_q();
        while let Some(addr) = comp_ring.consume().next() {
            fill_ring.produce(&[addr]);
        }
        let mut packet_count = 0;
        for desc in rx_ring.consume(64) {
            let packet_data = unsafe {
                std::slice::from_raw_parts(
                    self.umem.data(desc.addr()),
                    desc.len() as usize
                )
            };
            self.print_packet_info(packet_data);
            packet_count += 1;
            fill_ring.produce(&[desc.addr()]);
        }
        if packet_count > 0 {
            println!("Processed {} packets", packet_count);
        }
        if packet_count == 0 {
            sleep(Duration::from_millis(1)).await;
        }
    }

    fn print_packet_info(&self, packet_data: &[u8]) {
        if packet_data.len() < 14 {
            println!("Packet too small: {} bytes", packet_data.len());
            return;
        }

        // 印出基本封包資訊
        println!("Received packet: {} bytes", packet_data.len());

        // 印出前 64 bytes 的 hex dump
        let print_len = std::cmp::min(64, packet_data.len());
        print!("Data: ");
        for i in 0..print_len {
            print!("{:02x} ", packet_data[i]);
            if (i + 1) % 16 == 0 {
                print!("\n      ");
            }
        }
        println!();

        if packet_data.len() >= 14 {
            let dst_mac = &packet_data[0..6];
            let src_mac = &packet_data[6..12];
            let eth_type = u16::from_be_bytes([packet_data[12], packet_data[13]]);

            println!(
                "Ethernet: src={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, dst={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, type=0x{:04x}",
                src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
                dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5],
                eth_type
            );

            match eth_type {
                0x0800 => println!("  -> IPv4 packet"),
                0x86DD => println!("  -> IPv6 packet"),
                0x0806 => println!("  -> ARP packet"),
                _ => println!("  -> Unknown protocol"),
            }
        }

        println!("---");
    }
}
