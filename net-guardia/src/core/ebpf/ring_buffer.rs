use std::sync::Arc;
use std::time::Duration;

use aya::maps::{MapData, RingBuf};
use aya::Ebpf;
use tokio::select;
use tokio::sync::{oneshot, RwLock};
use tokio::time::sleep;

use crate::model::error::ebpf::EbpfError;
use crate::model::error::Error;

pub struct RingBuffer {
    inner: RwLock<RingBuf<MapData>>,
}

impl RingBuffer {
    pub fn new(ebpf: &mut Ebpf) -> Result<Self, Error> {
        let map = ebpf.take_map("PACKET_RING").ok_or(EbpfError::MapNotFound)?;
        let ring_buffer = RingBuf::try_from(map).map_err(EbpfError::MapOperationError)?;
        let inner = RwLock::new(ring_buffer);
        Ok(Self { inner })
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
        let mut ring_buf = self.inner.write().await;
        while let Some(event) = ring_buf.next() {
            if event.len() >= 16 {
                let data = unsafe { &*(event.as_ptr() as *const [usize; 2]) };
                println!(
                    "Debug: start={}, end={}, diff={}",
                    data[0],
                    data[1],
                    data[1].saturating_sub(data[0])
                );
            }
        }
        sleep(Duration::from_millis(1)).await;
    }
}
