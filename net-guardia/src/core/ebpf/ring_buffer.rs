use crate::model::error::Error;

#[allow(dead_code)]
pub struct RingBuffer {}

impl RingBuffer {
    pub fn new() -> Result<Self, Error> {
        let ring_buffer = Self {};
        Ok(ring_buffer)
    }
}
