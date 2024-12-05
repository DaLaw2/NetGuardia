use crate::MAX_PORT_ACCESS;

#[derive(Clone, Copy)]
pub struct PortAccesses {
    pub records: [(u16, u64); MAX_PORT_ACCESS],
}

impl Default for PortAccesses {
    fn default() -> Self {
        Self {
            records: [(0, 0); MAX_PORT_ACCESS],
        }
    }
}
