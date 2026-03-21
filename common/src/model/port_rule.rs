#[cfg(feature = "user")]
use aya::Pod;
#[cfg(feature = "user")]
use std::vec::Vec;

use crate::define::setting::MAX_RULES_PORT;
use crate::model::ip_address::Port;

pub const PORT_RULE_MATCH_ALL: u8 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PortRule {
    pub match_all: u8,
    pub count: u8,
    pub _pad: [u8; 2],
    pub ports: [Port; MAX_RULES_PORT],
}

impl PortRule {
    pub fn new_empty() -> Self {
        Self {
            match_all: 0,
            count: 0,
            _pad: [0; 2],
            ports: [0; MAX_RULES_PORT],
        }
    }

    pub fn new_match_all() -> Self {
        Self {
            match_all: PORT_RULE_MATCH_ALL,
            count: 0,
            _pad: [0; 2],
            ports: [0; MAX_RULES_PORT],
        }
    }

    pub fn is_match_all(&self) -> bool {
        self.match_all == PORT_RULE_MATCH_ALL
    }

    pub fn contains(&self, port: Port) -> bool {
        if self.is_match_all() {
            return true;
        }
        for i in 0..(self.count as usize) {
            if i >= MAX_RULES_PORT {
                break;
            }
            if self.ports[i] == port {
                return true;
            }
        }
        false
    }

    #[cfg(feature = "user")]
    pub fn add_port(&mut self, port: Port) -> bool {
        if self.is_match_all() {
            return true;
        }
        for i in 0..(self.count as usize) {
            if i >= MAX_RULES_PORT {
                return false;
            }
            if self.ports[i] == port {
                return true;
            }
        }
        if (self.count as usize) >= MAX_RULES_PORT {
            return false;
        }
        self.ports[self.count as usize] = port;
        self.count += 1;
        true
    }

    #[cfg(feature = "user")]
    pub fn remove_port(&mut self, port: Port) -> bool {
        for i in 0..(self.count as usize) {
            if i >= MAX_RULES_PORT {
                break;
            }
            if self.ports[i] == port {
                for j in i..(self.count as usize - 1) {
                    self.ports[j] = self.ports[j + 1];
                }
                self.count -= 1;
                self.ports[self.count as usize] = 0;
                return true;
            }
        }
        false
    }

    #[cfg(feature = "user")]
    pub fn to_port_vec(&self) -> Vec<Port> {
        let count = (self.count as usize).min(MAX_RULES_PORT);
        self.ports[..count].to_vec()
    }

    #[cfg(feature = "user")]
    pub fn is_empty(&self) -> bool {
        !self.is_match_all() && self.count == 0
    }
}

#[cfg(feature = "user")]
unsafe impl Pod for PortRule {}
