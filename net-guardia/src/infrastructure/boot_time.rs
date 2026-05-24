use sysinfo::System;

use crate::interface::system::system_control::BootTimeQuery;

pub struct SysinfoBootTimeQuery;

impl BootTimeQuery for SysinfoBootTimeQuery {
    fn boot_time_ns(&self) -> u64 {
        System::boot_time() * 1_000_000_000
    }
}
