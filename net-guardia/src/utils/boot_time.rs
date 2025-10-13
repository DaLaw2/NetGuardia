use sysinfo::System as SystemInfo;

pub fn boot_time() -> u64 {
    SystemInfo::boot_time() * 1_000_000_000
}
