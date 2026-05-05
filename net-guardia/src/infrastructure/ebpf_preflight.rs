//! Classifier for eBPF bring-up failures.
//!
//! Takes a raw error plus interface/stage context and produces an
//! `EbpfHealth::Unavailable { stage, category, reason }` suitable for the
//! frontend status display.
//!
//! Classification is best-effort: we inspect `std::io::ErrorKind` where we
//! have one, then fall back to substring matching on the rendered error
//! string. The produced `reason` always includes the interface name,
//! host kernel release, and the NIC driver where those are obtainable,
//! so the operator can diagnose directly from the UI without shelling in.

use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::mem;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};

use libc::{
    AF_NETLINK, NETLINK_GENERIC, SOCK_CLOEXEC, SOCK_RAW, bind, close, genlmsghdr, nlmsghdr, recv, sendto, sockaddr,
    sockaddr_nl, socket,
};

use crate::domain::common::error::Error;
use crate::domain::common::system::health::{EbpfFailCategory, EbpfFailStage, EbpfHealth};

/// Read the running kernel release from `/proc/sys/kernel/osrelease`.
/// Returns the trimmed value, or `"unknown"` if the file cannot be read.
pub fn kernel_release() -> String {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

const SYS_CLASS_NET: &str = "/sys/class/net";
const NETDEV_FAMILY_NAME: &str = "netdev";
const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const NETDEV_CMD_DEV_GET: u8 = 1;
const NETDEV_A_DEV_IFINDEX: u16 = 1;
const NETDEV_A_DEV_XDP_FEATURES: u16 = 3;
const NETDEV_A_DEV_XDP_ZC_MAX_SEGS: u16 = 4;
const NETDEV_A_DEV_XSK_FEATURES: u16 = 6;
const NETDEV_XDP_ACT_XSK_ZEROCOPY: u64 = 8;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 1;
const NETLINK_SEQUENCE: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetdevCapabilities {
    pub xdp_features: Option<u64>,
    pub xdp_zc_max_segs: Option<u32>,
    pub xsk_features: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceCapabilities {
    pub driver: String,
    pub mtu: Option<u32>,
    pub rx_queues: Option<usize>,
    pub tx_queues: Option<usize>,
    pub netdev: Option<NetdevCapabilities>,
}

impl InterfaceCapabilities {
    fn load(ifname: &str) -> Self {
        Self::load_from(ifname, Path::new(SYS_CLASS_NET))
    }

    fn load_from(ifname: &str, sys_class_net: &Path) -> Self {
        let iface_path = sys_class_net.join(ifname);

        Self {
            driver: interface_driver_from(&iface_path),
            mtu: read_u32(iface_path.join("mtu")),
            rx_queues: count_queue_dirs(&iface_path, "rx-"),
            tx_queues: count_queue_dirs(&iface_path, "tx-"),
            netdev: read_u32(iface_path.join("ifindex")).and_then(load_netdev_capabilities),
        }
    }

    fn xsk_zerocopy_supported(&self) -> Option<bool> {
        self.netdev
            .as_ref()
            .and_then(|netdev| netdev.xdp_features)
            .map(|features| features & NETDEV_XDP_ACT_XSK_ZEROCOPY != 0)
    }
}

impl fmt::Display for InterfaceCapabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "driver {}", self.driver)?;

        if let Some(mtu) = self.mtu {
            write!(f, ", mtu {}", mtu)?;
        }
        if let Some(rx_queues) = self.rx_queues {
            write!(f, ", rx_queues {}", rx_queues)?;
        }
        if let Some(tx_queues) = self.tx_queues {
            write!(f, ", tx_queues {}", tx_queues)?;
        }
        match self.netdev.as_ref() {
            Some(netdev) => {
                if let Some(features) = netdev.xdp_features {
                    write!(f, ", xdp_features 0x{features:x}")?;
                }
                if let Some(max_segs) = netdev.xdp_zc_max_segs {
                    write!(f, ", xdp_zc_max_segs {}", max_segs)?;
                }
                if let Some(features) = netdev.xsk_features {
                    write!(f, ", xsk_features 0x{features:x}")?;
                }
            }
            None => write!(f, ", netdev_features unavailable")?,
        }

        Ok(())
    }
}

/// Build an `EbpfHealth::Unavailable` from an error and stage context.
///
/// `ifname` is optional because some stages (Load, LoggerInit, PipelineSetup)
/// fail before any interface is involved.
pub fn classify(stage: EbpfFailStage, err: &Error, ifname: Option<&str>) -> EbpfHealth {
    let raw = err.to_string();
    let category = categorize(&raw);
    let kernel = kernel_release();
    let capabilities = ifname.map(InterfaceCapabilities::load);

    let mut reason = format!("stage={:?}: {}", stage, raw);
    reason.push_str(&format!(" (kernel {}", kernel));
    if let Some(iface) = ifname {
        reason.push_str(&format!(", interface {}", iface));
        if let Some(caps) = capabilities.as_ref() {
            reason.push_str(&format!(", {}", caps));
        }
    }
    reason.push(')');

    if matches!(category, EbpfFailCategory::AfXdpUnsupported) {
        if let Some(Some(false)) = capabilities.as_ref().map(InterfaceCapabilities::xsk_zerocopy_supported) {
            reason.push_str(". The interface reports no AF_XDP zero-copy capability in xdp_features.");
        } else if capabilities.as_ref().and_then(|caps| caps.netdev.as_ref()).is_none() {
            reason.push_str(". Kernel did not expose netdev XDP feature data for this interface.");
        }
    }

    EbpfHealth::Unavailable {
        stage,
        category,
        reason,
    }
}

/// Heuristic categorization based on the rendered error string.
/// Kept intentionally shallow — aya does not currently expose structured
/// enums for all kernel errno paths, so substring matching is the realistic
/// fallback.
fn categorize(raw: &str) -> EbpfFailCategory {
    let lower = raw.to_lowercase();

    if lower.contains("permission denied") || lower.contains("operation not permitted") || lower.contains("eperm") {
        return EbpfFailCategory::Permission;
    }
    if lower.contains("no such device")
        || lower.contains("enodev")
        || lower.contains("no such file or directory")
            && (lower.contains("/sys/class/net") || lower.contains("interface"))
    {
        return EbpfFailCategory::InterfaceNotFound;
    }
    if lower.contains("operation not supported") || lower.contains("eopnotsupp") || lower.contains("enotsup") {
        // The same errno covers both "driver does not support XDP" and
        // "driver does not support AF_XDP". Disambiguate by XDP vs XSK/AF_XDP
        // mention in the message when possible.
        if lower.contains("xsk") || lower.contains("af_xdp") || lower.contains("afxdp") || lower.contains("bind") {
            return EbpfFailCategory::AfXdpUnsupported;
        }
        return EbpfFailCategory::XdpUnsupported;
    }
    if lower.contains("cannot allocate memory") || lower.contains("enomem") || lower.contains("rlimit") {
        return EbpfFailCategory::MemlockExhausted;
    }
    if lower.contains("invalid argument")
        && (lower.contains("verifier") || lower.contains("bpf_prog_load") || lower.contains("program load"))
    {
        return EbpfFailCategory::VerifierRejected;
    }
    if lower.contains("no such file")
        && (lower.contains("net-guardia-ingress") || lower.contains("net-guardia-egress") || lower.contains(".o"))
    {
        return EbpfFailCategory::ObjectNotFound;
    }

    EbpfFailCategory::Unknown
}

fn interface_driver_from(iface_path: &Path) -> String {
    match fs::read_link(iface_path.join("device").join("driver")) {
        Ok(target) => basename_to_string(&target),
        Err(_) => "unknown".to_string(),
    }
}

fn basename_to_string(path: &Path) -> String {
    path.file_name()
        .and_then(OsStr::to_str)
        .map(str::to_string)
        .unwrap_or_else(|| "unknown".to_string())
}

fn read_u32(path: PathBuf) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn count_queue_dirs(iface_path: &Path, prefix: &str) -> Option<usize> {
    let queues_path = iface_path.join("queues");
    let entries = fs::read_dir(queues_path).ok()?;
    let count = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().map(|ty| ty.is_dir()).unwrap_or(false))
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .map(|name| name.starts_with(prefix))
                .unwrap_or(false)
        })
        .count();

    Some(count)
}

fn load_netdev_capabilities(ifindex: u32) -> Option<NetdevCapabilities> {
    let family_id = resolve_genl_family_id(NETDEV_FAMILY_NAME)?;
    let payload = genl_request(
        family_id,
        NETDEV_CMD_DEV_GET,
        &[netlink_attr_u32(NETDEV_A_DEV_IFINDEX, ifindex)],
    );
    let response = netlink_round_trip(&payload)?;
    let attrs = first_genl_attrs(&response)?;

    Some(NetdevCapabilities {
        xdp_features: attr_u64(attrs, NETDEV_A_DEV_XDP_FEATURES),
        xdp_zc_max_segs: attr_u32(attrs, NETDEV_A_DEV_XDP_ZC_MAX_SEGS),
        xsk_features: attr_u64(attrs, NETDEV_A_DEV_XSK_FEATURES),
    })
}

fn resolve_genl_family_id(name: &str) -> Option<u16> {
    let payload = genl_request(
        GENL_ID_CTRL,
        CTRL_CMD_GETFAMILY,
        &[netlink_attr_string(CTRL_ATTR_FAMILY_NAME, name)],
    );
    let response = netlink_round_trip(&payload)?;
    let attrs = first_genl_attrs(&response)?;
    attr_u16(attrs, CTRL_ATTR_FAMILY_ID)
}

fn netlink_round_trip(payload: &[u8]) -> Option<Vec<u8>> {
    let fd = open_netlink_socket()?;
    let sent = send_netlink(fd, payload).is_some();
    let response = if sent { recv_netlink(fd) } else { None };
    close_fd(fd);
    response
}

fn open_netlink_socket() -> Option<RawFd> {
    // SAFETY: socket and bind are called with a valid sockaddr_nl and length.
    let fd = unsafe { socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC) };
    if fd < 0 {
        return None;
    }

    // SAFETY: zeroed sockaddr_nl is immediately initialized before bind.
    let mut addr: sockaddr_nl = unsafe { mem::zeroed() };
    addr.nl_family = AF_NETLINK as u16;

    // SAFETY: fd is a netlink socket, addr points to initialized storage.
    let rc = unsafe {
        bind(
            fd,
            &addr as *const sockaddr_nl as *const sockaddr,
            mem::size_of::<sockaddr_nl>() as u32,
        )
    };
    if rc < 0 {
        close_fd(fd);
        return None;
    }

    Some(fd)
}

fn close_fd(fd: RawFd) {
    // SAFETY: closing an owned file descriptor; failures are irrelevant here.
    unsafe {
        close(fd);
    }
}

fn send_netlink(fd: RawFd, payload: &[u8]) -> Option<()> {
    // SAFETY: zeroed sockaddr_nl is immediately initialized before sendto.
    let mut kernel: sockaddr_nl = unsafe { mem::zeroed() };
    kernel.nl_family = AF_NETLINK as u16;

    // SAFETY: payload is a valid byte slice and kernel points to initialized storage.
    let sent = unsafe {
        sendto(
            fd,
            payload.as_ptr().cast(),
            payload.len(),
            0,
            &kernel as *const sockaddr_nl as *const sockaddr,
            mem::size_of::<sockaddr_nl>() as u32,
        )
    };
    if sent == payload.len() as isize { Some(()) } else { None }
}

fn recv_netlink(fd: RawFd) -> Option<Vec<u8>> {
    let mut buf = vec![0_u8; 8192];
    // SAFETY: buf is valid writable storage for recv.
    let received = unsafe { recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
    if received <= 0 {
        return None;
    }
    buf.truncate(received as usize);
    Some(buf)
}

fn genl_request(nlmsg_type: u16, cmd: u8, attrs: &[Vec<u8>]) -> Vec<u8> {
    let header_len = align4(mem::size_of::<nlmsghdr>());
    let genl_len = mem::size_of::<genlmsghdr>();
    let mut buf = vec![0_u8; header_len + genl_len];

    write_u32(&mut buf, 0, 0);
    write_u16(&mut buf, 4, nlmsg_type);
    write_u16(&mut buf, 6, NLM_F_REQUEST);
    write_u32(&mut buf, 8, NETLINK_SEQUENCE);
    write_u32(&mut buf, 12, 0);
    buf[header_len] = cmd;
    buf[header_len + 1] = 1;

    for attr in attrs {
        buf.extend_from_slice(attr);
    }

    let nlmsg_len = buf.len() as u32;
    write_u32(&mut buf, 0, nlmsg_len);
    buf
}

fn netlink_attr_string(attr_type: u16, value: &str) -> Vec<u8> {
    let mut payload = value.as_bytes().to_vec();
    payload.push(0);
    netlink_attr(attr_type, &payload)
}

fn netlink_attr_u32(attr_type: u16, value: u32) -> Vec<u8> {
    netlink_attr(attr_type, &value.to_ne_bytes())
}

fn netlink_attr(attr_type: u16, payload: &[u8]) -> Vec<u8> {
    let len = 4 + payload.len();
    let mut attr = vec![0_u8; align4(len)];
    write_u16(&mut attr, 0, len as u16);
    write_u16(&mut attr, 2, attr_type);
    attr[4..4 + payload.len()].copy_from_slice(payload);
    attr
}

fn first_genl_attrs(response: &[u8]) -> Option<&[u8]> {
    let header_len = align4(mem::size_of::<nlmsghdr>());
    let genl_len = mem::size_of::<genlmsghdr>();
    if response.len() < header_len + genl_len {
        return None;
    }

    let nlmsg_len = read_u32_ne(response, 0)? as usize;
    let nlmsg_type = read_u16_ne(response, 4)?;
    if nlmsg_type == NLMSG_ERROR || nlmsg_len > response.len() || nlmsg_len < header_len + genl_len {
        return None;
    }

    Some(&response[header_len + genl_len..nlmsg_len])
}

fn attr_u16(attrs: &[u8], attr_type: u16) -> Option<u16> {
    find_attr(attrs, attr_type).and_then(|payload| read_u16_ne(payload, 0))
}

fn attr_u32(attrs: &[u8], attr_type: u16) -> Option<u32> {
    find_attr(attrs, attr_type).and_then(|payload| read_u32_ne(payload, 0))
}

fn attr_u64(attrs: &[u8], attr_type: u16) -> Option<u64> {
    find_attr(attrs, attr_type).and_then(|payload| read_u64_ne(payload, 0))
}

fn find_attr(attrs: &[u8], attr_type: u16) -> Option<&[u8]> {
    let mut offset = 0;
    while offset + 4 <= attrs.len() {
        let len = read_u16_ne(attrs, offset)? as usize;
        let current_type = read_u16_ne(attrs, offset + 2)?;
        if len < 4 || offset + len > attrs.len() {
            return None;
        }

        if current_type == attr_type {
            return Some(&attrs[offset + 4..offset + len]);
        }

        offset += align4(len);
    }

    None
}

fn align4(value: usize) -> usize {
    (value + 3) & !3
}

fn write_u16(buf: &mut [u8], offset: usize, value: u16) {
    buf[offset..offset + 2].copy_from_slice(&value.to_ne_bytes());
}

fn write_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}

fn read_u16_ne(buf: &[u8], offset: usize) -> Option<u16> {
    let bytes = buf.get(offset..offset + 2)?;
    Some(u16::from_ne_bytes([bytes[0], bytes[1]]))
}

fn read_u32_ne(buf: &[u8], offset: usize) -> Option<u32> {
    let bytes = buf.get(offset..offset + 4)?;
    Some(u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64_ne(buf: &[u8], offset: usize) -> Option<u64> {
    let bytes = buf.get(offset..offset + 8)?;
    Some(u64::from_ne_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categorizes_permission_errors() {
        assert!(matches!(
            categorize("Permission denied (os error 13)"),
            EbpfFailCategory::Permission
        ));
        assert!(matches!(
            categorize("Operation not permitted"),
            EbpfFailCategory::Permission
        ));
    }

    #[test]
    fn categorizes_af_xdp_vs_xdp() {
        assert!(matches!(
            categorize("bind failed: Operation not supported (os error 95)"),
            EbpfFailCategory::AfXdpUnsupported
        ));
        assert!(matches!(
            categorize("xdp attach: Operation not supported"),
            EbpfFailCategory::XdpUnsupported
        ));
    }

    #[test]
    fn loads_interface_capabilities_from_sysfs_shape() {
        let root = std::env::temp_dir().join(format!("netguardia-ebpf-preflight-{}", std::process::id()));
        let iface = root.join("eth0");
        let queues = iface.join("queues");
        let device = iface.join("device");
        let driver_target = root.join("drivers").join("virtio_net");

        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(queues.join("rx-0")).unwrap();
        fs::create_dir_all(queues.join("rx-1")).unwrap();
        fs::create_dir_all(queues.join("tx-0")).unwrap();
        fs::create_dir_all(&driver_target).unwrap();
        fs::create_dir_all(&device).unwrap();
        fs::write(iface.join("mtu"), "1500\n").unwrap();
        fs::write(iface.join("ifindex"), "not-a-number\n").unwrap();
        std::os::unix::fs::symlink(&driver_target, device.join("driver")).unwrap();

        let caps = InterfaceCapabilities::load_from("eth0", &root);

        assert_eq!(caps.driver, "virtio_net");
        assert_eq!(caps.mtu, Some(1500));
        assert_eq!(caps.rx_queues, Some(2));
        assert_eq!(caps.tx_queues, Some(1));
        assert_eq!(caps.netdev, None);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn parses_netlink_attributes() {
        let attrs = [
            netlink_attr_u32(NETDEV_A_DEV_IFINDEX, 7),
            netlink_attr(NETDEV_A_DEV_XDP_FEATURES, &8_u64.to_ne_bytes()),
        ]
        .concat();

        assert_eq!(attr_u32(&attrs, NETDEV_A_DEV_IFINDEX), Some(7));
        assert_eq!(attr_u64(&attrs, NETDEV_A_DEV_XDP_FEATURES), Some(8));
        assert_eq!(attr_u32(&attrs, NETDEV_A_DEV_XSK_FEATURES), None);
    }

    #[test]
    fn interprets_xsk_zerocopy_from_netdev_features() {
        let caps = InterfaceCapabilities {
            driver: "virtio_net".to_string(),
            mtu: Some(1500),
            rx_queues: Some(1),
            tx_queues: Some(1),
            netdev: Some(NetdevCapabilities {
                xdp_features: Some(NETDEV_XDP_ACT_XSK_ZEROCOPY),
                xdp_zc_max_segs: Some(1),
                xsk_features: Some(0),
            }),
        };

        assert_eq!(caps.xsk_zerocopy_supported(), Some(true));
    }
}
