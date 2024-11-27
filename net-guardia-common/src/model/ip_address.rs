/// IPv4 address stored as a u32 in network byte order (big-endian)
///
/// # Example
/// ```ignore
/// let ip_bytes = [192, 168, 1, 1];
/// let ip: IPv4 = u32::from_be_bytes(ip_bytes);
/// ```
pub type IPv4 = u32;

/// IPv6 address stored as a u128 in network byte order (big-endian)
///
/// # Example
/// ```ignore
/// let ip_bytes = [
///     0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
/// ];
/// let ip: IPv6 = u128::from_be_bytes(ip_bytes);
/// ```
pub type IPv6 = u128;

/// Network port number stored as a u16
///
/// Valid values range from 0 to 65535 (inclusive).
/// Common well-known ports are 0-1023, registered ports are 1024-49151,
/// and dynamic/private ports are 49152-65535.
///
/// # Example
/// ```ignore
/// let http_port: Port = 80;
/// let https_port: Port = 443;
/// let dynamic_port: Port = 49152;
/// ```
pub type Port = u16;

/// Network endpoint identifier combining IP address and port number
///
/// # Layout
/// ```text
/// [0]: IPv4 address (u32) in network byte order
/// [1]: Port number (u16) in network byte order, stored in lower 16 bits
/// ```
///
/// # Example
/// ```ignore
/// // Create key for 192.168.1.1:8080
/// let ip_bytes = [192, 168, 1, 1];
/// let ip = u32::from_be_bytes(ip_bytes);
/// let port = 8080_u16;
/// let key: IpPortKey = [ip, port as u32];
/// ```
///
/// # Note
/// - IP address should be in network byte order (big-endian)
/// - Port number is stored in the lower 16 bits of the second u32
/// - Upper 16 bits of second u32 are unused and should be zero
///
/// # Memory Layout
/// ```text
/// [0]:    [------------ IP Address (32 bits) ------------]
/// [1]:    [-- Unused (16 bits) --][--- Port (16 bits) ---]
/// ```
pub type AddrPortV4 = [u32; 2];

/// Network endpoint identifier combining IPv6 address and port number
///
/// A compact representation of an IPv6 endpoint using two u128 values,
/// storing the IP address and port number in network byte order.
///
/// # Layout
/// ```text
/// [0]: IPv6 address (u128) in network byte order
/// [1]: Port number (u16) in network byte order, stored in lower 16 bits
/// ```
///
/// # Example
/// ```ignore
/// // Create key for 2001:db8::1:8080
/// let ip_bytes = [
///     0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
/// ];
/// let ip = u128::from_be_bytes(ip_bytes);
/// let port = 8080_u16;
/// let key: AddrPortV6 = [ip, port as u128];
/// ```
///
/// # Notes
/// - IP address should be in network byte order (big-endian)
/// - Port number is stored in the lower 16 bits of the second u128
/// - Upper 112 bits of second u128 are unused and should be zero
///
/// # Memory Layout
/// ```text
/// [0]:    [---------------------- IPv6 Address (128 bits) ----------------------]
/// [1]:    [-------------- Unused (112 bits) --------------][-- Port (16 bits) --]
/// ```
pub type AddrPortV6 = [u128; 2];
