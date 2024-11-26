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
pub type IpPortKey = [u32; 2];
