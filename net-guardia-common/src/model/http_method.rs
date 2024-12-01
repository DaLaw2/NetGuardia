/// HTTP methods bitmap type for eBPF programs.
///
/// Each bit represents whether a specific HTTP method is allowed:
/// - Bit 0: GET     (0b0000_0000_0000_0001)
/// - Bit 1: POST    (0b0000_0000_0000_0010)
/// - Bit 2: PUT     (0b0000_0000_0000_0100)
/// - Bit 3: DELETE  (0b0000_0000_0000_1000)
/// - Bit 4: HEAD    (0b0000_0000_0001_0000)
/// - Bit 5: OPTIONS (0b0000_0000_0010_0000)
/// - Bit 6: PATCH   (0b0000_0000_0100_0000)
/// - Bit 7: TRACE   (0b0000_0000_1000_0000)
/// - Bit 8: CONNECT (0b0000_0001_0000_0000)
///
/// # Examples
/// ```ignore
/// // Allow GET and POST
/// let methods: EbpfHttpMethod = 0b0000_0000_0000_0011;
///
/// // Allow all common methods (GET, POST, PUT, DELETE, PATCH)
/// let methods: EbpfHttpMethod = 0b0000_0000_0100_1111;
/// ```
pub type EbpfHttpMethod = u16;
