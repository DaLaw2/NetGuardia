/// Network flow statistics tracking bytes, packets count, and timing
///
/// # Layout
/// ```text
/// [0]: Total bytes count (u64)
/// [1]: Total packets count (u64)
/// [2]: Last seen timestamp (u64) in nanoseconds from system boot
/// ```
///
/// # Example
/// ```ignore
/// // Create new flow status
/// let now = bpf_ktime_get_ns();
/// let status: FlowStatus = [
///     1500,       // 1500 bytes
///     1,          // 1 packet
///     now,        // Current timestamp
/// ];
///
/// // Update existing flow
/// status[0] += packet_size;   // Add bytes
/// status[1] += 1;             // Increment packet count
/// status[2] = new_timestamp;  // Update last seen
/// ```
///
/// # Notes
/// - All counters are monotonically increasing
/// - Timestamp uses kernel time (bpf_ktime_get_ns)
/// - Counters may wrap around on very high traffic flows
///
/// # Memory Layout
/// ```text
/// [0]:    [------------------- Bytes (64 bits) ------------------]
/// [1]:    [------------------ Packets (64 bits) -----------------]
/// [2]:    [----------------- Timestamp (64 bits) ----------------]
/// ```
pub type FlowStatus = [u64; 3];
