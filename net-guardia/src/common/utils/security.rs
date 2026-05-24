pub fn constant_time_eq(expected: &str, candidate: &str) -> bool {
    let expected_bytes = expected.as_bytes();
    let candidate_bytes = candidate.as_bytes();
    let mut diff = expected_bytes.len() ^ candidate_bytes.len();
    for (index, expected_byte) in expected_bytes.iter().enumerate() {
        let candidate_byte = candidate_bytes.get(index).copied().unwrap_or(0);
        diff |= usize::from(expected_byte ^ candidate_byte);
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::constant_time_eq;

    #[test]
    fn constant_time_eq_accepts_matching_values() {
        assert!(constant_time_eq("abc123", "abc123"));
    }

    #[test]
    fn constant_time_eq_rejects_mismatched_values() {
        assert!(!constant_time_eq("abc123", "abc124"));
        assert!(!constant_time_eq("abc123", "abc1234"));
        assert!(!constant_time_eq("abc123", "abc12"));
    }
}
