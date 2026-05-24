pub fn level_severity(level: &str) -> u8 {
    match level {
        "ERROR" => 1,
        "WARN" => 2,
        "INFO" => 3,
        "DEBUG" => 4,
        _ => 5,
    }
}
