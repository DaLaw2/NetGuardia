#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackOutcome {
    Blocked,
    BlockFailed,
    WhitelistSkipped,
    CooldownSkipped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatHandleOutcome {
    PlaybooksExecuted { count: usize, errors: usize },
    Fallback { outcome: FallbackOutcome },
    NoSourceIp,
}
