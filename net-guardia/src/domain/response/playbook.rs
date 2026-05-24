use std::fmt;
use std::str::FromStr;

use crate::domain::common::event::ThreatDetectedEvent;
use crate::domain::detection::attack_type::{CanonicalAttackType, canonical_from_str};
use crate::domain::response::condition::PlaybookCondition;
use crate::domain::response::error::SoarError;

#[derive(Debug, Clone)]
pub struct Playbook {
    pub id: i64,
    pub name: String,
    pub enabled: bool,
    pub trigger_event: CanonicalAttackType,
    pub cooldown_secs: i64,
    pub actions: Vec<PlaybookAction>,
    pub conditions: Vec<PlaybookCondition>,
}

impl Playbook {
    pub fn matches_trigger(&self, event: &ThreatDetectedEvent) -> bool {
        self.enabled
            && canonical_from_str(&event.attack_type).is_some_and(|event_type| self.trigger_event == event_type)
    }
}

#[derive(Debug, Clone)]
pub struct PlaybookAction {
    pub action_order: i64,
    pub action_type: ActionType,
    pub params: PlaybookActionParams,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ActionType {
    BlockIp,
    AdjustRateLimit,
    SendTelegram,
    SendEmail,
    Webhook,
    Log,
}

impl ActionType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BlockIp => "block_ip",
            Self::AdjustRateLimit => "adjust_rate_limit",
            Self::SendTelegram => "send_telegram",
            Self::SendEmail => "send_email",
            Self::Webhook => "webhook",
            Self::Log => "log",
        }
    }
}

impl fmt::Display for ActionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ActionType {
    type Err = SoarError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "block_ip" => Ok(Self::BlockIp),
            "adjust_rate_limit" => Ok(Self::AdjustRateLimit),
            "send_telegram" => Ok(Self::SendTelegram),
            "send_email" => Ok(Self::SendEmail),
            "webhook" => Ok(Self::Webhook),
            "log" => Ok(Self::Log),
            other => Err(SoarError::UnknownActionType(other)),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PlaybookActionParams {
    pub ttl_secs: Option<u64>,
    pub factor: Option<f64>,
    pub url: Option<String>,
    pub timeout_secs: Option<u64>,
    pub level: Option<String>,
}
