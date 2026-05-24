pub struct DefaultPlaybook {
    pub name: &'static str,
    pub trigger_event: &'static str,
    pub threshold: Option<f64>,
    pub count: Option<i64>,
    pub window: Option<i64>,
    pub cooldown: i64,
    pub actions: &'static [DefaultAction],
    pub conditions: &'static [DefaultCondition],
}

pub struct DefaultAction {
    pub order: i64,
    pub action_type: &'static str,
    pub params: &'static str,
}

pub struct DefaultCondition {
    pub condition_type: &'static str,
    pub operator: &'static str,
    pub value: &'static str,
    pub value2: Option<&'static str>,
}

pub const DEFAULT_PLAYBOOKS: &[DefaultPlaybook] = &[
    DefaultPlaybook {
        name: "brute_force_block",
        trigger_event: "brute_force",
        threshold: None,
        count: Some(5),
        window: Some(60),
        cooldown: 600,
        actions: &[
            DefaultAction {
                order: 1,
                action_type: "block_ip",
                params: r#"{"ttl_secs": 3600}"#,
            },
            DefaultAction {
                order: 2,
                action_type: "send_telegram",
                params: "{}",
            },
            DefaultAction {
                order: 3,
                action_type: "log",
                params: r#"{"level": "warn"}"#,
            },
        ],
        conditions: &[DefaultCondition {
            condition_type: "frequency",
            operator: ">=",
            value: "5",
            value2: Some("60"),
        }],
    },
    DefaultPlaybook {
        name: "port_scan_alert",
        trigger_event: "port_scan",
        threshold: Some(0.7),
        count: None,
        window: None,
        cooldown: 300,
        actions: &[
            DefaultAction {
                order: 1,
                action_type: "send_telegram",
                params: "{}",
            },
            DefaultAction {
                order: 2,
                action_type: "log",
                params: r#"{"level": "warn"}"#,
            },
        ],
        conditions: &[DefaultCondition {
            condition_type: "threshold",
            operator: ">=",
            value: "0.7",
            value2: None,
        }],
    },
    DefaultPlaybook {
        name: "fusion_c2_multi_source_block",
        trigger_event: "c2_beacon",
        threshold: None,
        count: None,
        window: None,
        cooldown: 600,
        actions: &[
            DefaultAction {
                order: 1,
                action_type: "block_ip",
                params: r#"{"ttl_secs": 3600}"#,
            },
            DefaultAction {
                order: 2,
                action_type: "send_telegram",
                params: "{}",
            },
            DefaultAction {
                order: 3,
                action_type: "log",
                params: r#"{"level": "warn"}"#,
            },
        ],
        conditions: &[DefaultCondition {
            condition_type: "multi_source_min",
            operator: ">=",
            value: "2",
            value2: None,
        }],
    },
    DefaultPlaybook {
        name: "fusion_c2_suricata_solo_high_block",
        trigger_event: "c2_beacon",
        threshold: None,
        count: None,
        window: None,
        cooldown: 600,
        actions: &[
            DefaultAction {
                order: 1,
                action_type: "block_ip",
                params: r#"{"ttl_secs": 3600}"#,
            },
            DefaultAction {
                order: 2,
                action_type: "send_telegram",
                params: "{}",
            },
            DefaultAction {
                order: 3,
                action_type: "log",
                params: r#"{"level": "warn"}"#,
            },
        ],
        conditions: &[DefaultCondition {
            condition_type: "single_source_high",
            operator: ">=",
            value: "Suricata",
            value2: Some("0.95"),
        }],
    },
];

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::domain::common::event::DetectionSource;
    use crate::domain::response::condition::{ConditionType, is_valid_operator};

    #[test]
    fn default_playbook_conditions_use_valid_domain_operators() {
        for playbook in DEFAULT_PLAYBOOKS {
            for condition in playbook.conditions {
                let condition_type =
                    ConditionType::from_str(condition.condition_type).expect("default condition type should be known");

                assert!(
                    is_valid_operator(&condition_type, condition.operator),
                    "default playbook '{}' condition '{}' uses invalid operator '{}'",
                    playbook.name,
                    condition.condition_type,
                    condition.operator
                );
            }
        }
    }

    #[test]
    fn default_playbook_condition_values_parse() {
        for playbook in DEFAULT_PLAYBOOKS {
            for condition in playbook.conditions {
                let condition_type =
                    ConditionType::from_str(condition.condition_type).expect("default condition type should be known");

                match condition_type {
                    ConditionType::Threshold | ConditionType::FusedConfidenceAbove => {
                        condition.value.parse::<f64>().expect("threshold should parse");
                    }
                    ConditionType::Frequency | ConditionType::MultiSourceMin => {
                        condition.value.parse::<usize>().expect("count should parse");
                    }
                    ConditionType::SingleSourceHigh => {
                        DetectionSource::from_str(condition.value).expect("source should parse");
                        if let Some(value2) = condition.value2 {
                            value2.parse::<f32>().expect("confidence should parse");
                        }
                    }
                    ConditionType::SourceCountry | ConditionType::IpPattern | ConditionType::RepeatOffender => {}
                }
            }
        }
    }
}
