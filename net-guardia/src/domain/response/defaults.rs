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
            operator: "==",
            value: "Suricata",
            value2: Some("0.95"),
        }],
    },
];
