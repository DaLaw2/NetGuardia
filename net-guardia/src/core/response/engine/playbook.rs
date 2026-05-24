use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use macros::log;

use crate::common::error::Error;
use crate::core::response::engine::SoarEngine;
use crate::domain::detection::attack_type::canonical_from_str;
use crate::domain::response::condition::{ConditionType, PlaybookCondition, is_valid_operator};
use crate::domain::response::error::SoarError;
use crate::domain::response::log::SoarLog;
use crate::domain::response::playbook::{ActionType, Playbook, PlaybookAction, PlaybookActionParams};

impl SoarEngine {
    pub async fn reload_cache(&self) -> Result<(), Error> {
        let views = self.db.list_playbooks().await?;
        let mut playbooks: Vec<Playbook> = Vec::new();

        for view in views {
            let mut actions: Vec<PlaybookAction> = Vec::new();
            for a in view.actions {
                actions.push(PlaybookAction {
                    action_order: a.action_order,
                    action_type: a.action_type.parse::<ActionType>()?,
                    params: parse_action_params(&a.params),
                });
            }

            let mut conditions: Vec<PlaybookCondition> = Vec::new();
            for c in view.conditions {
                let ctype = c.condition_type.parse::<ConditionType>()?;
                if !is_valid_operator(&ctype, &c.operator) {
                    Err(SoarError::InvalidConditionOperator(
                        c.condition_type.clone(),
                        c.operator.clone(),
                    ))?;
                }
                conditions.push(PlaybookCondition {
                    condition_type: ctype,
                    operator: c.operator,
                    value: c.value,
                    value2: c.value2,
                });
            }

            let Some(trigger_event) = canonical_from_str(&view.trigger_event) else {
                log!(SoarLog::NonCanonicalTriggerEvent(
                    view.name.clone(),
                    view.trigger_event.clone(),
                ));
                continue;
            };

            playbooks.push(Playbook {
                id: view.id,
                name: view.name,
                enabled: view.enabled,
                trigger_event,
                cooldown_secs: view.cooldown_secs,
                actions,
                conditions,
            });
        }

        let playbook_count = playbooks.len();
        let playbooks: Vec<Arc<Playbook>> = playbooks.into_iter().map(Arc::new).collect();
        self.matcher.playbooks.store(Arc::new(playbooks));

        let whitelist = self.db.list_admin_whitelist().await?;
        let whitelist: HashSet<String> = whitelist.into_iter().collect();
        let whitelist_count = whitelist.len();
        self.matcher.admin_whitelist.store(Arc::new(whitelist));

        let count = self.db.count_active_soar_blocks().await?;
        self.matcher.active_block_count.store(count, Ordering::SeqCst);

        log!(SoarLog::CacheLoaded(playbook_count, whitelist_count, count));

        Ok(())
    }
}

fn parse_action_params(params: &serde_json::Value) -> PlaybookActionParams {
    PlaybookActionParams {
        ttl_secs: params.get("ttl_secs").and_then(|v| v.as_u64()),
        factor: params.get("factor").and_then(|v| v.as_f64()),
        url: params.get("url").and_then(|v| v.as_str()).map(str::to_string),
        timeout_secs: params.get("timeout_secs").and_then(|v| v.as_u64()),
        level: params.get("level").and_then(|v| v.as_str()).map(str::to_string),
    }
}
