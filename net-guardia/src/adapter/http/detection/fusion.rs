use std::cmp;
use std::net::IpAddr;

use actix_web::{HttpResponse, Responder, Scope, web};
use arc_swap::ArcSwap;

use crate::adapter::http::helpers::{bad_request, internal_error};
use crate::core::detection::metrics::FusionMetrics;
use crate::domain::common::audit::AuditLogEntry;
use crate::domain::common::config::AppConfig;
use crate::interface::system::audit::AuditRepo;

pub fn initialize() -> Scope {
    web::scope("/fusion")
        .route("/metrics", web::get().to(get_metrics))
        .route("/explain/{src_ip}", web::get().to(explain_ip))
}

async fn get_metrics(metrics: web::Data<FusionMetrics>) -> impl Responder {
    HttpResponse::Ok().json(metrics.snapshot())
}

async fn explain_ip(
    path: web::Path<String>,
    audit: web::Data<dyn AuditRepo>,
    app_config: web::Data<ArcSwap<AppConfig>>,
) -> impl Responder {
    let src_ip = path.into_inner();
    let src_ip = match src_ip.parse::<IpAddr>() {
        Ok(ip) => ip.to_string(),
        Err(_) => return bad_request("Invalid source IP address"),
    };
    let obs = app_config.load().observability.clone();
    let query_limit = fusion_explain_query_limit(obs.fusion_explain_scan_limit, obs.fusion_explain_response_cap);
    let mut entries = match audit.list_audit_logs_by_src_ip(&src_ip, query_limit).await {
        Ok(e) => e,
        Err(e) => {
            return internal_error(format!("audit store unavailable: {e}"));
        }
    };

    let truncated = entries.len() > obs.fusion_explain_response_cap;
    if truncated {
        entries.truncate(obs.fusion_explain_response_cap);
    }
    let matches: Vec<serde_json::Value> = entries.iter().map(render_fusion_evidence_entry).collect();
    HttpResponse::Ok().json(serde_json::json!({
        "src_ip": src_ip,
        "match_count": matches.len(),
        "truncated": truncated,
        "entries": matches,
    }))
}

fn fusion_explain_query_limit(scan_limit: i64, response_cap: usize) -> i64 {
    let cap_plus_one = i64::try_from(response_cap.saturating_add(1)).unwrap_or(i64::MAX);
    cmp::max(1, cmp::min(scan_limit, cap_plus_one))
}

#[cfg(test)]
pub fn filter_fusion_evidence_for_ip(
    entries: &[AuditLogEntry],
    target_ip: &str,
    cap: usize,
) -> (Vec<serde_json::Value>, bool) {
    let mut filtered: Vec<&AuditLogEntry> = entries
        .iter()
        .filter(|entry| detail_matches_src_ip(&entry.detail, target_ip))
        .collect();
    filtered.sort_by_key(|entry| entry.id);
    let truncated = filtered.len() > cap;
    if truncated {
        filtered.truncate(cap);
    }
    let rendered = filtered.into_iter().map(render_fusion_evidence_entry).collect();
    (rendered, truncated)
}

fn render_fusion_evidence_entry(entry: &AuditLogEntry) -> serde_json::Value {
    let detail: serde_json::Value = serde_json::from_str(&entry.detail).unwrap_or_default();
    serde_json::json!({
        "id": entry.id,
        "actor": entry.actor,
        "action": entry.action,
        "created_at": entry.created_at,
        "detail": detail,
    })
}

#[cfg(test)]
fn detail_matches_src_ip(detail_json: &str, target_ip: &str) -> bool {
    let parsed: serde_json::Value = match serde_json::from_str(detail_json) {
        Ok(v) => v,
        Err(_) => return false,
    };
    parsed.get("src_ip").and_then(|v| v.as_str()) == Some(target_ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: i64, src_ip: &str, attack: &str) -> AuditLogEntry {
        let detail = serde_json::json!({
            "src_ip": src_ip,
            "attack_type": attack,
            "fused_confidence": 0.9,
            "per_source": [{"source": "Suricata", "confidence": 0.9, "local_attack_type": "brute-force"}],
        })
        .to_string();
        AuditLogEntry {
            id,
            actor: "FusionEngine".to_string(),
            action: "fused_threat_emitted".to_string(),
            detail,
            created_at: format!("2026-04-18T10:00:{:02}Z", id),
        }
    }

    #[test]
    fn filter_returns_only_matching_src_ip() {
        let entries = [
            entry(1, "1.2.3.4", "brute_force"),
            entry(2, "10.0.0.5", "port_scan"),
            entry(3, "1.2.3.4", "exploit"),
        ];
        let (got, truncated) = filter_fusion_evidence_for_ip(&entries, "1.2.3.4", 100);
        assert_eq!(got.len(), 2);
        assert!(!truncated);
        assert_eq!(got[0]["id"], 1);
        assert_eq!(got[1]["id"], 3);
    }

    #[test]
    fn filter_sorts_oldest_first_even_when_input_is_reversed() {
        let entries = [
            entry(30, "1.1.1.1", "a"),
            entry(10, "1.1.1.1", "b"),
            entry(20, "1.1.1.1", "c"),
        ];
        let (got, _) = filter_fusion_evidence_for_ip(&entries, "1.1.1.1", 100);
        let ids: Vec<i64> = got.iter().map(|v| v["id"].as_i64().unwrap()).collect();
        assert_eq!(ids, vec![10, 20, 30]);
    }

    #[test]
    fn filter_applies_response_cap() {
        let entries: Vec<AuditLogEntry> = (1..=10).map(|i| entry(i, "9.9.9.9", "x")).collect();
        let (got, truncated) = filter_fusion_evidence_for_ip(&entries, "9.9.9.9", 3);
        assert_eq!(got.len(), 3);
        assert!(truncated, "10 matching rows with cap=3 must set truncated");
        let ids: Vec<i64> = got.iter().map(|v| v["id"].as_i64().unwrap()).collect();
        assert_eq!(ids, vec![1, 2, 3], "cap takes oldest, not newest");
    }

    #[test]
    fn filter_exactly_cap_is_not_truncated() {
        let entries: Vec<AuditLogEntry> = (1..=3).map(|i| entry(i, "9.9.9.9", "x")).collect();
        let (got, truncated) = filter_fusion_evidence_for_ip(&entries, "9.9.9.9", 3);
        assert_eq!(got.len(), 3);
        assert!(!truncated, "exactly cap matches must NOT report truncated");
    }

    #[test]
    fn filter_drops_rows_with_unparseable_detail() {
        let good = entry(1, "1.2.3.4", "brute_force");
        let bad = AuditLogEntry {
            id: 2,
            actor: "FusionEngine".into(),
            action: "fused_threat_emitted".into(),
            detail: "{{not json".into(),
            created_at: "2026-04-18T10:00:02Z".into(),
        };
        let (got, _) = filter_fusion_evidence_for_ip(&[good, bad], "1.2.3.4", 100);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0]["id"], 1);
    }

    #[test]
    fn filter_nonmatching_ip_returns_empty() {
        let entries = [entry(1, "1.2.3.4", "brute_force")];
        let (got, truncated) = filter_fusion_evidence_for_ip(&entries, "5.6.7.8", 100);
        assert!(got.is_empty());
        assert!(!truncated);
    }

    #[test]
    fn filter_preserves_detail_structure_in_response() {
        let entries = [entry(1, "1.2.3.4", "brute_force")];
        let (got, _) = filter_fusion_evidence_for_ip(&entries, "1.2.3.4", 100);
        assert_eq!(got.len(), 1);
        let detail = &got[0]["detail"];
        assert_eq!(detail["attack_type"], "brute_force");
        assert_eq!(detail["per_source"][0]["source"], "Suricata");
    }
}
