//! HTTP surface for fusion-layer observability + incident explain.
//! Metrics handlers read shared atomic counters maintained by the
//! detection orchestrator — they never touch orchestrator state, so a
//! hung dashboard cannot stall the detection pipeline. The explain
//! handler reads the WORM audit chain populated by
//! `publish_fusion_audit` and surfaces a per-IP evidence timeline so
//! analysts can answer "why was this IP blocked?" without parsing
//! logs by hand.

use actix_web::{HttpRequest, HttpResponse, Responder, Scope, web};

use crate::core::detection::metrics::FusionMetrics;
use crate::interface::port::audit::{AuditLogEntry, AuditRepo};

/// Maximum audit rows scanned per explain request. Caps DB work in
/// case the audit chain grows large enough that a naive full-table
/// scan would be noticeable.
const FUSION_EXPLAIN_SCAN_LIMIT: i64 = 5_000;

/// Upper cap on entries returned to the client per explain request.
/// Guards against a UI rendering path that chokes on enormous JSON.
const FUSION_EXPLAIN_RESPONSE_CAP: usize = 200;

/// Stable audit action string the fusion engine emits — kept in sync
/// with `core::detection::orchestrator::FUSION_AUDIT_ACTION`. If that
/// constant changes, the explain endpoint silently returns nothing, so
/// keep this updated at the same time.
const FUSION_AUDIT_ACTION: &str = "fused_threat_emitted";

pub fn initialize() -> Scope {
    web::scope("/fusion")
        .route("/metrics", web::get().to(get_metrics))
        .route("/explain/{src_ip}", web::get().to(explain_ip))
}

/// `GET /api/fusion/metrics` — lock-free snapshot of fusion counters and
/// derived rates. Drives the operator dashboard's "how well is fusion
/// working on my network?" view.
async fn get_metrics(metrics: web::Data<FusionMetrics>) -> impl Responder {
    HttpResponse::Ok().json(metrics.snapshot())
}

/// `GET /api/fusion/explain/{src_ip}` — per-IP fusion evidence timeline.
/// Scans the WORM audit chain for `fused_threat_emitted` entries that
/// match `src_ip`, returning them oldest-first so the UI can render a
/// chronological "why was this IP blocked" view.
async fn explain_ip(req: HttpRequest, audit: web::Data<dyn AuditRepo>) -> impl Responder {
    let src_ip = match req.match_info().get("src_ip") {
        Some(ip) => ip.to_string(),
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "missing src_ip path segment",
            }));
        }
    };

    let entries = match audit.list_audit_logs_by_action(FUSION_AUDIT_ACTION, FUSION_EXPLAIN_SCAN_LIMIT) {
        Ok(e) => e,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("audit store unavailable: {e}"),
            }));
        }
    };

    let (matches, truncated) = filter_fusion_evidence_for_ip(&entries, &src_ip, FUSION_EXPLAIN_RESPONSE_CAP);
    HttpResponse::Ok().json(serde_json::json!({
        "src_ip": src_ip,
        "match_count": matches.len(),
        "truncated": truncated,
        "entries": matches,
    }))
}

/// Filter audit entries down to the ones whose JSON detail's `src_ip`
/// matches `target_ip`, ordered oldest-first (ascending id). Entries
/// with unparseable detail are dropped silently — the chain is
/// append-only, so a malformed row is an integrity concern for the
/// audit-verify endpoint to surface, not this handler.
///
/// Returns `(entries_up_to_cap, truncated)`. `truncated` is `true` when
/// at least one matching entry was dropped — `matches.len() == cap` does
/// NOT imply truncation, so we look at `cap + 1` candidates and set the
/// flag only when the overflow entry exists.
///
/// Extracted as a free function so tests can cover the filter /
/// ordering / cap behaviour without an in-memory DB.
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
    let rendered = filtered
        .into_iter()
        .map(|entry| {
            let detail: serde_json::Value = serde_json::from_str(&entry.detail).unwrap_or(serde_json::Value::Null);
            serde_json::json!({
                "id": entry.id,
                "actor": entry.actor,
                "action": entry.action,
                "created_at": entry.created_at,
                "detail": detail,
            })
        })
        .collect();
    (rendered, truncated)
}

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
        // Real repo query returns DESC; filter must still hand back ASC.
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
        // Regression guard: `matches.len() == cap` with no overflow row must
        // return `truncated = false`. Earlier `>=` check mis-flagged this.
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
