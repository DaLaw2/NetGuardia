use crate::interface::port::repository::RepositoryPort;
use crate::model::error::Error;

/// Generate an HTML weekly report email body.
///
/// Reads aggregated statistics from the Database settings table and formats
/// them into a self-contained HTML email. Keys consumed:
///   - `weekly_threats_count`
///   - `weekly_top_ips` (JSON array of `{ "ip": "...", "count": N }`)
///   - `weekly_threat_breakdown` (JSON object `{ "type": count, ... }`)
///   - `weekly_bandwidth_bytes`
///   - `weekly_system_health` (JSON object with cpu, memory, disk fields)
///
/// If a key is missing the report uses empty/zero defaults.
pub fn generate_weekly_report(db: &dyn RepositoryPort) -> Result<String, Error> {
    let threats_count = db
        .get_setting("weekly_threats_count")
?
        .unwrap_or_else(|| "0".to_string());

    let top_ips_json = db
        .get_setting("weekly_top_ips")
?
        .unwrap_or_else(|| "[]".to_string());

    let threat_breakdown_json = db
        .get_setting("weekly_threat_breakdown")
?
        .unwrap_or_else(|| "{}".to_string());

    let bandwidth = db
        .get_setting("weekly_bandwidth_bytes")
?
        .unwrap_or_else(|| "0".to_string());

    let health_json = db
        .get_setting("weekly_system_health")
?
        .unwrap_or_else(|| {
            serde_json::json!({
                "cpu_percent": 0.0,
                "memory_percent": 0.0,
                "disk_percent": 0.0
            })
            .to_string()
        });

    // ── Parse JSON blobs ───────────────────────────────────────────────

    let top_ips: Vec<serde_json::Value> =
        serde_json::from_str(&top_ips_json).unwrap_or_default();

    let threat_breakdown: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&threat_breakdown_json).unwrap_or_default();

    let health: serde_json::Value =
        serde_json::from_str(&health_json).unwrap_or_default();

    // ── Build HTML ─────────────────────────────────────────────────────

    let bandwidth_mb = bandwidth
        .parse::<f64>()
        .unwrap_or(0.0)
        / 1_048_576.0;

    let mut top_ips_rows = String::new();
    for (i, entry) in top_ips.iter().enumerate().take(5) {
        let ip = entry["ip"].as_str().unwrap_or("unknown");
        let count = entry["count"].as_u64().unwrap_or(0);
        top_ips_rows.push_str(&format!(
            "<tr><td style=\"padding:6px 12px;border-bottom:1px solid #e0e0e0;\">{}</td>\
             <td style=\"padding:6px 12px;border-bottom:1px solid #e0e0e0;\">{}</td>\
             <td style=\"padding:6px 12px;border-bottom:1px solid #e0e0e0;text-align:right;\">{}</td></tr>",
            i + 1,
            ip,
            count,
        ));
    }

    let mut breakdown_rows = String::new();
    for (threat_type, count) in &threat_breakdown {
        let n = count.as_u64().unwrap_or(0);
        breakdown_rows.push_str(&format!(
            "<tr><td style=\"padding:6px 12px;border-bottom:1px solid #e0e0e0;\">{}</td>\
             <td style=\"padding:6px 12px;border-bottom:1px solid #e0e0e0;text-align:right;\">{}</td></tr>",
            threat_type, n,
        ));
    }

    let cpu = health["cpu_percent"].as_f64().unwrap_or(0.0);
    let mem = health["memory_percent"].as_f64().unwrap_or(0.0);
    let disk = health["disk_percent"].as_f64().unwrap_or(0.0);

    let now = chrono::Local::now().format("%Y-%m-%d %H:%M");

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Arial,Helvetica,sans-serif;background:#f4f6f9;margin:0;padding:20px;">
<div style="max-width:640px;margin:0 auto;background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">

  <!-- Header -->
  <div style="background:#1a237e;color:#ffffff;padding:24px 32px;">
    <h1 style="margin:0;font-size:22px;">NetGuardia Weekly Report</h1>
    <p style="margin:6px 0 0;font-size:13px;opacity:0.85;">Generated {now}</p>
  </div>

  <div style="padding:24px 32px;">

    <!-- Threats summary -->
    <h2 style="font-size:16px;color:#1a237e;border-bottom:2px solid #1a237e;padding-bottom:6px;">
      Threat Summary
    </h2>
    <p style="font-size:28px;font-weight:bold;margin:8px 0;">{threats_count}
      <span style="font-size:14px;font-weight:normal;color:#666;"> threats detected this week</span>
    </p>

    <!-- Top blocked IPs -->
    <h2 style="font-size:16px;color:#1a237e;border-bottom:2px solid #1a237e;padding-bottom:6px;margin-top:24px;">
      Top 5 Blocked IPs
    </h2>
    <table style="width:100%;border-collapse:collapse;font-size:14px;">
      <thead>
        <tr style="background:#f0f0f0;">
          <th style="padding:8px 12px;text-align:left;">#</th>
          <th style="padding:8px 12px;text-align:left;">IP Address</th>
          <th style="padding:8px 12px;text-align:right;">Events</th>
        </tr>
      </thead>
      <tbody>{top_ips_rows}</tbody>
    </table>

    <!-- Threat breakdown -->
    <h2 style="font-size:16px;color:#1a237e;border-bottom:2px solid #1a237e;padding-bottom:6px;margin-top:24px;">
      Threat Type Breakdown
    </h2>
    <table style="width:100%;border-collapse:collapse;font-size:14px;">
      <thead>
        <tr style="background:#f0f0f0;">
          <th style="padding:8px 12px;text-align:left;">Type</th>
          <th style="padding:8px 12px;text-align:right;">Count</th>
        </tr>
      </thead>
      <tbody>{breakdown_rows}</tbody>
    </table>

    <!-- Bandwidth -->
    <h2 style="font-size:16px;color:#1a237e;border-bottom:2px solid #1a237e;padding-bottom:6px;margin-top:24px;">
      Bandwidth
    </h2>
    <p style="font-size:14px;">{bandwidth_mb:.2} MB processed this week</p>

    <!-- System Health -->
    <h2 style="font-size:16px;color:#1a237e;border-bottom:2px solid #1a237e;padding-bottom:6px;margin-top:24px;">
      System Health
    </h2>
    <table style="width:100%;border-collapse:collapse;font-size:14px;">
      <tr>
        <td style="padding:6px 12px;">CPU</td>
        <td style="padding:6px 12px;text-align:right;">{cpu:.1}%</td>
      </tr>
      <tr>
        <td style="padding:6px 12px;">Memory</td>
        <td style="padding:6px 12px;text-align:right;">{mem:.1}%</td>
      </tr>
      <tr>
        <td style="padding:6px 12px;">Disk</td>
        <td style="padding:6px 12px;text-align:right;">{disk:.1}%</td>
      </tr>
    </table>

  </div>

  <!-- Footer -->
  <div style="background:#f0f0f0;padding:16px 32px;font-size:12px;color:#888;text-align:center;">
    NetGuardia &mdash; Automated Weekly Report
  </div>

</div>
</body>
</html>"#
    );

    Ok(html)
}
