use super::html::escape;
use super::report_data_builder::build_report_data;
use crate::common::error::Error;
use crate::domain::report::data::ReportData;
use crate::interface::reporting::report_snapshot::ReportSnapshotRepo;

pub async fn generate_weekly_report(db: &dyn ReportSnapshotRepo) -> Result<String, Error> {
    let data = build_report_data(db).await?;
    Ok(render_weekly_email(&data))
}

fn render_weekly_email(data: &ReportData) -> String {
    let mut top_ips_rows = String::new();
    for (i, entry) in data.top_blocked_ips.iter().enumerate().take(5) {
        top_ips_rows.push_str(&format!(
            "<tr><td style=\"padding:6px 12px;border-bottom:1px solid #e0e0e0;\">{}</td>\
             <td style=\"padding:6px 12px;border-bottom:1px solid #e0e0e0;\">{}</td>\
             <td style=\"padding:6px 12px;border-bottom:1px solid #e0e0e0;text-align:right;\">{}</td></tr>",
            i + 1,
            escape(&entry.ip),
            entry.count,
        ));
    }

    let mut breakdown_rows = String::new();
    for item in &data.threat_breakdown {
        breakdown_rows.push_str(&format!(
            "<tr><td style=\"padding:6px 12px;border-bottom:1px solid #e0e0e0;\">{}</td>\
             <td style=\"padding:6px 12px;border-bottom:1px solid #e0e0e0;text-align:right;\">{}</td></tr>",
            escape(&item.threat_type),
            item.count,
        ));
    }

    format!(
        r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Arial,Helvetica,sans-serif;background:#f4f6f9;margin:0;padding:20px;">
<div style="max-width:640px;margin:0 auto;background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">

  <div style="background:#1a237e;color:#ffffff;padding:24px 32px;">
    <h1 style="margin:0;font-size:22px;">NetGuardia Weekly Report</h1>
    <p style="margin:6px 0 0;font-size:13px;opacity:0.85;">Report Period: {period} &mdash; Generated: {generated_at}</p>
  </div>

  <div style="padding:24px 32px;">
    <h2 style="font-size:16px;color:#1a237e;border-bottom:2px solid #1a237e;padding-bottom:6px;">
      Threat Summary
    </h2>
    <p style="font-size:28px;font-weight:bold;margin:8px 0;">{threats_count}
      <span style="font-size:14px;font-weight:normal;color:#666;"> threats detected this week</span>
    </p>

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

    <h2 style="font-size:16px;color:#1a237e;border-bottom:2px solid #1a237e;padding-bottom:6px;margin-top:24px;">
      System Health
    </h2>
    <table style="width:100%;border-collapse:collapse;font-size:14px;">
      <tr><td style="padding:6px 12px;">CPU</td><td style="padding:6px 12px;text-align:right;">{cpu:.1}%</td></tr>
      <tr><td style="padding:6px 12px;">Memory</td><td style="padding:6px 12px;text-align:right;">{mem:.1}%</td></tr>
      <tr><td style="padding:6px 12px;">Disk</td><td style="padding:6px 12px;text-align:right;">{disk:.1}%</td></tr>
    </table>
  </div>

  <div style="background:#f0f0f0;padding:16px 32px;font-size:12px;color:#888;text-align:center;">
    NetGuardia &mdash; Automated Weekly Report
  </div>

</div>
</body>
</html>"#,
        period = escape(&data.period),
        generated_at = escape(&data.generated_at),
        threats_count = data.executive_summary.total_threats,
        top_ips_rows = top_ips_rows,
        breakdown_rows = breakdown_rows,
        cpu = data.system_health.avg_cpu_percent,
        mem = data.system_health.avg_memory_percent,
        disk = data.system_health.disk_usage_percent,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    struct FakeSettings {
        values: HashMap<String, String>,
    }

    #[async_trait::async_trait]
    impl ReportSnapshotRepo for FakeSettings {
        async fn get_report_snapshot(&self, key: &str) -> Result<Option<String>, Error> {
            Ok(self.values.get(key).cloned())
        }

        async fn set_report_snapshot(&self, _key: &str, _value: &str) -> Result<(), Error> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn weekly_report_escapes_snapshot_derived_html() {
        let mut values = HashMap::new();
        values.insert(
            "weekly_top_ips".to_string(),
            r#"[{"ip":"<img src=x onerror=alert(1)>","count":3,"country":"N/A"}]"#.to_string(),
        );
        values.insert(
            "weekly_threat_breakdown".to_string(),
            r#"{"\"><script>alert(1)</script>":2}"#.to_string(),
        );
        let repo = FakeSettings { values };

        let html = generate_weekly_report(&repo).await.unwrap();

        assert!(!html.contains("<img src=x onerror=alert(1)>"));
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assert!(html.contains("&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"));
    }
}
