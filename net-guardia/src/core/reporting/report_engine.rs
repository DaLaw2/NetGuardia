use std::path::PathBuf;

use macros::log;

use super::html::escape;
use super::report_data_builder::build_report_data;
use crate::common::error::Error;
use crate::common::error::codec::CodecError;
use crate::common::log::reporting::ReportingLog;
use crate::domain::report::data::ReportData;
use crate::interface::reporting::html_report_writer::HtmlReportWriter;
use crate::interface::reporting::report_snapshot::ReportSnapshotRepo;

pub async fn generate_html_report(
    db: &dyn ReportSnapshotRepo,
    writer: &dyn HtmlReportWriter,
    output_dir: &str,
) -> Result<PathBuf, Error> {
    let data = build_report_data(db).await?;
    let html = render_html_report(&data);

    let html_path = writer.write_html_report(output_dir, &html)?;

    log!(ReportingLog::HtmlReportGenerated(format!("{html_path:?}")));

    Ok(html_path)
}

fn render_html_report(data: &ReportData) -> String {
    let mut breakdown_rows = String::new();
    for item in &data.threat_breakdown {
        breakdown_rows.push_str(&format!(
            "<tr><td>{}</td><td class=\"num\">{}</td><td>{}</td></tr>",
            escape(&item.threat_type),
            item.count,
            escape(&item.trend)
        ));
    }
    if data.threat_breakdown.is_empty() {
        breakdown_rows
            .push_str("<tr><td colspan=\"3\" class=\"empty\">No threat data available for this period</td></tr>");
    }

    let mut ip_rows = String::new();
    for ip in &data.top_blocked_ips {
        ip_rows.push_str(&format!(
            "<tr><td><code>{}</code></td><td class=\"num\">{}</td><td>{}</td></tr>",
            escape(&ip.ip),
            ip.count,
            escape(&ip.country)
        ));
    }
    if data.top_blocked_ips.is_empty() {
        ip_rows.push_str("<tr><td colspan=\"3\" class=\"empty\">No blocked IPs for this period</td></tr>");
    }

    let mut geo_rows = String::new();
    for geo in &data.geo_distribution {
        geo_rows.push_str(&format!(
            "<tr><td>{}</td><td class=\"num\">{}</td></tr>",
            escape(&geo.country),
            geo.threat_count
        ));
    }
    if data.geo_distribution.is_empty() {
        geo_rows.push_str("<tr><td colspan=\"2\" class=\"empty\">No geographic data available</td></tr>");
    }

    let mut rec_items = String::new();
    for rec in &data.recommendations {
        rec_items.push_str(&format!("<li>{}</li>", escape(rec)));
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetGuardia Security Report — {period}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; background: #f4f6f9; color: #1a1a2e; line-height: 1.5; }}
  .container {{ max-width: 900px; margin: 24px auto; background: #fff; border-radius: 10px; box-shadow: 0 2px 12px rgba(0,0,0,0.08); overflow: hidden; }}
  .header {{ background: linear-gradient(135deg, #1a237e, #283593); color: #fff; padding: 32px 40px; }}
  .header h1 {{ font-size: 24px; margin-bottom: 4px; }}
  .header .meta {{ font-size: 13px; opacity: 0.85; }}
  .content {{ padding: 32px 40px; }}
  h2 {{ font-size: 17px; color: #1a237e; border-bottom: 2px solid #1a237e; padding-bottom: 6px; margin: 28px 0 14px; }}
  h2:first-child {{ margin-top: 0; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 8px; }}
  .summary-card {{ background: #f8f9fc; border-radius: 8px; padding: 16px; text-align: center; }}
  .summary-card .value {{ font-size: 28px; font-weight: 700; color: #1a237e; }}
  .summary-card .label {{ font-size: 12px; color: #666; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 14px; margin-bottom: 8px; }}
  th {{ background: #f0f0f5; text-align: left; padding: 10px 14px; font-weight: 600; }}
  td {{ padding: 8px 14px; border-bottom: 1px solid #e8e8e8; }}
  td.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  td.empty {{ text-align: center; color: #999; font-style: italic; padding: 20px; }}
  code {{ background: #f0f0f5; padding: 2px 6px; border-radius: 4px; font-size: 13px; }}
  ul {{ padding-left: 20px; }}
  li {{ margin-bottom: 6px; }}
  .footer {{ background: #f0f0f5; padding: 18px 40px; font-size: 12px; color: #888; text-align: center; }}
  @media print {{ body {{ background: #fff; }} .container {{ box-shadow: none; margin: 0; }} }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>NetGuardia Security Report</h1>
    <div class="meta">Report Period: {period} &mdash; Generated: {generated_at}</div>
  </div>
  <div class="content">

    <h2>Executive Summary</h2>
    <div class="summary-grid">
      <div class="summary-card"><div class="value">{total_threats}</div><div class="label">Total Threats</div></div>
      <div class="summary-card"><div class="value">{total_blocked}</div><div class="label">Total Blocked</div></div>
      <div class="summary-card"><div class="value">{uptime:.1}%</div><div class="label">Uptime</div></div>
      <div class="summary-card"><div class="value">{active_rules}</div><div class="label">Active Rules</div></div>
    </div>

    <h2>Threat Breakdown</h2>
    <table>
      <thead><tr><th>Threat Type</th><th style="text-align:right">Count</th><th>Trend</th></tr></thead>
      <tbody>{breakdown_rows}</tbody>
    </table>

    <h2>Top Blocked IPs</h2>
    <table>
      <thead><tr><th>IP Address</th><th style="text-align:right">Block Count</th><th>Country</th></tr></thead>
      <tbody>{ip_rows}</tbody>
    </table>

    <h2>Geographic Distribution</h2>
    <table>
      <thead><tr><th>Country</th><th style="text-align:right">Threat Count</th></tr></thead>
      <tbody>{geo_rows}</tbody>
    </table>

    <h2>SOAR Activity</h2>
    <table>
      <thead><tr><th>Auto-Blocks</th><th>Playbooks Triggered</th><th>Auto-Unblocks</th></tr></thead>
      <tbody><tr><td class="num">{auto_blocks}</td><td class="num">{playbooks_triggered}</td><td class="num">{auto_unblocks}</td></tr></tbody>
    </table>

    <h2>System Health</h2>
    <table>
      <thead><tr><th>Metric</th><th style="text-align:right">Value</th></tr></thead>
      <tbody>
        <tr><td>Avg CPU</td><td class="num">{avg_cpu:.1}%</td></tr>
        <tr><td>Avg Memory</td><td class="num">{avg_mem:.1}%</td></tr>
        <tr><td>Disk Usage</td><td class="num">{disk:.1}%</td></tr>
        <tr><td>eBPF Status</td><td>{ebpf_status}</td></tr>
      </tbody>
    </table>

    <h2>Recommendations</h2>
    <ul>{rec_items}</ul>

  </div>
  <div class="footer">Generated by NetGuardia &mdash; Network Security Platform</div>
</div>
</body>
</html>"#,
        period = escape(&data.period),
        generated_at = escape(&data.generated_at),
        total_threats = data.executive_summary.total_threats,
        total_blocked = data.executive_summary.total_blocked,
        uptime = data.executive_summary.uptime_percent,
        active_rules = data.executive_summary.active_rules,
        breakdown_rows = breakdown_rows,
        ip_rows = ip_rows,
        geo_rows = geo_rows,
        auto_blocks = data.soar_activity.auto_blocks_executed,
        playbooks_triggered = data.soar_activity.playbooks_triggered,
        auto_unblocks = data.soar_activity.auto_unblocks,
        avg_cpu = data.system_health.avg_cpu_percent,
        avg_mem = data.system_health.avg_memory_percent,
        disk = data.system_health.disk_usage_percent,
        ebpf_status = escape(&data.system_health.ebpf_status),
        rec_items = rec_items,
    )
}

pub async fn generate_report_json(db: &dyn ReportSnapshotRepo) -> Result<serde_json::Value, Error> {
    let data = build_report_data(db).await?;
    let json = serde_json::to_value(&data).map_err(CodecError::SerializeFailed)?;
    Ok(json)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use parking_lot::Mutex;

    use super::*;

    struct FakeSnapshots {
        values: HashMap<String, String>,
    }

    #[async_trait::async_trait]
    impl ReportSnapshotRepo for FakeSnapshots {
        async fn get_report_snapshot(&self, key: &str) -> Result<Option<String>, Error> {
            Ok(self.values.get(key).cloned())
        }

        async fn set_report_snapshot(&self, _key: &str, _value: &str) -> Result<(), Error> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct CaptureWriter {
        calls: Mutex<Vec<(String, String)>>,
    }

    impl HtmlReportWriter for CaptureWriter {
        fn write_html_report(&self, output_dir: &str, html: &str) -> Result<PathBuf, Error> {
            self.calls.lock().push((output_dir.to_string(), html.to_string()));
            Ok(PathBuf::from(output_dir).join("adapter-owned-report.html"))
        }
    }

    #[tokio::test]
    async fn html_report_delegates_file_write_to_port() {
        let mut values = HashMap::new();
        values.insert(
            "weekly_top_ips".to_string(),
            r#"[{"ip":"<script>alert(1)</script>","count":7,"country":"N/A"}]"#.to_string(),
        );
        let repo = FakeSnapshots { values };
        let writer = CaptureWriter::default();

        let path = generate_html_report(&repo, &writer, "/tmp/netguardia-reports")
            .await
            .expect("generate report");

        let calls = writer.calls.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "/tmp/netguardia-reports");
        assert_eq!(path, PathBuf::from("/tmp/netguardia-reports/adapter-owned-report.html"));
        assert!(!calls[0].1.contains("<script>alert(1)</script>"));
        assert!(calls[0].1.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }
}
