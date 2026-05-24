use std::path::PathBuf;

use crate::common::error::Error;

pub trait HtmlReportWriter: Send + Sync {
    fn write_html_report(&self, output_dir: &str, html: &str) -> Result<PathBuf, Error>;
}
