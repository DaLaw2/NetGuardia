use std::fs;
use std::io;
use std::io::Write as _;
use std::path::PathBuf;

use chrono::Local;

use crate::common::error::Error;
use crate::common::error::io::IOError;
use crate::interface::reporting::html_report_writer::HtmlReportWriter;

const REPORT_CREATE_ATTEMPTS: u32 = 100;

#[derive(Default)]
pub struct FsHtmlReportWriter;

impl HtmlReportWriter for FsHtmlReportWriter {
    fn write_html_report(&self, output_dir: &str, html: &str) -> Result<PathBuf, Error> {
        let timestamp = Local::now().format("%Y%m%d-%H%M%S").to_string();
        write_html_report_at(&PathBuf::from(output_dir), &timestamp, html)
    }
}

fn write_html_report_at(output_dir: &PathBuf, timestamp: &str, html: &str) -> Result<PathBuf, Error> {
    fs::create_dir_all(output_dir).map_err(|e| IOError::CreateDirectoryFailed(output_dir.clone(), e))?;

    for attempt in 0..REPORT_CREATE_ATTEMPTS {
        let html_path = output_dir.join(report_file_name(timestamp, attempt));
        let mut file = match fs::OpenOptions::new().create_new(true).write(true).open(&html_path) {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => Err(IOError::WriteFileFailed(html_path.clone(), err))?,
        };
        file.write_all(html.as_bytes())
            .and_then(|()| file.flush())
            .map_err(|err| IOError::WriteFileFailed(html_path.clone(), err))?;
        return Ok(html_path);
    }

    Err(IOError::WriteFileFailed(
        output_dir.join(report_file_name(timestamp, 0)),
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "HTML report filename collision budget exhausted",
        ),
    ))?
}

fn report_file_name(timestamp: &str, attempt: u32) -> String {
    if attempt == 0 {
        format!("netguardia-report-{timestamp}.html")
    } else {
        format!("netguardia-report-{timestamp}-{attempt:02}.html")
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn scratch_dir(tag: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "nguardia-html-report-{tag}-{}",
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ))
    }

    #[test]
    fn html_report_writer_does_not_overwrite_same_second_report() {
        let dir = scratch_dir("collision");
        let first = write_html_report_at(&dir, "20260507-120000", "<h1>first</h1>").unwrap();
        let second = write_html_report_at(&dir, "20260507-120000", "<h1>second</h1>").unwrap();

        assert_ne!(first, second);
        assert_eq!(fs::read_to_string(first).unwrap(), "<h1>first</h1>");
        assert_eq!(fs::read_to_string(second).unwrap(), "<h1>second</h1>");
        fs::remove_dir_all(dir).ok();
    }
}
