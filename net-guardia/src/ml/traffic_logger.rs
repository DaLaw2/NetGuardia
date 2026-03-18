use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::thread;

use crossbeam::channel::{bounded, Sender, TrySendError};

pub struct TrafficLogger {
    sender: Sender<Vec<String>>,
}

impl TrafficLogger {
    pub fn new(csv_path: &str, header: Vec<String>) -> Result<Self, std::io::Error> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(csv_path)?;

        let mut writer = BufWriter::new(file);
        writeln!(writer, "{}", header.join(","))?;
        writer.flush()?;

        let (sender, receiver) = bounded::<Vec<String>>(65536);

        thread::Builder::new()
            .name("traffic-logger".to_string())
            .spawn(move || {
                for record in receiver {
                    if let Err(e) = writeln!(writer, "{}", record.join(",")) {
                        eprintln!("[traffic-logger] write error: {}", e);
                    }
                }
                let _ = writer.flush();
            })?;

        Ok(Self { sender })
    }

    pub fn log_row(&self, record: Vec<String>) {
        match self.sender.try_send(record) {
            Ok(_) => {}
            Err(TrySendError::Full(_)) => {}
            Err(TrySendError::Disconnected(_)) => {}
        }
    }
}
