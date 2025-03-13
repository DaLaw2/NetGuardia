use crate::core::config_manager::ConfigManager;
use crate::model::alert::Alert;
use crate::utils::log_entry::system::SystemEntry;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::fs::OpenOptions;
use tokio::io::AsyncReadExt;
use tokio::select;
use tokio::sync::mpsc::unbounded_channel;
use tokio::sync::{broadcast, mpsc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use tokio::time::sleep;
use tracing::error;

static AI_INSTANCE: OnceLock<RwLock<AI>> = OnceLock::new();

pub struct AI {
    #[allow(dead_code)]
    broadcast_tx: broadcast::Sender<Alert>,
    #[allow(dead_code)]
    broadcast_rx: broadcast::Receiver<Alert>,
    shutdown: mpsc::UnboundedSender<()>,
}

impl AI {
    pub async fn initialize() {
        let (broadcast_tx, broadcast_rx) = broadcast::channel(20);
        let (tx, rx) = unbounded_channel();
        let ai = AI {
            broadcast_tx: broadcast_tx.clone(),
            broadcast_rx,
            shutdown: tx,
        };
        AI_INSTANCE.get_or_init(|| RwLock::new(ai));
        tokio::spawn(async move { AI::run(broadcast_tx, rx).await });
    }

    pub async fn instance() -> RwLockReadGuard<'static, AI> {
        let instance = AI_INSTANCE.get().unwrap();
        instance.read().await
    }

    pub async fn instance_mut() -> RwLockWriteGuard<'static, AI> {
        let instance = AI_INSTANCE.get().unwrap();
        instance.write().await
    }

    pub async fn run(
        broadcast: broadcast::Sender<Alert>,
        mut shutdown: mpsc::UnboundedReceiver<()>,
    ) {
        let config = ConfigManager::now().await;
        let alert_path = config.alert_path.clone();
        let refresh_interval = Duration::from_secs(config.refresh_interval);

        loop {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&alert_path)
                .await;
            if let Ok(mut file) = file {
                let mut contents = String::new();
                if file.read_to_string(&mut contents).await.is_ok() {
                    for line in contents.lines() {
                        if let Some(alert) = Self::parse_alert(line) {
                            let _ = broadcast.send(alert);
                        } else {
                            error!("{}", SystemEntry::InvalidAlert(line.to_string()))
                        }
                    }
                }
                if file.set_len(0).await.is_err() {
                    error!("{}", SystemEntry::ClearAlertFailed);
                }
            }
            select! {
                _ = shutdown.recv() => break,
                _ = sleep(refresh_interval) => {}
            }
        }
    }

    pub async fn terminate() {
        let instance = Self::instance_mut().await;
        let _ = instance.shutdown.send(());
    }

    pub async fn subscribe() -> broadcast::Receiver<Alert> {
        let instance = AI::instance().await;
        instance.broadcast_tx.subscribe()
    }

    fn parse_ip_address(ip_port_str: &str) -> Option<(String, u16)> {
        if ip_port_str.matches(':').count() == 1 {
            let parts: Vec<&str> = ip_port_str.split(':').collect();
            if parts.len() == 2 {
                return Some((parts[0].to_string(), parts[1].parse::<u16>().ok()?));
            }
        } else {
            let last_colon_pos = ip_port_str.rfind(':')?;
            let ip = &ip_port_str[0..last_colon_pos];
            let port = &ip_port_str[last_colon_pos + 1..];
            return Some((ip.to_string(), port.parse::<u16>().ok()?));
        }
        None
    }

    fn parse_alert(line: &str) -> Option<Alert> {
        let parts: Vec<&str> = line.split(" [**] ").collect();
        if parts.len() < 3 {
            return None;
        }

        let timestamp = parts[0].trim();

        let sig_msg: Vec<&str> = parts[1].split("] ").collect();
        if sig_msg.len() < 2 {
            return None;
        }
        let signature_id = sig_msg[0].trim_start_matches('[');
        let message = sig_msg[1].trim();

        let remaining = parts[2];

        let class_start = remaining.find("[Classification: ");
        let class_end = remaining.find("] [Priority:");
        if class_start.is_none() || class_end.is_none() {
            return None;
        }
        let classification = remaining[class_start.unwrap() + 16..class_end.unwrap()].trim();

        let prio_start = remaining.find("[Priority: ");
        let prio_end = remaining.find("] {");
        if prio_start.is_none() || prio_end.is_none() {
            return None;
        }
        let priority = remaining[prio_start.unwrap() + 11..prio_end.unwrap()]
            .trim()
            .parse::<u32>()
            .ok()?;

        let proto_start = remaining.find("{");
        let proto_end = remaining.find("}");
        if proto_start.is_none() || proto_end.is_none() {
            return None;
        }
        let protocol = remaining[proto_start.unwrap() + 1..proto_end.unwrap()].trim();

        let ip_info_start = remaining.find("} ");
        if ip_info_start.is_none() {
            return None;
        }
        let ip_info = &remaining[ip_info_start.unwrap() + 2..];

        let ip_parts: Vec<&str> = ip_info.split(" -> ").collect();
        if ip_parts.len() < 2 {
            return None;
        }

        let (source_ip, source_port) = Self::parse_ip_address(ip_parts[0])?;
        let (destination_ip, destination_port) = Self::parse_ip_address(ip_parts[1])?;

        Some(Alert {
            timestamp: timestamp.to_string(),
            signature_id: signature_id.to_string(),
            message: message.to_string(),
            classification: classification.to_string(),
            priority,
            protocol: protocol.to_string(),
            source_ip,
            source_port,
            destination_ip,
            destination_port,
        })
    }
}
