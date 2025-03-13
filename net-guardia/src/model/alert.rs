use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    pub timestamp: String,
    pub signature_id: String,
    pub message: String,
    pub classification: String,
    pub priority: u32,
    pub protocol: String,
    pub source_ip: String,
    pub source_port: u16,
    pub destination_ip: String,
    pub destination_port: u16,
}
