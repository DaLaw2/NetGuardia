/// Alert notification data sent by SOAR engine.
#[derive(Debug, Clone)]
pub struct AlertPayload {
    pub source_ip: String,
    pub dest_ip: String,
    pub country: Option<String>,
    pub threat_type: String,
    pub confidence: f32,
    pub action_description: String,
    pub timestamp: String,
}
