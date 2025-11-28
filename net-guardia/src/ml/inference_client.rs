use super::features::CicFeatures;
use super::flow_record::FlowRecord;
use futures_util::{SinkExt, StreamExt};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::Message};

/// Detection request message
#[derive(Debug, Clone, Serialize)]
struct DetectionRequest {
    #[serde(rename = "type")]
    msg_type: String,
    flow_id: String,
    timestamp: u64,
    features: Vec<f64>,
}

/// Batch detection request
#[derive(Debug, Clone, Serialize)]
struct BatchDetectionRequest {
    #[serde(rename = "type")]
    msg_type: String,
    flows: Vec<DetectionRequest>,
}

/// Detection result message
#[derive(Debug, Clone, Deserialize)]
pub struct DetectionResult {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub flow_id: String,
    pub is_anomaly: bool,
    pub mse: f64,
    pub threshold: f64,
    #[serde(default)]
    pub attack_type: Option<String>,
    #[serde(default)]
    pub confidence: Option<f64>,
    #[serde(default)]
    pub attack_probabilities: Option<HashMap<String, f64>>,
    pub processing_time_ms: f64,
}

/// Batch detection result
#[derive(Debug, Clone, Deserialize)]
struct BatchDetectionResult {
    #[serde(rename = "type")]
    msg_type: String,
    results: Vec<DetectionResult>,
}

/// Error response
#[derive(Debug, Clone, Deserialize)]
struct ErrorResponse {
    #[serde(rename = "type")]
    msg_type: String,
    #[serde(default)]
    flow_id: Option<String>,
    error: String,
    code: String,
}

/// WebSocket inference client
pub struct InferenceClient {
    /// WebSocket URL
    ws_url: String,

    /// Send channel for requests
    tx: mpsc::UnboundedSender<Message>,

    /// Pending requests (flow_id -> callback)
    pending: Arc<RwLock<HashMap<String, tokio::sync::oneshot::Sender<DetectionResult>>>>,

    /// Callback for detection results
    result_callback: Arc<RwLock<Option<Arc<dyn Fn(DetectionResult) + Send + Sync>>>>,

    /// Connection status
    connected: Arc<RwLock<bool>>,
}

impl InferenceClient {
    /// Create a new inference client
    pub async fn new(ws_url: String) -> Result<Self, Box<dyn std::error::Error>> {
        // Connect to WebSocket (use String directly, not Url)
        let (ws_stream, _) = connect_async(&ws_url).await?;
        tracing::info!("Connected to inference service: {}", ws_url);

        let (mut write, mut read) = ws_stream.split();

        // Create channels
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

        let pending: Arc<RwLock<HashMap<String, tokio::sync::oneshot::Sender<DetectionResult>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let pending_write = pending.clone();
        let pending_read = pending.clone();

        let result_callback: Arc<RwLock<Option<Arc<dyn Fn(DetectionResult) + Send + Sync>>>> =
            Arc::new(RwLock::new(None));
        let callback_clone = result_callback.clone();

        let connected = Arc::new(RwLock::new(true));
        let connected_write = connected.clone();
        let connected_read = connected.clone();

        // Spawn write task
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if let Err(e) = write.send(msg).await {
                    tracing::error!("WebSocket write error: {}", e);
                    *connected_write.write() = false;
                    break;
                }
            }
        });

        // Spawn read task
        tokio::spawn(async move {
            while let Some(result) = read.next().await {
                match result {
                    Ok(Message::Text(text)) => {
                        if let Err(e) = Self::handle_message(&text, &pending_read, &callback_clone)
                        {
                            tracing::error!("Failed to handle message: {}", e);
                        }
                    }
                    Ok(Message::Close(_)) => {
                        tracing::warn!("WebSocket closed by server");
                        *connected_read.write() = false;
                        break;
                    }
                    Err(e) => {
                        tracing::error!("WebSocket read error: {}", e);
                        *connected_read.write() = false;
                        break;
                    }
                    _ => {}
                }
            }
        });

        Ok(Self {
            ws_url,
            tx,
            pending,
            result_callback,
            connected,
        })
    }

    /// Handle incoming message
    fn handle_message(
        text: &str,
        pending: &Arc<
            RwLock<HashMap<String, tokio::sync::oneshot::Sender<DetectionResult>>>,
        >,
        callback: &Arc<RwLock<Option<Arc<dyn Fn(DetectionResult) + Send + Sync>>>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Try to parse as detection result
        if let Ok(result) = serde_json::from_str::<DetectionResult>(text) {
            let flow_id = result.flow_id.clone();

            // Check if there's a pending request
            if let Some(tx) = pending.write().remove(&flow_id) {
                let _ = tx.send(result.clone());
            }

            // Call result callback
            if let Some(cb) = callback.read().as_ref() {
                cb(result);
            }

            return Ok(());
        }

        // Try to parse as batch result
        if let Ok(batch) = serde_json::from_str::<BatchDetectionResult>(text) {
            for result in batch.results {
                let flow_id = result.flow_id.clone();

                if let Some(tx) = pending.write().remove(&flow_id) {
                    let _ = tx.send(result.clone());
                }

                if let Some(cb) = callback.read().as_ref() {
                    cb(result);
                }
            }
            return Ok(());
        }

        // Try to parse as error
        if let Ok(error) = serde_json::from_str::<ErrorResponse>(text) {
            tracing::error!("Inference error: {} ({})", error.error, error.code);
            return Ok(());
        }

        // Pong message
        if text.contains("\"type\":\"pong\"") {
            return Ok(());
        }

        tracing::warn!("Unknown message type: {}", text);
        Ok(())
    }

    /// Send detection request
    pub async fn detect(
        &self,
        flow: &FlowRecord,
        features: &CicFeatures,
    ) -> Result<DetectionResult, Box<dyn std::error::Error>> {
        if !*self.connected.read() {
            return Err("WebSocket not connected".into());
        }

        let request = DetectionRequest {
            msg_type: "detect".to_string(),
            flow_id: flow.flow_id.clone(),
            timestamp: flow.last_seen,
            features: features.to_vec(),
        };

        let json = serde_json::to_string(&request)?;

        // Create oneshot channel for response
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending.write().insert(flow.flow_id.clone(), tx);

        // Send request
        self.tx.send(Message::Text(json.into()))?;

        // Wait for response with timeout
        let result = tokio::time::timeout(Duration::from_secs(10), rx).await??;

        Ok(result)
    }

    /// Send batch detection request (fire-and-forget)
    pub fn detect_batch(&self, flows: Vec<(FlowRecord, CicFeatures)>) -> Result<(), Box<dyn std::error::Error>> {
        if !*self.connected.read() {
            return Err("WebSocket not connected".into());
        }

        let requests: Vec<DetectionRequest> = flows
            .iter()
            .map(|(flow, features)| DetectionRequest {
                msg_type: "detect".to_string(),
                flow_id: flow.flow_id.clone(),
                timestamp: flow.last_seen,
                features: features.to_vec(),
            })
            .collect();

        let batch = BatchDetectionRequest {
            msg_type: "batch_detect".to_string(),
            flows: requests,
        };

        let json = serde_json::to_string(&batch)?;
        self.tx.send(Message::Text(json.into()))?;

        Ok(())
    }

    /// Set result callback (called for all results, including batch)
    pub fn on_result<F>(&self, callback: F)
    where
        F: Fn(DetectionResult) + Send + Sync + 'static,
    {
        *self.result_callback.write() = Some(Arc::new(callback));
    }

    /// Send ping
    pub fn ping(&self) -> Result<(), Box<dyn std::error::Error>> {
        let ping = serde_json::json!({"type": "ping"});
        self.tx
            .send(Message::Text(ping.to_string().into()))
            .map_err(|e| e.into())
    }

    /// Start periodic ping task
    pub fn start_ping_task(
        self: Arc<Self>,
        interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                if let Err(e) = self.ping() {
                    tracing::error!("Failed to send ping: {}", e);
                }
            }
        })
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        *self.connected.read()
    }

    /// Reconnect (placeholder for auto-reconnection logic)
    pub async fn reconnect(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        tracing::info!("Reconnecting to inference service...");
        let new_client = Self::new(self.ws_url.clone()).await?;

        // Copy state (clone Arc references)
        self.tx = new_client.tx.clone();
        self.pending = new_client.pending.clone();
        self.connected = new_client.connected.clone();

        Ok(())
    }
}

impl Drop for InferenceClient {
    fn drop(&mut self) {
        tracing::info!("Closing inference client connection");
    }
}