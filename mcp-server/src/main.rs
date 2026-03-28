use std::io::{self, BufRead, Write};
use std::time::Duration;

use clap::Parser;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// NetGuardia MCP Server — thin proxy to the NetGuardia HTTP API.
/// Communicates via stdin/stdout using the MCP JSON-RPC protocol.
#[derive(Parser)]
#[command(name = "netguardia-mcp", about = "NetGuardia MCP Server")]
struct Args {
    /// NetGuardia API base URL
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    api_url: String,

    /// API key for authentication (prefer NETGUARDIA_MCP_KEY env var)
    #[arg(long)]
    api_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

struct McpServer {
    client: Client,
    api_url: String,
    api_key: String,
}

impl McpServer {
    fn new(api_url: String, api_key: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");
        Self { client, api_url, api_key }
    }

    async fn handle_request(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        match req.method.as_str() {
            "initialize" => self.handle_initialize(req.id),
            "tools/list" => self.handle_tools_list(req.id),
            "tools/call" => self.handle_tool_call(req.id, req.params).await,
            _ => JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id: req.id,
                result: None,
                error: Some(JsonRpcError { code: -32601, message: "Method not found".into() }),
            },
        }
    }

    fn handle_initialize(&self, id: Option<Value>) -> JsonRpcResponse {
        JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id,
            result: Some(serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": {
                    "name": "netguardia-mcp",
                    "version": "0.1.0"
                }
            })),
            error: None,
        }
    }

    fn handle_tools_list(&self, id: Option<Value>) -> JsonRpcResponse {
        let tools = serde_json::json!({
            "tools": [
                { "name": "get_health", "description": "System health status (CPU, memory, uptime, eBPF status)", "inputSchema": { "type": "object", "properties": {} } },
                { "name": "get_stats", "description": "Traffic statistics summary", "inputSchema": { "type": "object", "properties": {} } },
                { "name": "list_alerts", "description": "Recent threat alerts with details", "inputSchema": { "type": "object", "properties": { "limit": { "type": "integer", "default": 20 } } } },
                { "name": "list_blocked_ips", "description": "Currently blocked IPs (manual + auto)", "inputSchema": { "type": "object", "properties": {} } },
                { "name": "get_geo_stats", "description": "GeoIP traffic breakdown", "inputSchema": { "type": "object", "properties": {} } },
                { "name": "get_flow_summary", "description": "Top talkers, protocols, ports", "inputSchema": { "type": "object", "properties": {} } },
                { "name": "get_enforce_mode", "description": "Current mode (monitor/enforce)", "inputSchema": { "type": "object", "properties": {} } },
                { "name": "list_playbooks", "description": "SOAR playbook configurations", "inputSchema": { "type": "object", "properties": {} } },
                { "name": "generate_report", "description": "Generate security summary report", "inputSchema": { "type": "object", "properties": {} } },
                { "name": "block_ip", "description": "Add IP to blacklist", "inputSchema": { "type": "object", "properties": { "ip": { "type": "string" }, "ttl_secs": { "type": "integer", "default": 1800 } }, "required": ["ip"] } },
                { "name": "unblock_ip", "description": "Remove IP from blacklist", "inputSchema": { "type": "object", "properties": { "ip": { "type": "string" } }, "required": ["ip"] } },
                { "name": "set_enforce_mode", "description": "Toggle monitor/enforce mode", "inputSchema": { "type": "object", "properties": { "mode": { "type": "string", "enum": ["monitor", "enforce"] } }, "required": ["mode"] } },
                { "name": "add_dns_filter", "description": "Add domain to DNS blacklist", "inputSchema": { "type": "object", "properties": { "domain": { "type": "string" } }, "required": ["domain"] } },
                { "name": "add_geo_block", "description": "Block country by code", "inputSchema": { "type": "object", "properties": { "country_code": { "type": "string" } }, "required": ["country_code"] } },
            ]
        });

        JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id,
            result: Some(tools),
            error: None,
        }
    }

    async fn handle_tool_call(&self, id: Option<Value>, params: Value) -> JsonRpcResponse {
        let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let arguments = params.get("arguments").cloned().unwrap_or(Value::Object(Default::default()));

        let (method, path, body) = match tool_name {
            "get_health" => ("GET", "/api/health/status", None),
            "get_stats" => ("GET", "/api/stats/summary", None),
            "list_alerts" => ("GET", "/api/ml/alerts", None),
            "list_blocked_ips" => ("GET", "/api/soar/blocks", None),
            "get_geo_stats" => ("GET", "/api/stats/geo", None),
            "get_flow_summary" => ("GET", "/api/stats/flows", None),
            "get_enforce_mode" => ("GET", "/api/system/enforce-mode", None),
            "list_playbooks" => ("GET", "/api/soar/playbooks", None),
            "generate_report" => ("POST", "/api/report/generate", None),
            "block_ip" => {
                let ip = arguments.get("ip").and_then(|v| v.as_str()).unwrap_or("");
                let body = serde_json::json!({
                    "ip_version": if ip.contains(':') { 6 } else { 4 },
                    "direction": "source",
                    "list_type": "blacklist",
                    "ip_address": ip,
                    "port": 0
                });
                ("POST", "/api/acl/add", Some(body))
            }
            "unblock_ip" => {
                let ip = arguments.get("ip").and_then(|v| v.as_str()).unwrap_or("");
                let body = serde_json::json!({
                    "ip_version": if ip.contains(':') { 6 } else { 4 },
                    "direction": "source",
                    "list_type": "blacklist",
                    "ip_address": ip,
                    "port": 0
                });
                ("POST", "/api/acl/delete", Some(body))
            }
            "set_enforce_mode" => {
                let mode = arguments.get("mode").and_then(|v| v.as_str()).unwrap_or("monitor");
                let body = serde_json::json!({"mode": mode});
                ("POST", "/api/system/enforce-mode", Some(body))
            }
            "add_dns_filter" => {
                let domain = arguments.get("domain").and_then(|v| v.as_str()).unwrap_or("");
                let body = serde_json::json!({"domain": domain});
                ("POST", "/api/filter/dns/add", Some(body))
            }
            "add_geo_block" => {
                let code = arguments.get("country_code").and_then(|v| v.as_str()).unwrap_or("");
                let body = serde_json::json!({"codes": [code]});
                ("POST", "/api/acl/geo/block", Some(body))
            }
            _ => {
                return JsonRpcResponse {
                    jsonrpc: "2.0".into(),
                    id,
                    result: None,
                    error: Some(JsonRpcError { code: -32602, message: format!("Unknown tool: {}", tool_name) }),
                };
            }
        };

        let url = format!("{}{}", self.api_url, path);
        let mut req_builder = match method {
            "POST" => self.client.post(&url),
            _ => self.client.get(&url),
        };

        req_builder = req_builder.header("X-API-Key", &self.api_key);

        if let Some(body) = body {
            req_builder = req_builder.json(&body);
        }

        match req_builder.send().await {
            Ok(resp) => {
                let status = resp.status();
                let body: Value = resp.json().await.unwrap_or(Value::Null);

                if status.is_success() {
                    JsonRpcResponse {
                        jsonrpc: "2.0".into(),
                        id,
                        result: Some(serde_json::json!({
                            "content": [{ "type": "text", "text": serde_json::to_string_pretty(&body).unwrap_or_default() }]
                        })),
                        error: None,
                    }
                } else {
                    JsonRpcResponse {
                        jsonrpc: "2.0".into(),
                        id,
                        result: Some(serde_json::json!({
                            "content": [{ "type": "text", "text": format!("API error ({}): {}", status, serde_json::to_string(&body).unwrap_or_default()) }],
                            "isError": true
                        })),
                        error: None,
                    }
                }
            }
            Err(e) => {
                JsonRpcResponse {
                    jsonrpc: "2.0".into(),
                    id,
                    result: Some(serde_json::json!({
                        "content": [{ "type": "text", "text": format!("Connection error: {}", e) }],
                        "isError": true
                    })),
                    error: None,
                }
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let api_key = args.api_key
        .or_else(|| std::env::var("NETGUARDIA_MCP_KEY").ok())
        .unwrap_or_else(|| {
            eprintln!("Error: No API key provided. Set NETGUARDIA_MCP_KEY env var or use --api-key flag.");
            std::process::exit(1);
        });

    let server = McpServer::new(args.api_url, api_key);

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        if line.trim().is_empty() {
            continue;
        }

        let req: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let err_resp = JsonRpcResponse {
                    jsonrpc: "2.0".into(),
                    id: None,
                    result: None,
                    error: Some(JsonRpcError { code: -32700, message: format!("Parse error: {}", e) }),
                };
                let _ = writeln!(stdout, "{}", serde_json::to_string(&err_resp).unwrap());
                let _ = stdout.flush();
                continue;
            }
        };

        let resp = server.handle_request(req).await;
        let _ = writeln!(stdout, "{}", serde_json::to_string(&resp).unwrap());
        let _ = stdout.flush();
    }
}
