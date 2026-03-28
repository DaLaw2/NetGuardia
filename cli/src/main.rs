use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use reqwest::Client;
use serde_json::Value;

/// NetGuardia CLI management tool.
#[derive(Parser)]
#[command(name = "ng", about = "NetGuardia CLI", version)]
struct Cli {
    /// API base URL
    #[arg(long, default_value = "http://127.0.0.1:8080", global = true)]
    url: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// System health + enforce mode + uptime
    Status,
    /// Recent threat alerts
    Alerts {
        #[arg(long, default_value = "20")]
        limit: u32,
    },
    /// Add IP to blacklist
    Block {
        ip: String,
        #[arg(long, default_value = "1800")]
        ttl: u64,
    },
    /// Remove IP from blacklist
    Unblock { ip: String },
    /// List all ACL rules
    Rules,
    /// Generate security report
    Report {
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Get or set enforce mode
    Mode {
        /// Set mode to "monitor" or "enforce"
        mode: Option<String>,
    },
    /// Authenticate and save JWT
    Login,
    /// MCP API key management
    McpKey {
        #[command(subcommand)]
        action: McpKeyAction,
    },
}

#[derive(Subcommand)]
enum McpKeyAction {
    /// Generate a new MCP API key
    Generate {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long, default_value = "read_only")]
        level: String,
    },
    /// List all MCP API keys
    List,
    /// Revoke an MCP API key
    Revoke { id: i64 },
}

struct ApiClient {
    client: Client,
    base_url: String,
    token_path: PathBuf,
}

impl ApiClient {
    fn new(base_url: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to create HTTP client");

        let token_path = dirs_next().join("token");

        Self { client, base_url, token_path }
    }

    fn load_token(&self) -> Option<String> {
        std::fs::read_to_string(&self.token_path).ok()
    }

    fn save_token(&self, token: &str) {
        if let Some(parent) = self.token_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&self.token_path, token);
    }

    async fn get(&self, path: &str) -> Result<Value, String> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.client.get(&url);
        if let Some(token) = self.load_token() {
            req = req.header("Authorization", format!("Bearer {}", token.trim()));
        }
        let resp = req.send().await.map_err(|e| format!("Connection error: {}", e))?;
        if resp.status().as_u16() == 401 {
            return Err("Session expired. Run `ng login` to re-authenticate.".into());
        }
        resp.json().await.map_err(|e| format!("Parse error: {}", e))
    }

    async fn post(&self, path: &str, body: Value) -> Result<Value, String> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.client.post(&url).json(&body);
        if let Some(token) = self.load_token() {
            req = req.header("Authorization", format!("Bearer {}", token.trim()));
        }
        let resp = req.send().await.map_err(|e| format!("Connection error: {}", e))?;
        if resp.status().as_u16() == 401 {
            return Err("Session expired. Run `ng login` to re-authenticate.".into());
        }
        resp.json().await.map_err(|e| format!("Parse error: {}", e))
    }

    async fn delete(&self, path: &str) -> Result<Value, String> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.client.delete(&url);
        if let Some(token) = self.load_token() {
            req = req.header("Authorization", format!("Bearer {}", token.trim()));
        }
        let resp = req.send().await.map_err(|e| format!("Connection error: {}", e))?;
        if resp.status().as_u16() == 401 {
            return Err("Session expired. Run `ng login` to re-authenticate.".into());
        }
        resp.json().await.map_err(|e| format!("Parse error: {}", e))
    }

    async fn login(&self, username: &str, password: &str) -> Result<String, String> {
        let url = format!("{}/api/auth/login", self.base_url);
        let body = serde_json::json!({"username": username, "password": password});
        let resp = self.client.post(&url).json(&body).send().await
            .map_err(|e| format!("Connection error: {}", e))?;
        let data: Value = resp.json().await.map_err(|e| format!("Parse error: {}", e))?;
        data.get("token").and_then(|t| t.as_str()).map(|s| s.to_string())
            .ok_or_else(|| data.get("error").and_then(|e| e.as_str()).unwrap_or("Login failed").to_string())
    }
}

fn dirs_next() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".ng")
}

fn format_report_text(data: &Value) -> String {
    let mut out = String::new();
    out.push_str("=== NetGuardia Security Report ===\n\n");

    if let Some(obj) = data.as_object() {
        for (key, value) in obj {
            let label = key.replace('_', " ");
            match value {
                Value::String(s) => {
                    out.push_str(&format!("{}: {}\n", label, s));
                }
                Value::Number(n) => {
                    out.push_str(&format!("{}: {}\n", label, n));
                }
                Value::Bool(b) => {
                    out.push_str(&format!("{}: {}\n", label, b));
                }
                Value::Array(arr) => {
                    out.push_str(&format!("{}:\n", label));
                    for item in arr {
                        out.push_str(&format!("  - {}\n", item));
                    }
                }
                Value::Object(_) => {
                    out.push_str(&format!("{}:\n{}\n", label, serde_json::to_string_pretty(value).unwrap_or_default()));
                }
                Value::Null => {
                    out.push_str(&format!("{}: N/A\n", label));
                }
            }
        }
    } else {
        out.push_str(&serde_json::to_string_pretty(data).unwrap_or_default());
    }

    out
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let api = ApiClient::new(cli.url);

    let result = match cli.command {
        Commands::Status => {
            match api.get("/api/health/status").await {
                Ok(data) => {
                    println!("{}", serde_json::to_string_pretty(&data).unwrap_or_default());
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        // Issue 8: Use limit parameter in alerts query
        Commands::Alerts { limit } => {
            match api.get(&format!("/api/ml/alerts?limit={}", limit)).await {
                Ok(data) => {
                    println!("{}", serde_json::to_string_pretty(&data).unwrap_or_default());
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        // Issue 9: Use ttl parameter in block request body
        Commands::Block { ip, ttl } => {
            let ip_ver = if ip.contains(':') { 6 } else { 4 };
            let body = serde_json::json!({
                "ip_version": ip_ver, "direction": "source",
                "list_type": "blacklist", "ip_address": ip, "port": 0,
                "ttl_secs": ttl
            });
            match api.post("/api/acl/add", body).await {
                Ok(data) => { println!("Blocked: {}", serde_json::to_string(&data).unwrap_or_default()); Ok(()) }
                Err(e) => Err(e),
            }
        }
        Commands::Unblock { ip } => {
            let ip_ver = if ip.contains(':') { 6 } else { 4 };
            let body = serde_json::json!({
                "ip_version": ip_ver, "direction": "source",
                "list_type": "blacklist", "ip_address": ip, "port": 0
            });
            match api.post("/api/acl/delete", body).await {
                Ok(data) => { println!("Unblocked: {}", serde_json::to_string(&data).unwrap_or_default()); Ok(()) }
                Err(e) => Err(e),
            }
        }
        Commands::Rules => {
            match api.get("/api/acl/list").await {
                Ok(data) => { println!("{}", serde_json::to_string_pretty(&data).unwrap_or_default()); Ok(()) }
                Err(e) => Err(e),
            }
        }
        // Issue 10: Use format parameter for report output
        Commands::Report { format } => {
            match api.post("/api/report/generate", serde_json::json!({})).await {
                Ok(data) => {
                    if format == "json" {
                        println!("{}", serde_json::to_string_pretty(&data).unwrap_or_default());
                    } else {
                        print!("{}", format_report_text(&data));
                    }
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        Commands::Mode { mode } => {
            match mode {
                Some(m) => {
                    let body = serde_json::json!({"mode": m});
                    match api.post("/api/system/enforce-mode", body).await {
                        Ok(data) => { println!("{}", serde_json::to_string_pretty(&data).unwrap_or_default()); Ok(()) }
                        Err(e) => Err(e),
                    }
                }
                None => {
                    match api.get("/api/system/enforce-mode").await {
                        Ok(data) => { println!("{}", serde_json::to_string_pretty(&data).unwrap_or_default()); Ok(()) }
                        Err(e) => Err(e),
                    }
                }
            }
        }
        Commands::Login => {
            print!("Username: ");
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
            let mut username = String::new();
            std::io::stdin().read_line(&mut username).unwrap();
            let username = username.trim();

            // Read password without echo (simple version)
            print!("Password: ");
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
            let mut password = String::new();
            std::io::stdin().read_line(&mut password).unwrap();
            let password = password.trim();

            match api.login(username, password).await {
                Ok(token) => {
                    api.save_token(&token);
                    println!("Login successful. Token saved to ~/.ng/token");
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        Commands::McpKey { action } => {
            match action {
                // Issue 13: Generate key via API so it persists
                McpKeyAction::Generate { name, level } => {
                    let body = serde_json::json!({
                        "name": name,
                        "level": level,
                    });
                    match api.post("/api/mcp-keys/generate", body).await {
                        Ok(data) => {
                            if let Some(key) = data.get("key").and_then(|k| k.as_str()) {
                                println!("Generated MCP API key: {}", key);
                                println!("Name: {}, Level: {}", name, level);
                                println!("Set NETGUARDIA_MCP_KEY={} in your MCP client config", key);
                            } else {
                                println!("{}", serde_json::to_string_pretty(&data).unwrap_or_default());
                            }
                            Ok(())
                        }
                        Err(e) => Err(e),
                    }
                }
                // Issue 11: List keys via API
                McpKeyAction::List => {
                    match api.get("/api/mcp-keys").await {
                        Ok(data) => {
                            if let Some(keys) = data.as_array() {
                                if keys.is_empty() {
                                    println!("No MCP keys found.");
                                } else {
                                    println!("{:<6} {:<20} {:<15} {:<22} Last Used", "ID", "Name", "Level", "Created");
                                    println!("{}", "-".repeat(80));
                                    for key in keys {
                                        println!("{:<6} {:<20} {:<15} {:<22} {}",
                                            key.get("id").and_then(|v| v.as_i64()).unwrap_or(0),
                                            key.get("name").and_then(|v| v.as_str()).unwrap_or("-"),
                                            key.get("permission_level").and_then(|v| v.as_str()).unwrap_or("-"),
                                            key.get("created_at").and_then(|v| v.as_str()).unwrap_or("-"),
                                            key.get("last_used_at").and_then(|v| v.as_str()).unwrap_or("never"),
                                        );
                                    }
                                }
                            } else {
                                println!("{}", serde_json::to_string_pretty(&data).unwrap_or_default());
                            }
                            Ok(())
                        }
                        Err(e) => Err(e),
                    }
                }
                // Issue 12: Revoke key via API
                McpKeyAction::Revoke { id } => {
                    match api.delete(&format!("/api/mcp-keys/{}", id)).await {
                        Ok(data) => {
                            if data.get("deleted").and_then(|v| v.as_bool()).unwrap_or(false) {
                                println!("Key #{} revoked successfully.", id);
                            } else {
                                println!("{}", serde_json::to_string_pretty(&data).unwrap_or_default());
                            }
                            Ok(())
                        }
                        Err(e) => Err(e),
                    }
                }
            }
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
