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
    /// System health + enforce mode
    Status,
    /// ML engine status
    Ml,
    /// Add IP to source blacklist
    Block {
        ip: String,
    },
    /// Remove IP from source blacklist
    Unblock { ip: String },
    /// List ACL rules (source blacklist by default)
    Rules {
        #[arg(long, default_value = "source")]
        direction: String,
        #[arg(long, default_value = "blacklist")]
        list_type: String,
    },
    /// Generate security report (JSON data)
    Report,
    /// Get or set enforce mode
    Mode {
        /// Set mode to "monitor" or "enforce"
        mode: Option<String>,
    },
    /// Authenticate and save JWT
    Login,
    /// List SOAR active blocks
    Blocks,
    /// List SOAR playbooks
    Playbooks,
    /// List SOAR execution history
    Executions,
    /// API key management
    ApiKey {
        #[command(subcommand)]
        action: ApiKeyAction,
    },
}

#[derive(Subcommand)]
enum ApiKeyAction {
    /// Generate a new API key
    Generate {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long, default_value = "read_only")]
        level: String,
    },
    /// List all API keys
    List,
    /// Revoke an API key
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
        let status = resp.status().as_u16();
        if status == 401 {
            return Err("Session expired. Run `ng login` to re-authenticate.".into());
        }
        let text = resp.text().await.map_err(|e| format!("Read error: {}", e))?;
        serde_json::from_str(&text).map_err(|_| format!("Unexpected response (HTTP {}): {}", status, &text[..text.len().min(200)]))
    }

    async fn request(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> Result<Value, String> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.client.request(method, &url);
        if let Some(token) = self.load_token() {
            req = req.header("Authorization", format!("Bearer {}", token.trim()));
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.map_err(|e| format!("Connection error: {}", e))?;
        let status = resp.status().as_u16();
        if status == 401 {
            return Err("Session expired. Run `ng login` to re-authenticate.".into());
        }
        let text = resp.text().await.map_err(|e| format!("Read error: {}", e))?;
        if text.is_empty() {
            if (200..300).contains(&status) {
                return Ok(Value::Null);
            }
            return Err(format!("Empty response (HTTP {})", status));
        }
        serde_json::from_str(&text).map_err(|_| format!("Unexpected response (HTTP {}): {}", status, &text[..text.len().min(200)]))
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

fn print_json(data: &Value) {
    println!("{}", serde_json::to_string_pretty(data).unwrap_or_default());
}

fn read_password() -> String {
    // Disable echo for password input
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = std::io::stdin().as_raw_fd();
        let mut termios = unsafe { std::mem::zeroed::<libc::termios>() };
        unsafe { libc::tcgetattr(fd, &mut termios) };
        let old = termios;
        termios.c_lflag &= !libc::ECHO;
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) };

        let mut password = String::new();
        std::io::stdin().read_line(&mut password).unwrap();
        println!(); // newline after hidden input

        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &old) };
        password.trim().to_string()
    }
    #[cfg(not(unix))]
    {
        let mut password = String::new();
        std::io::stdin().read_line(&mut password).unwrap();
        password.trim().to_string()
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let api = ApiClient::new(cli.url);

    let result = match cli.command {
        Commands::Status => {
            api.get("/api/health/status").await.map(|d| print_json(&d))
        }
        Commands::Ml => {
            api.get("/api/ml/status").await.map(|d| print_json(&d))
        }
        Commands::Block { ip } => {
            let is_v6 = ip.contains(':');
            let ip_ver = if is_v6 { "ipv6" } else { "ipv4" };
            let addr = if is_v6 { format!("[{}]:0", ip) } else { format!("{}:0", ip) };
            api.request(reqwest::Method::PUT, &format!("/api/acl/{}/source/blacklist", ip_ver), Some(Value::String(addr)))
                .await.map(|_| println!("Blocked: {}", ip))
        }
        Commands::Unblock { ip } => {
            let is_v6 = ip.contains(':');
            let ip_ver = if is_v6 { "ipv6" } else { "ipv4" };
            let addr = if is_v6 { format!("[{}]:0", ip) } else { format!("{}:0", ip) };
            api.request(reqwest::Method::DELETE, &format!("/api/acl/{}/source/blacklist", ip_ver), Some(Value::String(addr)))
                .await.map(|_| println!("Unblocked: {}", ip))
        }
        Commands::Rules { direction, list_type } => {
            // Try both IPv4 and IPv6
            let v4 = api.get(&format!("/api/acl/ipv4/{}/{}", direction, list_type)).await;
            let v6 = api.get(&format!("/api/acl/ipv6/{}/{}", direction, list_type)).await;
            println!("=== IPv4 {} {} ===", direction, list_type);
            match v4 {
                Ok(d) => print_json(&d),
                Err(e) => eprintln!("{}", e),
            }
            println!("\n=== IPv6 {} {} ===", direction, list_type);
            match v6 {
                Ok(d) => print_json(&d),
                Err(e) => eprintln!("{}", e),
            }
            Ok(())
        }
        Commands::Report => {
            // Use /api/report/data for JSON output
            api.get("/api/report/data").await.map(|d| print_json(&d))
        }
        Commands::Mode { mode } => {
            match mode {
                Some(m) => {
                    let body = serde_json::json!({"mode": m});
                    api.request(reqwest::Method::PUT, "/api/system/enforce-mode", Some(body))
                        .await.map(|d| print_json(&d))
                }
                None => {
                    api.get("/api/system/enforce-mode").await.map(|d| print_json(&d))
                }
            }
        }
        Commands::Login => {
            print!("Username: ");
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
            let mut username = String::new();
            std::io::stdin().read_line(&mut username).unwrap();
            let username = username.trim();

            print!("Password: ");
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
            let password = read_password();

            match api.login(username, &password).await {
                Ok(token) => {
                    api.save_token(&token);
                    println!("Login successful. Token saved to ~/.ng/token");
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        Commands::Blocks => {
            api.get("/api/soar/blocks").await.map(|d| print_json(&d))
        }
        Commands::Playbooks => {
            api.get("/api/soar/playbooks").await.map(|d| print_json(&d))
        }
        Commands::Executions => {
            api.get("/api/soar/executions").await.map(|d| print_json(&d))
        }
        Commands::ApiKey { action } => {
            match action {
                ApiKeyAction::Generate { name, level } => {
                    let body = serde_json::json!({"name": name, "level": level});
                    api.request(reqwest::Method::POST, "/api/api-keys/generate", Some(body))
                        .await.map(|data| {
                            if let Some(key) = data.get("key").and_then(|k| k.as_str()) {
                                println!("Generated API key: {}", key);
                                println!("Name: {}, Level: {}", name, level);
                                println!("Set NETGUARDIA_API_KEY={} in your client config", key);
                            } else {
                                print_json(&data);
                            }
                        })
                }
                ApiKeyAction::List => {
                    api.get("/api/api-keys").await.map(|data| {
                        if let Some(keys) = data.as_array() {
                            if keys.is_empty() {
                                println!("No API keys found.");
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
                            print_json(&data);
                        }
                    })
                }
                ApiKeyAction::Revoke { id } => {
                    api.request(reqwest::Method::DELETE, &format!("/api/api-keys/{}", id), None)
                        .await.map(|data| {
                            if data.get("deleted").and_then(|v| v.as_bool()).unwrap_or(false) {
                                println!("Key #{} revoked successfully.", id);
                            } else {
                                print_json(&data);
                            }
                        })
                }
            }
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
