use std::fs;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, Signature};
use pnet::datalink;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(name = "license-generator", about = "NetGuardia license generator")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Ed25519 keypair
    Keygen {
        #[arg(short, long, default_value = "license")]
        prefix: String,
    },
    /// Issue a signed license bound to NIC MACs
    Issue {
        #[arg(short = 'k', long)]
        private_key: String,
        /// Ingress interface name (e.g. ng-ext)
        #[arg(long)]
        ingress: String,
        /// Egress interface name (e.g. ng-int)
        #[arg(long)]
        egress: String,
        /// Expiry date (YYYY-MM-DD)
        #[arg(short, long)]
        expires: String,
        /// Comma-separated list of features
        #[arg(short, long, default_value = "")]
        features: String,
        /// Output license file path
        #[arg(short, long, default_value = "license.key")]
        output: String,
    },
    /// Verify a license file
    Verify {
        #[arg(short = 'k', long)]
        public_key: String,
        #[arg(short, long)]
        license: String,
    },
}

#[derive(Serialize, Deserialize, Debug)]
struct LicensePayload {
    ingress_mac: String,
    egress_mac: String,
    expires: String,
    features: Vec<String>,
}

fn get_mac(ifname: &str) -> String {
    for iface in datalink::interfaces() {
        if iface.name == ifname {
            if let Some(mac) = iface.mac {
                return format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    mac.0, mac.1, mac.2, mac.3, mac.4, mac.5
                );
            }
        }
    }
    eprintln!("Interface '{}' not found or has no MAC address", ifname);
    eprintln!("Available interfaces:");
    for iface in datalink::interfaces() {
        if let Some(mac) = iface.mac {
            eprintln!("  {} — {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                iface.name, mac.0, mac.1, mac.2, mac.3, mac.4, mac.5);
        }
    }
    std::process::exit(1);
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { prefix } => keygen(&prefix),
        Commands::Issue { private_key, ingress, egress, expires, features, output } => {
            issue(&private_key, &ingress, &egress, &expires, &features, &output)
        }
        Commands::Verify { public_key, license } => verify(&public_key, &license),
    }
}

fn keygen(prefix: &str) {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let priv_hex = hex_encode(signing_key.as_bytes());
    let pub_hex = hex_encode(verifying_key.as_bytes());

    let priv_path = format!("{}_priv.key", prefix);
    let pub_path = format!("{}_pub.key", prefix);

    fs::write(&priv_path, &priv_hex).expect("Failed to write private key");
    fs::write(&pub_path, &pub_hex).expect("Failed to write public key");

    println!("Keypair generated:");
    println!("  Private key: {}", priv_path);
    println!("  Public key:  {}", pub_path);
    println!();
    println!("Public key hex (embed in validator.rs):");
    println!("  {}", pub_hex);
}

fn issue(private_key_path: &str, ingress: &str, egress: &str, expires: &str, features: &str, output: &str) {
    let ingress_mac = get_mac(ingress);
    let egress_mac = get_mac(egress);

    println!("Detected MACs:");
    println!("  {} — {}", ingress, ingress_mac);
    println!("  {} — {}", egress, egress_mac);

    let priv_hex = fs::read_to_string(private_key_path)
        .expect("Failed to read private key")
        .trim()
        .to_string();
    let priv_bytes = hex_decode(&priv_hex).expect("Invalid hex");
    let priv_array: [u8; 32] = priv_bytes.try_into().expect("Key must be 32 bytes");
    let signing_key = SigningKey::from_bytes(&priv_array);

    let feature_list: Vec<String> = if features.is_empty() {
        vec![]
    } else {
        features.split(',').map(|s| s.trim().to_string()).collect()
    };

    let payload = LicensePayload {
        ingress_mac: ingress_mac.clone(),
        egress_mac: egress_mac.clone(),
        expires: expires.to_string(),
        features: feature_list,
    };

    let payload_json = serde_json::to_string(&payload).expect("Failed to serialize");
    let payload_b64 = BASE64.encode(payload_json.as_bytes());
    let signature: Signature = signing_key.sign(payload_b64.as_bytes());
    let sig_b64 = BASE64.encode(signature.to_bytes());

    let license_content = format!("{}.{}", payload_b64, sig_b64);
    fs::write(output, &license_content).expect("Failed to write license");

    println!();
    println!("License issued:");
    println!("  Ingress MAC: {}", ingress_mac);
    println!("  Egress MAC:  {}", egress_mac);
    println!("  Expires:     {}", expires);
    println!("  Features:    {:?}", payload.features);
    println!("  Output:      {}", output);
}

fn verify(public_key_path: &str, license_path: &str) {
    let pub_hex = fs::read_to_string(public_key_path)
        .expect("Failed to read public key")
        .trim()
        .to_string();
    let pub_bytes = hex_decode(&pub_hex).expect("Invalid hex");
    let pub_array: [u8; 32] = pub_bytes.try_into().expect("Key must be 32 bytes");
    let verifying_key = VerifyingKey::from_bytes(&pub_array).expect("Invalid public key");

    let contents = fs::read_to_string(license_path)
        .expect("Failed to read license")
        .trim()
        .to_string();

    let parts: Vec<&str> = contents.splitn(2, '.').collect();
    if parts.len() != 2 {
        eprintln!("Invalid license format");
        std::process::exit(1);
    }

    let sig_bytes = BASE64.decode(parts[1]).expect("Invalid signature");
    let sig_array: [u8; 64] = sig_bytes.try_into().expect("Signature must be 64 bytes");
    let signature = Signature::from_bytes(&sig_array);

    match verifying_key.verify(parts[0].as_bytes(), &signature) {
        Ok(()) => {
            let payload_bytes = BASE64.decode(parts[0]).expect("Invalid payload");
            let payload: LicensePayload = serde_json::from_slice(&payload_bytes).expect("Invalid JSON");
            println!("License VALID:");
            println!("  Ingress MAC: {}", payload.ingress_mac);
            println!("  Egress MAC:  {}", payload.egress_mac);
            println!("  Expires:     {}", payload.expires);
            println!("  Features:    {:?}", payload.features);
        }
        Err(e) => {
            eprintln!("License INVALID: {}", e);
            std::process::exit(1);
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("Odd-length hex string".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}
