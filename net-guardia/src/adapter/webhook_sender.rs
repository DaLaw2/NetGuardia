use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use macros::log;
use reqwest::Client;
use tokio::net::lookup_host;
use url::Url;

use crate::common::error::Error;
use crate::common::utils::ip_address::is_private_ip;
use crate::domain::response::error::SoarError;
use crate::domain::response::log::SoarLog;
use crate::interface::response::webhook_sender::WebhookSender;

const DEFAULT_WEBHOOK_HTTPS_PORT: u16 = 443;

#[derive(Default)]
pub struct ReqwestWebhookSender;

#[async_trait::async_trait]
impl WebhookSender for ReqwestWebhookSender {
    async fn post_json(&self, url: &str, timeout_secs: u64, payload: &serde_json::Value) -> Result<u16, Error> {
        let parsed_url = Url::parse(url).map_err(|e| SoarError::ActionFailed("webhook", e))?;
        require_supported_webhook_scheme(&parsed_url)?;
        let host = parsed_url.host_str().ok_or(SoarError::WebhookUrlNoHost)?;
        let addrs = resolve_public_webhook_addrs(&parsed_url, host).await?;

        let mut client_builder = Client::builder().timeout(Duration::from_secs(timeout_secs));
        for addr in &addrs {
            client_builder = client_builder.resolve(host, *addr);
        }
        let client = client_builder
            .build()
            .map_err(|e| SoarError::ActionFailed("webhook", e))?;

        let resp = client
            .post(url)
            .json(payload)
            .send()
            .await
            .map_err(|e| SoarError::ActionFailed("webhook", e))?;

        Ok(resp.status().as_u16())
    }
}

fn require_supported_webhook_scheme(parsed_url: &Url) -> Result<(), Error> {
    match parsed_url.scheme() {
        "http" | "https" => Ok(()),
        other => Err(SoarError::WebhookUnsupportedScheme(other))?,
    }
}

async fn resolve_public_webhook_addrs(parsed_url: &Url, host: &str) -> Result<Vec<SocketAddr>, Error> {
    let port = parsed_url.port_or_known_default().unwrap_or(DEFAULT_WEBHOOK_HTTPS_PORT);
    let addrs: Vec<SocketAddr> = lookup_host((host, port))
        .await
        .map_err(|e| SoarError::ActionFailed(format!("webhook (DNS for {})", host), e))?
        .collect();

    if addrs.is_empty() {
        Err(SoarError::WebhookDnsEmpty(host))?;
    }

    for addr in &addrs {
        if !is_public_webhook_ip(&addr.ip()) {
            log!(SoarLog::WebhookSsrfBlocked(host.to_string(), addr.ip().to_string()));
            Err(SoarError::WebhookSsrfBlocked(host, addr.ip().to_string()))?;
        }
    }

    Ok(addrs)
}

fn is_public_webhook_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_webhook_ipv4(v4),
        IpAddr::V6(v6) => is_public_webhook_ipv6(v6),
    }
}

fn is_public_webhook_ipv4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    let blocked = is_private_ip(&IpAddr::V4(*ip))
        || ip.is_multicast()
        || ip.is_documentation()
        || octets[0] == 0
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 198 && (18..=19).contains(&octets[1]))
        || octets[0] >= 240;
    !blocked
}

fn is_public_webhook_ipv6(ip: &Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_public_webhook_ipv4(&mapped);
    }

    let segments = ip.segments();
    let blocked =
        is_private_ip(&IpAddr::V6(*ip)) || ip.is_multicast() || (segments[0] == 0x2001 && segments[1] == 0x0db8);
    !blocked
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_scheme_accepts_http_and_https() {
        for url in ["http://example.com/hook", "https://example.com/hook"] {
            let parsed = Url::parse(url).expect("valid test URL");

            require_supported_webhook_scheme(&parsed).expect("scheme should be supported");
        }
    }

    #[test]
    fn webhook_scheme_rejects_non_http_urls() {
        for url in ["ftp://example.com/hook", "file:///tmp/hook"] {
            let parsed = Url::parse(url).expect("valid test URL");

            let result = require_supported_webhook_scheme(&parsed);

            assert!(result.is_err(), "{url} should be rejected");
        }
    }

    #[test]
    fn webhook_public_ip_rejects_non_public_ranges() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "198.18.0.1",
            "192.0.2.1",
            "224.0.0.1",
            "0.1.2.3",
            "240.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:10.0.0.1",
        ] {
            let ip = ip.parse::<IpAddr>().expect("test IP");

            assert!(!is_public_webhook_ip(&ip), "{ip} should be rejected");
        }
    }

    #[test]
    fn webhook_public_ip_accepts_global_unicast_examples() {
        for ip in ["8.8.8.8", "2606:4700:4700::1111"] {
            let ip = ip.parse::<IpAddr>().expect("test IP");

            assert!(is_public_webhook_ip(&ip), "{ip} should be accepted");
        }
    }
}
