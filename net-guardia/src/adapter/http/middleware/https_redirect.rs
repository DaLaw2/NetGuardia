use std::future::{Future, Ready, ready};
use std::net::IpAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};

use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header;
use actix_web::{Error as ActixError, HttpResponse, web};

use crate::infrastructure::http_runtime::ForceHttpsFlag;

fn is_safe_redirect_host(host: &str) -> bool {
    let Some(hostname) = redirect_hostname(host) else {
        return false;
    };

    if hostname.eq_ignore_ascii_case("localhost") {
        return true;
    }

    if let Ok(ip) = hostname.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168) || o[0] == 127
            }
            IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
        };
    }

    if !is_valid_redirect_hostname(hostname) {
        return false;
    }

    let hostname = hostname.to_ascii_lowercase();
    hostname.ends_with(".local") || !hostname.contains('.')
}

fn redirect_hostname(host: &str) -> Option<&str> {
    if host.is_empty() {
        return None;
    }

    if host.starts_with('[') {
        let bracket_end = host.find(']')?;
        let hostname = &host[1..bracket_end];
        let rest = &host[bracket_end + 1..];
        if hostname.is_empty() || !valid_optional_port(rest) {
            return None;
        }
        return Some(hostname);
    }

    if host.contains('[') || host.contains(']') {
        return None;
    }

    let colon_count = host.bytes().filter(|byte| *byte == b':').count();
    if colon_count > 1 {
        return None;
    }

    if let Some((hostname, port)) = host.rsplit_once(':') {
        if hostname.is_empty() || !valid_port(port) {
            return None;
        }
        return Some(hostname);
    }

    Some(host)
}

fn valid_optional_port(port_suffix: &str) -> bool {
    port_suffix.is_empty() || port_suffix.strip_prefix(':').is_some_and(valid_port)
}

fn valid_port(port: &str) -> bool {
    !port.is_empty() && port.parse::<u16>().is_ok()
}

fn is_valid_redirect_hostname(hostname: &str) -> bool {
    !hostname.is_empty() && hostname.len() <= 253 && hostname.split('.').all(is_valid_redirect_hostname_label)
}

fn is_valid_redirect_hostname_label(label: &str) -> bool {
    let first = label.bytes().next();
    let last = label.bytes().last();
    !label.is_empty()
        && label.len() <= 63
        && first.is_some_and(|byte| byte.is_ascii_alphanumeric())
        && last.is_some_and(|byte| byte.is_ascii_alphanumeric())
        && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn is_forwarded_https(proto: &str) -> bool {
    proto
        .split(',')
        .next()
        .is_some_and(|first| first.trim().eq_ignore_ascii_case("https"))
}

pub struct HttpsRedirect;

impl<S, B> Transform<S, ServiceRequest> for HttpsRedirect
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = ActixError;
    type Transform = HttpsRedirectService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(HttpsRedirectService {
            service: Rc::new(service),
        }))
    }
}

pub struct HttpsRedirectService<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for HttpsRedirectService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = ActixError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);

        Box::pin(async move {
            let force = req
                .app_data::<web::Data<ForceHttpsFlag>>()
                .map(|flag| flag.0.load(Ordering::Relaxed))
                .unwrap_or(false);

            if !force {
                let res = service.call(req).await?.map_into_left_body();
                return Ok(res);
            }

            let path = req.path();
            if path.starts_with("/health/") {
                let res = service.call(req).await?.map_into_left_body();
                return Ok(res);
            }

            let proto = req
                .headers()
                .get("X-Forwarded-Proto")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("http");

            if is_forwarded_https(proto) {
                let res = service.call(req).await?.map_into_left_body();
                return Ok(res);
            }

            let host = req.connection_info().host().to_string();
            let uri = req.uri().clone();

            if !is_safe_redirect_host(&host) {
                let resp = HttpResponse::BadRequest().finish();
                return Ok(req.into_response(resp).map_into_right_body());
            }

            let redirect_url = format!("https://{}{}", host, uri);
            let resp = HttpResponse::MovedPermanently()
                .insert_header((header::LOCATION, redirect_url))
                .insert_header(("Strict-Transport-Security", "max-age=31536000; includeSubDomains"))
                .finish();
            Ok(req.into_response(resp).map_into_right_body())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_redirect_host_accepts_private_and_local_hosts() {
        assert!(is_safe_redirect_host("192.168.1.10:8443"));
        assert!(is_safe_redirect_host("[::1]:8443"));
        assert!(is_safe_redirect_host("[fd00::1]"));
        assert!(is_safe_redirect_host("[fd00::1]:8443"));
        assert!(is_safe_redirect_host("localhost"));
        assert!(is_safe_redirect_host("netguardia"));
        assert!(is_safe_redirect_host("netguardia.local"));
    }

    #[test]
    fn safe_redirect_host_rejects_public_and_malformed_hosts() {
        assert!(!is_safe_redirect_host(""));
        assert!(!is_safe_redirect_host("8.8.8.8"));
        assert!(!is_safe_redirect_host("example.com"));
        assert!(!is_safe_redirect_host("evil%2ecom"));
        assert!(!is_safe_redirect_host("bad host"));
        assert!(!is_safe_redirect_host("-netguardia"));
        assert!(!is_safe_redirect_host("netguardia-"));
        assert!(!is_safe_redirect_host("fd00::1"));
        assert!(!is_safe_redirect_host("[::1]evil"));
        assert!(!is_safe_redirect_host("192.168.1.10:http"));
        assert!(!is_safe_redirect_host("192.168.1.10:99999"));
    }

    #[test]
    fn forwarded_proto_accepts_proxy_chain_first_hop() {
        assert!(is_forwarded_https("https"));
        assert!(is_forwarded_https("HTTPS"));
        assert!(is_forwarded_https(" https, http"));
        assert!(!is_forwarded_https("http, https"));
        assert!(!is_forwarded_https(""));
    }
}
