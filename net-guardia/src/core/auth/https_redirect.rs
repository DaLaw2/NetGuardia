use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header;
use actix_web::{Error as ActixError, HttpResponse, web};

/// Shared flag: when true, non-HTTPS requests are redirected.
pub type ForceHttpsFlag = Arc<AtomicBool>;

/// Validate that the host is safe to use in a redirect Location header.
/// Only allows: private IPs (RFC 1918), loopback, .local hostnames, and bare hostnames
/// without dots (e.g., "netguardia"). Rejects public IPs and arbitrary domains
/// to prevent host-header injection / open redirect attacks.
fn is_safe_redirect_host(host: &str) -> bool {
    // Strip port if present (e.g., "192.168.1.1:8443" → "192.168.1.1")
    let hostname = if host.starts_with('[') {
        // IPv6 bracket: [::1]:8443
        host.find(']').map(|i| &host[1..i]).unwrap_or(host)
    } else {
        host.split(':').next().unwrap_or(host)
    };

    // Localhost
    if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" {
        return true;
    }

    // .local mDNS hostnames (e.g., "netguardia.local")
    if hostname.ends_with(".local") {
        return true;
    }

    // Bare hostname without dots (e.g., "netguardia", not a public domain)
    if !hostname.contains('.') && !hostname.contains(':') {
        return true;
    }

    // Try parsing as IP — allow private ranges only
    if let Ok(ip) = hostname.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168) || o[0] == 127
            }
            std::net::IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
        };
    }

    false
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
            service: std::rc::Rc::new(service),
        }))
    }
}

pub struct HttpsRedirectService<S> {
    service: std::rc::Rc<S>,
}

impl<S, B> Service<ServiceRequest> for HttpsRedirectService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = ActixError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, ctx: &mut core::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = std::rc::Rc::clone(&self.service);

        Box::pin(async move {
            // Check if force_https is enabled
            let force = req
                .app_data::<web::Data<ForceHttpsFlag>>()
                .map(|flag| flag.load(Ordering::Relaxed))
                .unwrap_or(false);

            if !force {
                let res = service.call(req).await?.map_into_left_body();
                return Ok(res);
            }

            // Allow health check endpoints without redirect (for load balancer probes)
            let path = req.path();
            if path.starts_with("/health/") {
                let res = service.call(req).await?.map_into_left_body();
                return Ok(res);
            }

            // Check X-Forwarded-Proto (set by reverse proxy / load balancer)
            let proto = req
                .headers()
                .get("X-Forwarded-Proto")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("http");

            if proto == "https" {
                let res = service.call(req).await?.map_into_left_body();
                return Ok(res);
            }

            // Build HTTPS redirect URL.
            // Validate host to prevent host-header injection / open redirect:
            // only allow private IPs, localhost, and .local hostnames.
            let host = req.connection_info().host().to_string();
            let uri = req.uri().clone();

            if !is_safe_redirect_host(&host) {
                let resp = HttpResponse::BadRequest().finish();
                return Ok(req.into_response(resp).map_into_right_body());
            }

            let redirect_url = format!("https://{}{}", host, uri);
            let resp = HttpResponse::MovedPermanently()
                .insert_header((header::LOCATION, redirect_url))
                // HSTS: 1 year, include subdomains
                .insert_header(("Strict-Transport-Security", "max-age=31536000; includeSubDomains"))
                .finish();
            Ok(req.into_response(resp).map_into_right_body())
        })
    }
}
