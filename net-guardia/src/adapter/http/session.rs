use std::sync::Arc;

use actix_web::cookie::time::Duration as CookieDuration;
use actix_web::cookie::{Cookie, SameSite};
use arc_swap::ArcSwap;

use crate::core::identity::session_service::CreatedSession;
use crate::domain::common::config::AppConfig;

pub const SESSION_COOKIE_NAME: &str = "netguardia_session";
pub const SECURE_SESSION_COOKIE_NAME: &str = "__Host-netguardia_session";

pub struct SessionCookieService {
    config: Arc<ArcSwap<AppConfig>>,
}

impl SessionCookieService {
    pub fn new(config: Arc<ArcSwap<AppConfig>>) -> Self {
        Self { config }
    }

    pub fn session_cookie(&self, session: &CreatedSession) -> Cookie<'static> {
        Cookie::build(self.cookie_name(), session.id.clone())
            .path("/")
            .http_only(true)
            .secure(self.secure_cookie())
            .same_site(SameSite::Strict)
            .max_age(cookie_duration(session.max_age_secs))
            .finish()
    }

    pub fn removal_cookies(&self) -> Vec<Cookie<'static>> {
        let mut cookies = vec![self.removal_cookie_for(self.cookie_name())];
        if self.cookie_name() != SESSION_COOKIE_NAME {
            cookies.push(self.removal_cookie_for(SESSION_COOKIE_NAME));
        }
        cookies
    }

    pub fn cookie_name(&self) -> &'static str {
        if self.secure_cookie() {
            SECURE_SESSION_COOKIE_NAME
        } else {
            SESSION_COOKIE_NAME
        }
    }

    fn removal_cookie_for(&self, name: &'static str) -> Cookie<'static> {
        Cookie::build(name, "")
            .path("/")
            .http_only(true)
            .secure(self.secure_cookie())
            .same_site(SameSite::Strict)
            .max_age(CookieDuration::seconds(0))
            .finish()
    }

    fn secure_cookie(&self) -> bool {
        self.config.load().http_server.force_https
    }
}

fn cookie_duration(secs: u64) -> CookieDuration {
    let secs = i64::try_from(secs).unwrap_or(i64::MAX);
    CookieDuration::seconds(secs)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arc_swap::ArcSwap;

    use super::*;

    fn cookie_service(force_https: bool) -> SessionCookieService {
        let mut cfg = AppConfig::defaults();
        cfg.http_server.force_https = force_https;
        SessionCookieService::new(Arc::new(ArcSwap::from_pointee(cfg)))
    }

    fn created_session() -> CreatedSession {
        CreatedSession {
            id: "session-id".to_string(),
            csrf_token: "csrf-token".to_string(),
            max_age_secs: 3600,
        }
    }

    #[test]
    fn session_cookie_is_http_only_and_strict() {
        let service = cookie_service(false);
        let cookie = service.session_cookie(&created_session());

        assert_eq!(cookie.name(), SESSION_COOKIE_NAME);
        assert!(cookie.http_only().unwrap_or(false));
        assert_eq!(cookie.same_site(), Some(SameSite::Strict));
        assert_eq!(cookie.value(), "session-id");
    }

    #[test]
    fn secure_cookie_uses_host_prefix_when_https_is_forced() {
        let service = cookie_service(true);
        let cookie = service.session_cookie(&created_session());

        assert_eq!(cookie.name(), SECURE_SESSION_COOKIE_NAME);
        assert!(cookie.secure().unwrap_or(false));
    }
}
