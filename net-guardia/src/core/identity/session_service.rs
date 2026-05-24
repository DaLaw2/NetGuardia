use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use dashmap::DashMap;
use rand::Rng;

use crate::common::utils::security::constant_time_eq;
use crate::domain::common::config::AppConfig;
use crate::domain::identity::auth::Claims;

#[derive(Clone)]
struct SessionRecord {
    claims: Claims,
    csrf_token: String,
    expires_at_secs: u64,
    last_seen_secs: u64,
}

pub struct CreatedSession {
    pub id: String,
    pub csrf_token: String,
    pub max_age_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsrfTokenStatus {
    Valid,
    Invalid,
    Expired,
    MissingSession,
}

const GC_INTERVAL_LOGINS: u32 = 64;

pub struct SessionService {
    config: Arc<ArcSwap<AppConfig>>,
    sessions: DashMap<String, SessionRecord>,
    login_counter: AtomicU32,
}

impl SessionService {
    pub fn new(config: Arc<ArcSwap<AppConfig>>) -> Self {
        Self {
            config,
            sessions: DashMap::new(),
            login_counter: AtomicU32::new(0),
        }
    }

    pub fn create_session(&self, claims: Claims) -> CreatedSession {
        let now = now_secs();
        if self
            .login_counter
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(GC_INTERVAL_LOGINS)
        {
            self.remove_expired_sessions(now);
        }
        let session_id = random_url_token();
        let csrf_token = random_url_token();
        let max_age_secs = self.session_max_age_secs();
        let record = SessionRecord {
            claims,
            csrf_token: csrf_token.clone(),
            expires_at_secs: now.saturating_add(max_age_secs),
            last_seen_secs: now,
        };

        self.sessions.insert(session_id.clone(), record);

        CreatedSession {
            id: session_id,
            csrf_token,
            max_age_secs,
        }
    }

    pub fn claims_for_session(&self, session_id: &str) -> Option<Claims> {
        let now = now_secs();
        let mut entry = self.sessions.get_mut(session_id)?;
        if self.record_expired(&entry, now) {
            drop(entry);
            self.sessions.remove(session_id);
            return None;
        }
        entry.last_seen_secs = now;
        Some(entry.claims.clone())
    }

    pub fn csrf_token_status(&self, session_id: &str, csrf_token: &str) -> CsrfTokenStatus {
        let now = now_secs();
        let Some(entry) = self.sessions.get(session_id) else {
            return CsrfTokenStatus::MissingSession;
        };
        if self.record_expired(&entry, now) {
            return CsrfTokenStatus::Expired;
        }
        if constant_time_eq(&entry.csrf_token, csrf_token) {
            CsrfTokenStatus::Valid
        } else {
            CsrfTokenStatus::Invalid
        }
    }

    pub fn csrf_token_for_session(&self, session_id: &str) -> Option<String> {
        let now = now_secs();
        let entry = self.sessions.get(session_id)?;
        if self.record_expired(&entry, now) {
            return None;
        }
        Some(entry.csrf_token.clone())
    }

    pub fn remove_session(&self, session_id: &str) {
        self.sessions.remove(session_id);
    }

    pub fn remove_sessions_for_user(&self, user_id: i64) {
        self.sessions.retain(|_, record| record.claims.sub != user_id);
    }

    fn remove_expired_sessions(&self, now_secs: u64) {
        self.sessions.retain(|_, record| !self.record_expired(record, now_secs));
    }

    fn record_expired(&self, record: &SessionRecord, now_secs: u64) -> bool {
        if now_secs >= record.expires_at_secs {
            return true;
        }
        let idle_timeout_secs = self.session_idle_timeout_secs();
        now_secs.saturating_sub(record.last_seen_secs) >= idle_timeout_secs
    }

    fn session_max_age_secs(&self) -> u64 {
        self.config.load().http_server.session_expiry_hours.saturating_mul(3600)
    }

    fn session_idle_timeout_secs(&self) -> u64 {
        self.config
            .load()
            .http_server
            .session_idle_timeout_minutes
            .saturating_mul(60)
    }
}

fn random_url_token() -> String {
    let mut token = [0_u8; 32];
    rand::rng().fill_bytes(&mut token);
    URL_SAFE_NO_PAD.encode(token)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

#[cfg(test)]
mod tests {
    use arc_swap::ArcSwap;

    use super::*;
    use crate::domain::common::config::AppConfig;

    fn session_service() -> SessionService {
        SessionService::new(Arc::new(ArcSwap::from_pointee(AppConfig::defaults())))
    }

    fn claims() -> Claims {
        Claims {
            sub: 1,
            username: "admin".to_string(),
            role: "admin".to_string(),
            permissions: vec!["system:read".to_string()],
        }
    }

    #[test]
    fn created_session_validates_with_cookie_id() {
        let service = session_service();
        let session = service.create_session(claims());

        let claims = service.claims_for_session(&session.id).expect("claims");

        assert_eq!(claims.sub, 1);
        assert_eq!(
            service.csrf_token_status(&session.id, &session.csrf_token),
            CsrfTokenStatus::Valid
        );
        assert_eq!(
            service.csrf_token_status(&session.id, "wrong"),
            CsrfTokenStatus::Invalid
        );
    }

    #[test]
    fn removed_session_no_longer_validates() {
        let service = session_service();
        let session = service.create_session(claims());

        service.remove_session(&session.id);

        assert!(service.claims_for_session(&session.id).is_none());
    }

    #[test]
    fn sessions_for_user_can_be_removed_together() {
        let service = session_service();
        let first = service.create_session(claims());
        let second = service.create_session(claims());
        let mut other_claims = claims();
        other_claims.sub = 2;
        let other = service.create_session(other_claims);

        service.remove_sessions_for_user(1);

        assert!(service.claims_for_session(&first.id).is_none());
        assert!(service.claims_for_session(&second.id).is_none());
        assert!(service.claims_for_session(&other.id).is_some());
    }
}
