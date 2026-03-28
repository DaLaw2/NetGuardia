use std::future::{ready, Ready};

use actix_web::dev::Payload;
use actix_web::{FromRequest, HttpMessage, HttpRequest};

use crate::model::auth::Claims;

/// Actix-web extractor that pulls `Claims` from request extensions.
///
/// The `AuthMiddleware` validates JWT/API key and stores Claims in extensions.
/// This extractor simply reads them out, returning 401 if missing.
///
/// Usage:
/// ```ignore
/// async fn handler(auth: AuthClaims, ...) -> HttpResponse {
///     let user_id = auth.sub;
///     // ...
/// }
/// ```
pub struct AuthClaims(pub Claims);

impl std::ops::Deref for AuthClaims {
    type Target = Claims;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromRequest for AuthClaims {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        match req.extensions().get::<Claims>().cloned() {
            Some(claims) => ready(Ok(AuthClaims(claims))),
            None => ready(Err(actix_web::error::ErrorUnauthorized(
                serde_json::json!({"error": "Unauthorized"}),
            ))),
        }
    }
}
