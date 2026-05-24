use std::future::{Ready, ready};
use std::ops::Deref;

use actix_web::dev::Payload;
use actix_web::error::ErrorUnauthorized;
use actix_web::{Error as ActixError, FromRequest, HttpMessage, HttpRequest};

use crate::domain::identity::auth::Claims;

pub struct AuthClaims(pub Claims);

impl Deref for AuthClaims {
    type Target = Claims;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromRequest for AuthClaims {
    type Error = ActixError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        match req.extensions().get::<Claims>().cloned() {
            Some(claims) => ready(Ok(AuthClaims(claims))),
            None => ready(Err(ErrorUnauthorized(serde_json::json!({"error": "Unauthorized"})))),
        }
    }
}
