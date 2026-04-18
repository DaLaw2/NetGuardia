//! HTTP surface for the BYO (bring-your-own-model) Quickstart flow.
//! Exposes read-only metadata that helps an administrator author a
//! valid `manifest.yaml` — principally the `FEATURE_REGISTRY` list,
//! which is the authoritative set of feature names the system will
//! extract and feed to a user-supplied ONNX model.

use actix_web::{HttpResponse, Scope, web};

use crate::core::auth::extractor::AuthClaims;
use crate::core::ml::feature_extractor::feature_registry_names;

pub fn initialize() -> Scope {
    web::scope("/byo").route("/feature-registry", web::get().to(get_feature_registry))
}

/// `GET /api/byo/feature-registry` — list every feature name the
/// manifest validator accepts. Returning this over HTTP lets the
/// BYO Quickstart panel show the authoritative set without shipping
/// duplicated documentation that would drift from the Rust constants.
async fn get_feature_registry(_auth: AuthClaims) -> HttpResponse {
    let names = feature_registry_names();
    HttpResponse::Ok().json(serde_json::json!({
        "count": names.len(),
        "features": names,
    }))
}
