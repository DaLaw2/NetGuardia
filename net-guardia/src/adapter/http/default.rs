use std::path::{Component, Path};

use actix_web::{HttpRequest, HttpResponse, Responder};
use mime_guess::from_path;

use crate::adapter::http::static_files::StaticFiles;

pub async fn default_route(req: HttpRequest) -> impl Responder {
    let path = req.path();

    let Some(file_path) = embedded_web_asset_path(path) else {
        return HttpResponse::NotFound().body("404 Not Found");
    };
    if let Some(content) = StaticFiles::get(&file_path) {
        let mime_type = from_path(&file_path).first_or_octet_stream();
        return HttpResponse::Ok()
            .content_type(mime_type.as_ref())
            .body(content.data.into_owned());
    }
    if path.contains('.') {
        return HttpResponse::NotFound().body("404 Not Found");
    }
    match StaticFiles::get("web/index.html") {
        Some(page) => HttpResponse::Ok()
            .content_type("text/html")
            .body(page.data.into_owned()),
        None => HttpResponse::NotFound().body("404 Not Found"),
    }
}

fn embedded_web_asset_path(request_path: &str) -> Option<String> {
    if request_path == "/" {
        return Some("web/index.html".to_string());
    }
    let relative = request_path.strip_prefix('/').unwrap_or(request_path);
    if relative
        .split(['/', '\\'])
        .any(|segment| segment == "." || segment == "..")
    {
        return None;
    }
    if Path::new(relative).components().any(|component| {
        matches!(
            component,
            Component::CurDir | Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return None;
    }
    Some(format!("web/{relative}"))
}

#[cfg(test)]
mod tests {
    use super::embedded_web_asset_path;

    #[test]
    fn embedded_web_asset_path_maps_root_to_index() {
        assert_eq!(embedded_web_asset_path("/"), Some("web/index.html".to_string()));
    }

    #[test]
    fn embedded_web_asset_path_maps_normal_static_paths() {
        assert_eq!(
            embedded_web_asset_path("/assets/app.js"),
            Some("web/assets/app.js".to_string())
        );
    }

    #[test]
    fn embedded_web_asset_path_rejects_dot_segments() {
        assert_eq!(embedded_web_asset_path("/../Cargo.toml"), None);
        assert_eq!(embedded_web_asset_path("/assets/./app.js"), None);
    }
}
