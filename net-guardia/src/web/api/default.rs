use actix_web::{HttpRequest, HttpResponse, Responder};
use mime_guess::from_path;

use crate::utils::static_files::StaticFiles;

pub async fn default_route(req: HttpRequest) -> impl Responder {
    let request_path = req.path();

    let file_system_path = if request_path == "/" {
        "web/index.html".to_string()
    } else {
        format!("web{}", request_path)
    };

    if let Some(content) = StaticFiles::get(&file_system_path) {
        let mime_type = from_path(&file_system_path).first_or_octet_stream();
        return HttpResponse::Ok()
            .content_type(mime_type.as_ref())
            .body(content.data.into_owned());
    }

    let html_path = format!("{}.html", file_system_path);
    if let Some(content) = StaticFiles::get(&html_path) {
        return HttpResponse::Ok()
            .content_type("text/html")
            .body(content.data.into_owned());
    }

    let index_path = format!("{}/index.html", file_system_path);
    if let Some(content) = StaticFiles::get(&index_path) {
        return HttpResponse::Ok()
            .content_type("text/html")
            .body(content.data.into_owned());
    }

    match StaticFiles::get("web/404.html") {
        Some(page) => HttpResponse::NotFound()
            .content_type("text/html")
            .body(page.data.into_owned()),
        None => HttpResponse::NotFound().body("404 Not Found"),
    }
}