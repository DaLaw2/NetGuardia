use actix_web::{HttpRequest, HttpResponse, Responder};
use mime_guess::from_path;

use crate::utils::static_files::StaticFiles;

pub async fn default_route(req: HttpRequest) -> impl Responder {
    let path = req.path();

    let file_path = if path == "/" {
        "web/index.html".to_string()
    } else {
        format!("web{}", path)
    };

    // 1. Try exact static file match
    if let Some(content) = StaticFiles::get(&file_path) {
        let mime_type = from_path(&file_path).first_or_octet_stream();
        return HttpResponse::Ok()
            .content_type(mime_type.as_ref())
            .body(content.data.into_owned());
    }

    // 2. Has file extension (contains '.') but not found → 404
    if path.contains('.') {
        return HttpResponse::NotFound().body("404 Not Found");
    }

    // 3. Clean path → SPA fallback to index.html
    match StaticFiles::get("web/index.html") {
        Some(page) => HttpResponse::Ok()
            .content_type("text/html")
            .body(page.data.into_owned()),
        None => HttpResponse::NotFound().body("404 Not Found"),
    }
}
