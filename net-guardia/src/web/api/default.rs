use actix_web::{HttpRequest, HttpResponse, Responder};
use mime_guess::from_path;
use crate::utils::static_files::StaticFiles;

pub async fn default_route(req: HttpRequest) -> impl Responder {
    let request_path = req.path();
    let request_path = if request_path == "/" { "/index.html" } else { &request_path };
    let file_system_path = format!("web{}", request_path);
    match StaticFiles::get(&*file_system_path) {
        Some(content) => {
            let mime_type = from_path(file_system_path).first_or_octet_stream();
            HttpResponse::Ok()
                .content_type(mime_type.as_ref())
                .body(content.data.into_owned())
        }
        None => {
            match StaticFiles::get("index.html") {
                Some(index) => HttpResponse::Ok()
                    .content_type("text/html")
                    .body(index.data.into_owned()),
                None => HttpResponse::NotFound().body("404 Not Found"),
            }
        }
    }
}
