use crate::error::AppError;
use actix_web::{
    HttpResponse,
    get,
    http::header::ContentType,
    web,
};

const ROBOTS_TXT: &str = include_str!("../../static/robots.txt");

#[get("/robots.txt")]
async fn get() -> Result<HttpResponse, AppError> {
    Ok(HttpResponse::Ok()
        .content_type(ContentType::plaintext())
        .body(ROBOTS_TXT))
}

pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(get);
}
