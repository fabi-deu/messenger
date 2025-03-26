use askama::Template;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use serde::{Deserialize, Serialize};

/// wrapper for returning HTML in axum
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
struct HtmlWrapper<T>(T);


impl<T> IntoResponse for HtmlWrapper<T>
where
    T: Template
{
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to render template: {}", e),
            ).into_response()
        }
    }
}
