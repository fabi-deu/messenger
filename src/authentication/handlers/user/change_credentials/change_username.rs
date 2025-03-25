use std::io;
use std::io::ErrorKind;
use axum::{Extension, Json};
use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use crate::authentication::models::appstate::AppstateWrapper;
use crate::authentication::models::auth_user::AuthUser;

#[derive(Serialize, Deserialize)]
pub struct Body {
    username: String,
}


#[axum_macros::debug_handler]
pub async fn change_username(
    State(appstate_wrapper): State<AppstateWrapper>,
    auth_user: Extension<AuthUser>,
    Json(body): Json<Body>
) -> Result<StatusCode, (StatusCode, &'static str)> {
    let appstate = appstate_wrapper.0;
    let user = auth_user.0.0;
    let username = body.username;

    if user.username == username {
        return Err((StatusCode::BAD_REQUEST, "new username cannot be the same as old"))
    }


    // update
    match user.update_username(username, &appstate.db).await {
        Ok(_) => {},
        Err(e) => {
            // downcast error
            if let Some(io_err) = e.downcast_ref::<io::Error>() {
                return match io_err.kind() {
                    ErrorKind::Other => Err((StatusCode::BAD_REQUEST, "Bad password")),
                    _ => Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to update password"))
                }
            }
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to update password"))
        }
    }

    // we don't have to generate new tokens as the old ones are still perfectly valid (uuid-based)

    Ok(StatusCode::OK)
}