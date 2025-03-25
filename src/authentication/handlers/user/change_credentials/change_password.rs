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
    old_password: String,
    new_password: String,
}


#[axum_macros::debug_handler]
pub async fn change_password(
    State(appstate_wrapper): State<AppstateWrapper>,
    auth_user: Extension<AuthUser>,
    Json(body): Json<Body>
) -> Result<StatusCode, (StatusCode, &'static str)> {
    let appstate = appstate_wrapper.0;
    let user = auth_user.0.0;
    let (old_password, new_password) = (body.old_password, body.new_password);

    // verify old password
    match user.verify_password(old_password) {
        Ok(true) => {},
        Ok(false) => return Err((StatusCode::UNAUTHORIZED, "Wrong password")),
        _ => return Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to verify old password")),
    }

    // check if new password is the same
    match user.verify_password(new_password.clone()) {
        Ok(true) => return Err((StatusCode::BAD_REQUEST, "new password cannot be the same as old")),
        _ => {}, // just continue
    }

    // update password
    match user.update_password(new_password, &appstate.db).await {
        Ok(_) => {},
        Err(e) => {
            // downcast error
            if let Some(io_err) = e.downcast_ref::<io::Error>() {
                println!("E: {:?}", io_err.to_string());
                return match io_err.kind() {
                    ErrorKind::Other => Err((StatusCode::BAD_REQUEST, "Bad password")),
                    _ => Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to update password"))
                }
            }
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to update password"))
        }
    };


    Ok(StatusCode::OK)
}