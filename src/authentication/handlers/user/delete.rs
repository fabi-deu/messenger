use axum::{Extension, Json};
use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use crate::authentication::models::appstate::AppstateWrapper;
use crate::authentication::models::auth_user::AuthUser;

#[derive(Serialize, Deserialize)]
pub struct Body {
    password: String,
}



/// POST
/// Handler for deleting user,
/// checks by confirming password
pub async fn delete_user(
    State(appstate_wrapper): State<AppstateWrapper>,
    auth_user: Extension<AuthUser>,
    Json(body): Json<Body>
) -> Result<StatusCode, (StatusCode, &'static str)> {
    let appstate = appstate_wrapper.0;
    let user = auth_user.0.0;

    // verify password
    match user.verify_password(body.password) {
        Ok(is_correct) => {
            if !is_correct {
                return Err((StatusCode::UNAUTHORIZED, "Wrong password"))
            }
        }
        Err(_) => return Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to verify password"))
    }

    // delete user
    if let Err(_) = user.delete_from_db(&appstate.db).await {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to delete from db"))
    }


    Ok(StatusCode::OK)
}