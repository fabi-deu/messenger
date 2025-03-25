use crate::authentication::models::auth_user::AuthUser;
use crate::authentication::models::user::User;
use axum::{Extension, Json};


#[axum_macros::debug_handler]
pub async fn auth_test(
    user: Extension<AuthUser>,
) -> Json<User> {
    Json(user.0.0)
}