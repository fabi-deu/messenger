use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum_extra::extract::PrivateCookieJar;
use serde::{Deserialize, Serialize};
use crate::authentication::models::appstate::AppstateWrapper;
use crate::authentication::models::user::User;

#[derive(Serialize, Deserialize)]
pub struct Body {
    username: String,
    password: String,
}

#[axum_macros::debug_handler]
pub async fn refresh_refresh_token(
    State(appstate_wrapper): State<AppstateWrapper>,
    jar: PrivateCookieJar,
    Json(body): Json<Body>,
) -> Result<(StatusCode, PrivateCookieJar), (StatusCode, &'static str)> {
    let appstate = appstate_wrapper.0;
    let (username, password) = (body.username, body.password);

    // get user
    let user = User::login(username, password, &appstate.db).await?;

    // generate new token
    let token = match user.generate_refresh_token(&appstate.jwt_secret) {
        None => return Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate refresh token")),
        Some(token) => token,
    };

    // add cookie
    let jar = token.generate_cookie(jar);

    Ok((StatusCode::OK, jar))
}