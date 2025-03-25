use crate::authentication::models::appstate::AppstateWrapper;
use crate::authentication::models::user::User;
use crate::authentication::util::cookies::generate_cookies;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum_extra::extract::PrivateCookieJar;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Body {
    username: String,
    password: String,
}

/// login handler
#[axum_macros::debug_handler]
pub async fn login(
    State(appstate_wrapper): State<AppstateWrapper>,
    jar: PrivateCookieJar,
    Json(body): Json<Body>
) -> Result<(StatusCode, PrivateCookieJar), (StatusCode, &'static str)> {
    let appstate = appstate_wrapper.0;
    let (username, password) = (body.username, body.password);

    // login user
    let user = User::login(username, password, &appstate.db).await?;

    // set up cookies
    let jar = generate_cookies(&user, jar, &appstate)?;

    Ok((StatusCode::OK, jar))
}