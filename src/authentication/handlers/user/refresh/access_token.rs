use axum::Extension;
use axum::extract::State;
use axum::http::StatusCode;
use axum_extra::extract::PrivateCookieJar;
use crate::authentication::models::appstate::AppstateWrapper;
use crate::authentication::models::auth_user::AuthUser;

#[axum_macros::debug_handler]
/// generates a new access token
/// SET A REQUEST COOLDOWN!
pub async fn refresh_access_token(
    State(appstate_wrapper): State<AppstateWrapper>,
    auth_user: Extension<AuthUser>,
    jar: PrivateCookieJar,
) -> Result<(StatusCode, PrivateCookieJar), (StatusCode, &'static str)> {
    let appstate = appstate_wrapper.0;
    let user = auth_user.0.0;

    // generate new cookie
    let token = match user.generate_access_token(&appstate.jwt_secret) {
        None => return Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate new token")),
        Some(token) => token,
    };

    // add cookie
    let jar = token.generate_cookie(jar);
    
    Ok((StatusCode::OK, jar))
}