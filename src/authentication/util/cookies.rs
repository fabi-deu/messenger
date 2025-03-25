use crate::authentication::models::appstate::Appstate;
use crate::authentication::models::user::User;
use axum::http::StatusCode;
use axum_extra::extract::PrivateCookieJar;

/// generates both access and refresh token for user and adds it to the cookie jar, which is returned
pub fn generate_cookies(user: &User, jar: PrivateCookieJar, appstate: &Appstate) -> Result<PrivateCookieJar, (StatusCode, &'static str)> {
    let access_token = match user.generate_access_token(&appstate.jwt_secret) {
        Some(access_token) => access_token,
        None => return Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate access token please log in manually"))
    };
    let refresh_token = match user.generate_refresh_token(&appstate.jwt_secret) {
        Some(r_token) => r_token,
        None => return Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate refresh token please log in manually"))
    };

    let jar = access_token.generate_cookie(jar);
    let jar = refresh_token.generate_cookie(jar);

    Ok(jar)
}
