use crate::authentication::models::appstate::AppstateWrapper;
use crate::authentication::models::auth_user::AuthUser;
use crate::authentication::models::user::User;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use axum::Extension;
use axum_extra::extract::PrivateCookieJar;
use crate::authentication::util::jwt::refresh_token::RefreshToken;

#[axum_macros::debug_middleware]
/// middleware for authenticating users based on cookie jar (refresh_token)
pub async fn refresh_token_auth_middleware(
    Extension(appstate_wrapper): Extension<AppstateWrapper>,
    mut req: Request,
    next: Next
) -> Result<Response, StatusCode> {
    let appstate = appstate_wrapper.0;
    let headers = req.headers();

    // get cookies
    let jar = PrivateCookieJar::from_headers(headers, appstate.cookie_secret.clone());
    let token = match RefreshToken::from_jar(jar, &appstate.jwt_secret) {
        None => return Err(StatusCode::UNAUTHORIZED),
        Some(token) => token,
    };

    // check for expired token
    let claims = &token.claims.clone();
    if !claims.valid_dates() {
        return Err(StatusCode::UNAUTHORIZED)
    }


    // get user from access token
    let user = match User::from_uuid(claims.sub, &appstate.db).await {
        Ok(user) => user,
        Err(sqlx::Error::Database(err)) => {
            if err.message().contains("uuid") {
                return Err(StatusCode::BAD_REQUEST)
            }
            return Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
        _ => return Err(StatusCode::INTERNAL_SERVER_ERROR)
    };

    // make sure the token-versions are the same
    if &user.tokenversion != &claims.tokenversion {
        return Err(StatusCode::UNAUTHORIZED)
    }


    // pass wrapped user to next
    req.extensions_mut().insert(AuthUser(user));
    let response = next.run(req).await;
    Ok(response)
}