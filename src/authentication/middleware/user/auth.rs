use crate::authentication::models::appstate::AppstateWrapper;
use crate::authentication::models::auth_user::AuthUser;
use crate::authentication::models::user::User;
use crate::authentication::util::jwt::access_token::AccessToken;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use axum::Extension;
use axum_extra::extract::PrivateCookieJar;

#[axum_macros::debug_middleware]
/// middleware for authenticating users based on cookie jar
pub async fn auth_middleware(
    Extension(appstate_wrapper): Extension<AppstateWrapper>,
    mut req: Request,
    next: Next
) -> Result<Response, StatusCode> {
    let appstate = appstate_wrapper.0;
    let headers = req.headers();

    // get cookies
    let jar = PrivateCookieJar::from_headers(headers, appstate.cookie_secret.clone());
    let token = match AccessToken::from_jar(jar, &appstate.jwt_secret) {
        None => return Err(StatusCode::UNAUTHORIZED),
        Some(token) => token,
    };

    // check for expired token
    // TODO ! automatically generate new token if expired
    let claims = &token.claims.clone();
    if !claims.valid_dates() {
        return Err(StatusCode::UNAUTHORIZED)
    }


    // get user from access token
    let user = match User::from_access_token(token, &appstate.db).await {
        Ok(some_user) => {
            match some_user {
                Some(user) => user,
                _ => return Err(StatusCode::UNAUTHORIZED)
            }
        }
        Err(_) => return Err(StatusCode::BAD_REQUEST)
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