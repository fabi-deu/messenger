use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum_extra::extract::PrivateCookieJar;
use serde::{Deserialize, Serialize};
use sqlx::Error;
use crate::authentication::models::appstate::{AppstateWrapper};
use crate::authentication::models::user::User;
use crate::authentication::util::cookies::generate_cookies;
use crate::authentication::util::hashing::hash_password;
use crate::authentication::util::validation::{valid_password, valid_username};

#[derive(Serialize, Deserialize)]
pub struct Body {
    username: String,
    password: String,
    email: String,
}

/// Handler for creating new user
#[axum_macros::debug_handler]
pub async fn create_new_user(
    State(appstate_wrapper): State<AppstateWrapper>,
    jar: PrivateCookieJar,
    Json(body): Json<Body>
) -> Result<(StatusCode, PrivateCookieJar), (StatusCode, &'static str)> {
    let appstate = appstate_wrapper.0;

    // validate password and username
    if !valid_username(&body.username) {
        return Err((StatusCode::BAD_REQUEST, "Bad username (do specific checks on frontend)"))
    }
    if !valid_password(&body.password)  {
        return Err((StatusCode::BAD_REQUEST, "Bad password (do specific checks on frontend)"))
    }
    // ! TODO email validation

    // hash password and create user model
    let hashed_password = match hash_password(&body.password).await {
        Ok(o) => o,
        Err(_) => return Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to hash password")),
    };

    // create user
    let user = User::new(body.username, hashed_password, body.email);

    // add user to db
    // *I don't like this handling*
    let query = user.write_to_db(&appstate.db);
    match query.await {
        Ok(_) => {},
        Err(Error::Database(db_err)) => {
            return if db_err.message().contains("email") {
                Err((StatusCode::BAD_REQUEST, "Email is already in use"))
            } else if db_err.message().contains("username") {
                Err((StatusCode::BAD_REQUEST, "Username is already taken"))
            } else {
                Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to write to db"))
            }
        }
        _ => return Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to write to db"))
    }

    // set cookies
    let jar = generate_cookies(&user, jar, &appstate)?;

    Ok((StatusCode::CREATED, jar))
}