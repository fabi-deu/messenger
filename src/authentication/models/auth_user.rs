use std::future::{ready, Future};
use std::ops::Deref;
use async_trait::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use serde::{Serialize};
use crate::authentication::models::user::User;


/// Wrapper for User to handle middleware
#[derive(Serialize, Debug, Clone)]
pub struct AuthUser(pub(crate) User);

impl Deref for AuthUser {
    type Target = User;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}



#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync
{
    type Rejection = StatusCode;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let user = parts
            .extensions
            .get::<User>()
            .cloned()
            .map(AuthUser)
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR);

        ready(user)
    }
}