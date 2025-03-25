use std::sync::Arc;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite};
use uuid::Uuid;
use crate::authentication::models::user::User;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Claims {
    pub(crate) sub: Uuid,
    pub(crate) tokenversion: u64,
    pub(crate) iat: u64,
    pub(crate) exp: u64,
}


impl Claims {
    /// returns Claims
    /// * `exp` - Describes in how many minutes the token will expire
    pub fn new(sub: Uuid, tokenversion: u64, exp: u64) -> Self {
        Self {
            sub,
            tokenversion,
            iat: Utc::now().timestamp() as u64,
            exp: Utc::now().timestamp() as u64 + exp*60,
        }
    }
    /// returns claims made for user
    /// * `exp` - Describes in how many minutes the token will expire
    pub fn from_user(user: &User, exp: u64) -> Self {
        Self {
            sub: user.uuid.into_uuid(),
            tokenversion: user.tokenversion,
            iat: Utc::now().timestamp() as u64,
            exp: Utc::now().timestamp() as u64 + exp*60,
        }
    }

    pub fn valid_dates(&self) -> bool {
        let now = Utc::now().timestamp() as u64;
        if self.exp <  now {
            return false
        }
        if self.iat > now {
            return false
        }

        true
    }

    /// `alias` - [`User::from_claims`]
    pub async fn get_user(&self, conn: &Arc<Pool<Sqlite>>) -> Result<User, sqlx::Error> {
        User::from_claims(self.clone(), conn).await
    }
}