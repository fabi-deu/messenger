use crate::authentication::models::user_permission::Permission;
use crate::authentication::util::jwt::access_token::AccessToken;
use crate::authentication::util::jwt::claims::Claims;
use crate::authentication::util::jwt::refresh_token::RefreshToken;
use argon2::{password_hash, Algorithm, Argon2, Params, PasswordHash, PasswordVerifier, Version};
use serde::Serialize;
use sqlx::{FromRow, Pool, Sqlite};
use std::error::Error;
use std::sync::Arc;
use axum::http::StatusCode;
use uuid::Uuid;
use crate::authentication::util::hashing::hash_password;
use crate::authentication::util::jwt::general::Token;
use crate::authentication::util::validation::{valid_password, valid_username};

#[derive(Clone, Debug, Serialize, FromRow)]
pub struct User {
    pub(crate) uuid: uuid::fmt::Hyphenated,
    pub(crate) username: String,
    password: String,
    pub(crate) email: String,

    pub(crate) permission: Permission,
    pub(crate) tokenversion: u64,
    pub(crate) timestamp: u64,
}


impl User {
    pub fn new(username: String, password: String, email: String) -> Self {
        Self {
            uuid: Uuid::new_v4().hyphenated(),
            username,
            password,
            email,
            permission: Permission::USER,
            tokenversion: 0,
            timestamp: chrono::Utc::now().timestamp() as u64,
        }
    }

    /// gets user by token
    pub async fn from_access_token(token: AccessToken, conn: &Arc<Pool<Sqlite>>) -> Result<Option<Self>, Box<dyn Error>> {
        // validate claims
        let claims = token.claims;
        if !claims.valid_dates() {
            return Ok(None)
        }
        // get user
        let user = Self::from_claims(claims.clone(), conn).await?;
        // check for tokenversion
        if &claims.tokenversion != &user.tokenversion {
            return Ok(None)
        }
        Ok(Some(user))
    }

    /// gets user from db with uuid form claims
    /// DOES NOT CHECK FOR VALIDATION
    pub async fn from_claims(claims: Claims, conn: &Arc<Pool<Sqlite>>) -> Result<Self, sqlx::Error> {
        let uuid = claims.sub;
        Self::from_uuid(uuid, conn).await
    }

    pub async fn from_username(username: String, conn: &Arc<Pool<Sqlite>>) -> Result<Self, sqlx::Error> {
        let query = r"SELECT * FROM users WHERE username = ?";
        let user = sqlx::query_as::<_, Self>(query)
            .bind(username)
            .fetch_one(conn.as_ref())
            .await?;
        Ok(user)
    }

    pub async fn from_uuid(uuid: Uuid, conn: &Arc<Pool<Sqlite>>) -> Result<Self, sqlx::Error> {
        let query = r"SELECT * FROM users WHERE uuid = ?";
        let user = sqlx::query_as::<_, Self>(query)
            .bind(uuid.hyphenated().to_string())
            .fetch_one(conn.as_ref())
            .await?;
        Ok(user)
    }

    /// writes user to db
    pub async fn write_to_db(&self, conn: &Arc<Pool<Sqlite>>) -> Result<(), sqlx::Error> {
        let query =
            r"INSERT INTO users (uuid, username, email, password, permission, tokenversion, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)";

        let _ = sqlx::query(query)
            .bind(&self.uuid.to_string())
            .bind(&self.username)
            .bind(&self.email)
            .bind(&self.password)
            .bind(&self.permission.to_string())
            .bind(self.tokenversion.clone() as u32) // we have to parse as u32 here as u64 doesn't meet trait requirements
            .bind(self.timestamp.clone() as u32).execute(conn.as_ref()).await?;

        Ok(())
    }

    /// deletes from db
    pub async fn delete_from_db(&self, conn: &Arc<Pool<Sqlite>>) -> Result<(), sqlx::Error> {
        let query = "DELETE FROM users WHERE uuid = ?";
        let _ = sqlx::query(query)
            .bind(&self.uuid)
            .execute(conn.as_ref())
            .await?;

        Ok(())
    }

    /// generates access token (exp in 20 minutes) for user
    pub fn generate_access_token(&self, jwt_secret: &String) -> Option<AccessToken> {
        let claims = Claims::from_user(&self, 20);
        match AccessToken::from_claims(claims, jwt_secret) {
            Ok(token) => Some(token),
            _ => None,
        }
    }

    /// generates refresh token (exp in 1y) for user
    pub fn generate_refresh_token(&self, jwt_secret: &String) -> Option<RefreshToken> {
        let claims = Claims::from_user(&self, 525600); // 525600 = 60*24*365 = 1year
        match RefreshToken::from_claims(claims, jwt_secret) {
            Ok(token) => Some(token),
            _ => None
        }
    }


    /// verifies passwords
    pub fn verify_password(&self, attempt: String) -> password_hash::errors::Result<bool> {
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::default()
        );
        let self_parsed = PasswordHash::new(&self.password)?;
        Ok(argon2.verify_password(attempt.as_bytes(), &self_parsed).is_ok())
    }

    /// log in functionality by using password and username
    pub async fn login(username: String, password: String, conn: &Arc<Pool<Sqlite>>) -> Result<Self, (StatusCode, &'static str)> {
        // fetch user from db
        let user: Self = match Self::from_username(username, conn).await {
            Ok(user) => user,
            // technically this could also be a db error, but realistically it's the users false input
            Err(_) => return Err((StatusCode::BAD_REQUEST, "Failed to fetch user from db (most likely bad username)"))
        };


        // compare passwords and return
        match user.verify_password(password) {
            Ok(true) => Ok(user),
            Ok(false) => Err((StatusCode::BAD_REQUEST, "Wrong password")),
            Err(_) => Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to verify password")),
        }
    }

    /// updates field in db
    pub async fn update_password(&self, new_password_string: String, conn: &Arc<Pool<Sqlite>>) -> Result<Self, Box<dyn Error>> {
        // validate password
        if !valid_password(&new_password_string) {
            return Err(
                Box::new(
                    std::io::Error::new(
                        std::io::ErrorKind::Other, "password is not valid"
                    )
                )
            )
        }
        // hash password
        let hashed_password = match hash_password(&new_password_string).await {
            Ok(x) => x,
            Err(_) => return Err(
                Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Failed to hash password")))
        };

        // update
        let query = r"UPDATE users SET password = ? WHERE uuid = ?";
        let _ = sqlx::query(query)
            .bind(hashed_password.to_string())
            .bind(&self.uuid)
            .execute(conn.as_ref()).await?;

        // get new user model
        let new_user = Self::from_uuid(self.uuid.into_uuid(), conn).await?;

        // update tokenversion
        let new_user = new_user.update_tokenversion(conn).await?;

        Ok(new_user)
    }

    /// update username in db
    pub async fn update_username(&self, username: String, conn: &Arc<Pool<Sqlite>>) -> Result<Self, Box<dyn Error>> {
        // validate username
        if !valid_username(&username) {
            return Err(
                Box::new(
                    std::io::Error::new(
                        std::io::ErrorKind::Other, "Username is not valid"
                    )
                )
            )
        }

        // update
        let query = r"UPDATE users SET username = ? WHERE uuid = ?";
        let _ = sqlx::query(query)
            .bind(&username)
            .bind(&self.uuid)
            .execute(conn.as_ref()).await?;

        let new_user = Self::from_username(username, conn).await?;
        Ok(new_user)
    }

    // updates tokenversion in db
    pub async fn update_tokenversion(&self, conn: &Arc<Pool<Sqlite>>) -> Result<Self, Box<dyn Error>> {
        let query = r"UPDATE users SET tokenversion = ? WHERE uuid = ?";
        let _ = sqlx::query(query)
            .bind(self.tokenversion as u32)
            .bind(&self.uuid)
            .execute(conn.as_ref()).await?;

        Ok(Self { tokenversion: self.tokenversion + 1, ..self.clone() })
    }
}