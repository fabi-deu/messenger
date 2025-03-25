use crate::authentication::util::jwt::claims::Claims;
use crate::authentication::util::jwt::general::Token;
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::PrivateCookieJar;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RefreshToken {
    pub(crate) claims: Claims,
    pub(crate) token: String,
}


impl Token for RefreshToken {
    /// DOES NOT CHECK FOR VALIDATION
    /// exp should be long
    fn from_claims(claims: Claims, jwt_secret: &String) -> jsonwebtoken::errors::Result<Self> {
        // generate token with default headers
        let token =
            encode(&Header::default(), &claims, &EncodingKey::from_secret(jwt_secret.as_bytes()))?;
        Ok(Self {
            claims,
            token,
        })
    }

    fn from_literal(token: String, jwt_secret: &String) -> jsonwebtoken::errors::Result<Self> {
        // decode token
        let token_data = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(jwt_secret.as_bytes()),
            &Validation::default(),
        )?;
        Ok(Self {
            claims: token_data.claims,
            token,
        })
    }

    fn decode_literal(&self, jwt_secret: &String) -> jsonwebtoken::errors::Result<Claims> {
        Ok(
            decode::<Claims>(
                &self.to_string(),
                &DecodingKey::from_secret(jwt_secret.as_bytes()),
                &Validation::default(),
            )?.claims
        )
    }

    fn to_string(&self) -> String {
        self.token.clone()
    }

    fn refresh_token(self, jwt_secret: &String) -> jsonwebtoken::errors::Result<Self> {
        let old_claims = &self.claims;
        let new_claims = Claims::new(old_claims.sub, old_claims.tokenversion, 20);
        RefreshToken::from_claims(new_claims, jwt_secret)
    }
}


impl RefreshToken {
    /// retrieves token from jar
    pub fn from_jar(jar: PrivateCookieJar, jwt_secret: &String) -> Option<Self> {
        let c = jar.get("access_token")?;
        match RefreshToken::from_literal(c.value().to_string(), jwt_secret) {
            Ok(x) => Some(x),
            Err(_) => None
        }
    }
    /// generates cookie and adds it to jar
    pub fn generate_cookie(&self, jar: PrivateCookieJar) -> PrivateCookieJar {
        let token = self.to_string();
        let mut cookie = Cookie::new("refresh_token", token);
        cookie.set_http_only(true);
        cookie.set_same_site(SameSite::Strict);
        jar.add(cookie)
    }
}