use crate::authentication::util::jwt::claims::Claims;

pub trait Token {
    /// Returns Self from Claims
    fn from_claims(claims: Claims, jwt_secret: &String) -> jsonwebtoken::errors::Result<Self>
    where Self: Sized;
    /// Returns Self from literal JWT
    fn from_literal(token: String, jwt_secret: &String) -> jsonwebtoken::errors::Result<Self>
    where Self: Sized;
    /// Returns the literal JWT as a String
    fn decode_literal(&self, jwt_secret: &String) -> jsonwebtoken::errors::Result<Claims>;
    fn to_string(&self) -> String;
    /// Returns a new Self with updated exp and iat
    fn refresh_token(self, jwt_secret: &String) -> jsonwebtoken::errors::Result<Self>
    where Self: Sized;
}