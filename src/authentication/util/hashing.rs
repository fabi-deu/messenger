use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{password_hash, Algorithm, Argon2, Params, PasswordHasher, Version};

/// Hashes password with OsRng salt and default Argon2id, Version::V0x13, Params::default()
pub async fn hash_password(password: &String) -> password_hash::errors::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::default()
    );
    Ok(argon2.hash_password(password.as_bytes(), &salt)?.to_string())
}