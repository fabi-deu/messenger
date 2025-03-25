
/// Validates username based on contained chars and length  \
/// *allowed chars*:                                        \
/// a-z A-Z . _ - 0-9                                       \
/// *allowed length*: 3-16 chars
pub fn valid_username(username: &String) -> bool {
    if username.len() > 16 || username.len() < 3 {
        return false
    }

    let allowed = username.chars().all(|c| {
        matches!(c,
        'a'..='z' |
        'A'..='Z' |
        '0'..='9' |
        '.' | '_' | '-'
        )
    });
    allowed
}



/// Validates password based on contained chars and length  \
/// *allowed chars*:                                        \
/// a-z A-Z . _ - * # ? $ % & ! / 0-9                       \
/// *allowed length*: 8-50 chars
pub fn valid_password(password: &String) -> bool {
    // should probably rewrite this entire function for better performance and such

    if password.len() > 50 || password.len() < 8 {
        return false
    }

    let (mut has_lowercase, mut has_uppercase, mut has_digit, mut has_special) = (false,false,false,false);
    const SPECIAL_CHARS: [char; 9] = ['.', '-', '_', '*', '#', '%', '&', '$', '?'];

    for c in password.chars() {
        if !c.is_ascii_alphanumeric() && !SPECIAL_CHARS.contains(&c) {
            return false;
        }

        // update requirement flags
        if c.is_ascii_lowercase() {
            has_lowercase = true;
        } else if c.is_ascii_uppercase() {
            has_uppercase = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else if SPECIAL_CHARS.contains(&c) {
            has_special = true;
        }

        // early return if all requirements are met
        if has_lowercase && has_uppercase && has_digit && has_special {
            return true;
        }
    }

    has_lowercase && has_uppercase && has_digit && has_special
}