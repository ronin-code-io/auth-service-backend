use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret, Secret};

#[derive(Clone, Debug)]
pub struct Password(Secret<String>);

impl Password {
    pub fn parse(password: Secret<String>) -> Result<Self> {
        if validate_password(&password) {
            Ok(Self(password))
        } else {
            Err(eyre!("Failed to parse string to Password type."))
        }
    }
}

impl PartialEq for Password {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl AsRef<Secret<String>> for Password {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

fn validate_password(s: &Secret<String>) -> bool {
    s.expose_secret().len() >= 8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string_is_rejected() {
        let password = Secret::new("".to_string());
        assert!(Password::parse(password).is_err());
    }

    #[test]
    fn string_less_than_8_characters_is_rejected() {
        let password = Secret::new("1234567".to_string());
        assert!(Password::parse(password).is_err());
    }

    #[test]
    fn string_with_at_least_8_characters_are_ok() {
        let password = Secret::new("12345678".to_string());
        assert!(Password::parse(password).is_ok());
    }
}
