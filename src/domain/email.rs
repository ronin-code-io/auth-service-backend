use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret as _, Secret};
use validator::validate_email;

use std::hash::Hash;

#[derive(Clone, Debug)]
pub struct Email(Secret<String>);

impl PartialEq for Email {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Hash for Email {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.expose_secret().hash(state);
    }
}

impl Eq for Email {}

impl Email {
    pub fn parse(email: Secret<String>) -> Result<Self> {
        if validate_email(email.expose_secret()) {
            Ok(Self(email))
        } else {
            Err(eyre!("Invalid email".to_owned()))
        }
    }
}

impl AsRef<Secret<String>> for Email {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::Secret;

    #[test]
    fn test_valid_email() {
        let email = Email::parse(Secret::new("user@example.com".to_owned()));
        assert!(email.is_ok());
    }

    #[test]
    fn test_invalid_email() {
        let email = Email::parse(Secret::new("userexample.com".to_owned()));
        assert!(email.is_err());
    }
}
