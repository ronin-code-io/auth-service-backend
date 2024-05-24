use validator::validate_email;

#[derive(PartialEq, Eq, Clone, Debug, Hash)]
pub struct Email(String);

impl Email {
    pub fn parse(email: &str) -> Result<Self, String> {
        if validate_email(email) {
            Ok(Self(String::from(email)))
        } else {
            Err(format!("Invalid email: {}", email))
        }
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_email() {
        let email = Email::parse("user@example.com");
        assert!(email.is_ok());
        assert_eq!(email.unwrap().as_ref(), "user@example.com");
    }

    #[test]
    fn test_invalid_email() {
        let email = Email::parse("userexample.com");
        assert!(email.is_err());
    }
}
