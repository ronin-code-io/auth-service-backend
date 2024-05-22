use regex::Regex;

#[derive(PartialEq, Eq, Clone, Debug, Hash)]
pub struct Email(String);

impl Email {
    pub fn parse(email: &str) -> Result<Self, String> {
        let email_regex = Regex::new(
            r"^([a-z0-9_+]([a-z0-9_+.]*[a-z0-9_+])?)@([a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6})",
        )
        .unwrap();

        if email_regex.is_match(email) {
            Ok(Email(String::from(email)))
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
