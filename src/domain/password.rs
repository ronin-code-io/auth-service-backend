#[derive(PartialEq, Eq, Clone, Debug, Hash)]
pub struct Password(String);

impl Password {
    pub fn parse(password: &str) -> Result<Self, String> {
        if password.len() >= 8 {
            Ok(Password(String::from(password)))
        } else {
            Err(format!("Invalid password.",))
        }
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_password() {
        let password = Password::parse("password");
        assert!(password.is_ok());
        assert_eq!(password.unwrap().as_ref(), "password");
    }

    #[test]
    fn test_invalid_password() {
        let password = Password::parse("not");
        assert!(password.is_err());
    }
}
