// token check. we hash both sides and compare the digests in constant time.
// comparing the raw bytes would leak the token length and would bail early on the first
// wrong byte, which is enough to walk the secret out one character at a time.
// the token only ever comes from the environment so it does not end up in a config file
// that somebody commits by accident.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const TOKEN_ENV: &str = "MARIANA_TOKEN";
const MIN_TOKEN_BYTES: usize = 16;

pub struct Token([u8; 32]);

impl Token {
    pub fn new(secret: &[u8]) -> Token {
        Token(Sha256::digest(secret).into())
    }

    pub fn from_env() -> Result<Option<Token>, String> {
        let raw = match std::env::var(TOKEN_ENV) {
            Ok(value) => value,
            Err(_) => return Ok(None),
        };
        if raw.len() < MIN_TOKEN_BYTES {
            return Err(format!(
                "{TOKEN_ENV} must be at least {MIN_TOKEN_BYTES} characters"
            ));
        }
        Ok(Some(Token::new(raw.as_bytes())))
    }

    pub fn verify(&self, presented: &[u8]) -> bool {
        let digest: [u8; 32] = Sha256::digest(presented).into();
        self.0.ct_eq(&digest).into()
    }
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Token(redacted)")
    }
}

#[cfg(test)]
mod tests {
    use super::Token;

    #[test]
    fn accepts_the_right_secret_only() {
        let token = Token::new(b"correct horse battery staple");
        assert!(token.verify(b"correct horse battery staple"));
        assert!(!token.verify(b"correct horse battery stapl"));
        assert!(!token.verify(b""));
        assert!(!token.verify(b"correct horse battery staple "));
    }

    #[test]
    fn debug_does_not_leak() {
        let token = Token::new(b"hunter2hunter2hunter2");
        assert_eq!(format!("{token:?}"), "Token(redacted)");
    }
}
