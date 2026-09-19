use std::path::PathBuf;
use std::str::FromStr;

use age::secrecy::ExposeSecret;
use anyhow::{Context, Result};

pub fn default_identity_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("cryptenv")
        .join("key.txt")
}

pub fn generate_identity() -> age::x25519::Identity {
    age::x25519::Identity::generate()
}

pub fn identity_secret_string(id: &age::x25519::Identity) -> String {
    id.to_string().expose_secret().to_string()
}

pub fn public_string(id: &age::x25519::Identity) -> String {
    id.to_public().to_string()
}

/// Parses an age identity file: one `AGE-SECRET-KEY-1...` key per line,
/// blank lines and `#`-comments ignored — the same format the real `age`
/// CLI writes and reads, so a `cryptenv keygen`-generated file works with
/// plain `age -d -i key.txt` too, and vice versa.
pub fn parse_identity_file(contents: &str) -> Result<Vec<age::x25519::Identity>> {
    contents
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|line| {
            age::x25519::Identity::from_str(line)
                .map_err(|e| anyhow::anyhow!("invalid identity line: {e}"))
        })
        .collect::<Result<Vec<_>>>()
        .context("parsing identity file")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_identity_round_trips_through_its_own_string_form() {
        let id = generate_identity();
        let secret = identity_secret_string(&id);
        let parsed = parse_identity_file(&secret).unwrap();
        assert_eq!(parsed.len(), 1);
        // Two identities parsed from the same secret must produce the same
        // public key — that's the whole point of a deterministic keypair.
        assert_eq!(public_string(&parsed[0]), public_string(&id));
    }

    #[test]
    fn identity_file_parsing_skips_blanks_and_comments() {
        let id = generate_identity();
        let secret = identity_secret_string(&id);
        let contents = format!("# my laptop key\n\n{secret}\n");
        let parsed = parse_identity_file(&contents).unwrap();
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn public_key_has_the_age1_prefix() {
        let id = generate_identity();
        assert!(public_string(&id).starts_with("age1"));
    }
}
