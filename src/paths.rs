use std::path::{Path, PathBuf};

pub const ENCRYPTED_SUFFIX: &str = ".age";
pub const RECIPIENTS_FILENAME: &str = ".cryptenv-recipients";

/// `.env` -> `.env.age`. If the path already ends in `.age` it's returned
/// unchanged (idempotent, so `cryptenv encrypt .env.age` doesn't produce
/// `.env.age.age` by accident).
pub fn encrypted_path(plain: &Path) -> PathBuf {
    if plain.extension().and_then(|e| e.to_str()) == Some("age") {
        return plain.to_path_buf();
    }
    let mut s = plain.as_os_str().to_owned();
    s.push(ENCRYPTED_SUFFIX);
    PathBuf::from(s)
}

/// `.env.age` -> `.env`. For anything not ending in `.age`, appends
/// `.dec` rather than guessing, so a decrypt never silently overwrites a
/// same-named plaintext file that wasn't the pair this ciphertext came from.
pub fn decrypted_path(encrypted: &Path) -> PathBuf {
    let s = encrypted.as_os_str().to_string_lossy();
    match s.strip_suffix(ENCRYPTED_SUFFIX) {
        Some(stripped) => PathBuf::from(stripped),
        None => {
            let mut p = encrypted.to_path_buf();
            p.set_extension("dec");
            p
        }
    }
}

/// The recipients file cryptenv looks for next to the target file when no
/// `-r`/`--recipients-file` flag is given: same directory, fixed name.
pub fn default_recipients_file(target: &Path) -> PathBuf {
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    dir.join(RECIPIENTS_FILENAME)
}

/// One recipient per line; blank lines and `#`-prefixed comments ignored.
/// Same shape as an SSH `authorized_keys` file, deliberately, since that's
/// the format most people already have muscle memory for.
pub fn parse_recipients_file(contents: &str) -> Vec<String> {
    contents
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_path_appends_suffix() {
        assert_eq!(encrypted_path(Path::new(".env")), PathBuf::from(".env.age"));
        assert_eq!(
            encrypted_path(Path::new("secrets/prod.yaml")),
            PathBuf::from("secrets/prod.yaml.age")
        );
    }

    #[test]
    fn encrypted_path_is_idempotent() {
        assert_eq!(
            encrypted_path(Path::new(".env.age")),
            PathBuf::from(".env.age")
        );
    }

    #[test]
    fn decrypted_path_strips_suffix() {
        assert_eq!(decrypted_path(Path::new(".env.age")), PathBuf::from(".env"));
        assert_eq!(
            decrypted_path(Path::new("secrets/prod.yaml.age")),
            PathBuf::from("secrets/prod.yaml")
        );
    }

    #[test]
    fn decrypted_path_of_non_age_file_does_not_guess() {
        // Must not silently produce ".env" from something that was never
        // ".env.age" in the first place.
        assert_eq!(decrypted_path(Path::new(".env")), PathBuf::from(".env.dec"));
    }

    #[test]
    fn recipients_file_parsing_skips_blanks_and_comments() {
        let contents = "\n# alice's laptop\nage1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\n\n  # bob\nage1rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr  \n";
        let parsed = parse_recipients_file(contents);
        assert_eq!(
            parsed,
            vec![
                "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".to_string(),
                "age1rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr".to_string(),
            ]
        );
    }

    #[test]
    fn default_recipients_file_is_a_sibling() {
        assert_eq!(
            default_recipients_file(Path::new("apps/roasted/.env")),
            PathBuf::from("apps/roasted/.cryptenv-recipients")
        );
    }
}
