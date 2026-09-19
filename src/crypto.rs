use std::io::{Read, Write};
use std::str::FromStr;

use anyhow::{Context, Result};

/// Encrypts `plaintext` to a set of age recipients (public keys, `age1...`).
/// Output is armored (ASCII, git-diff-friendly-ish, and greppable) rather
/// than binary — a deliberate choice for a tool whose whole output ends up
/// committed to git.
pub fn encrypt(plaintext: &[u8], recipient_strings: &[String]) -> Result<Vec<u8>> {
    if recipient_strings.is_empty() {
        anyhow::bail!("no recipients given — see `cryptenv keygen` and `.cryptenv-recipients`");
    }
    let recipients: Vec<age::x25519::Recipient> = recipient_strings
        .iter()
        .map(|s| {
            age::x25519::Recipient::from_str(s)
                .map_err(|e| anyhow::anyhow!("invalid recipient '{s}': {e}"))
        })
        .collect::<Result<_>>()?;
    let recipient_refs: Vec<&dyn age::Recipient> = recipients
        .iter()
        .map(|r| r as &dyn age::Recipient)
        .collect();

    let encryptor = age::Encryptor::with_recipients(recipient_refs.into_iter())
        .context("building encryptor (need at least one recipient)")?;

    let mut output = Vec::new();
    {
        let mut armored =
            age::armor::ArmoredWriter::wrap_output(&mut output, age::armor::Format::AsciiArmor)?;
        let mut writer = encryptor.wrap_output(&mut armored)?;
        writer.write_all(plaintext)?;
        writer.finish()?;
        armored.finish()?;
    }
    Ok(output)
}

/// The marker every armored age file starts with (`age::armor`'s own
/// constant isn't public, but the format is fixed by the age spec, and
/// `simple.rs`'s own doctest in the `age` crate asserts the same string).
const ARMOR_MARKER: &str = "-----BEGIN AGE ENCRYPTED FILE-----";

/// True if `data` looks like an armored age file, i.e. it's already
/// ciphertext `cryptenv` (or the real `age`/`rage` CLI) produced. Used by
/// the git clean/smudge filters to stay idempotent: a clean filter must
/// not re-encrypt its own output, and a smudge filter must not try to
/// decrypt content that was never encrypted (or was already decrypted).
/// Leading blank lines/whitespace are tolerated since editors and shells
/// sometimes introduce them without meaning to change the content.
pub fn looks_like_age_armor(data: &[u8]) -> bool {
    let trimmed = {
        let mut i = 0;
        while i < data.len() && matches!(data[i], b'\n' | b'\r' | b' ' | b'\t') {
            i += 1;
        }
        &data[i..]
    };
    trimmed.starts_with(ARMOR_MARKER.as_bytes())
}

/// Decrypts age-armored ciphertext with the first identity (of possibly
/// several) it was actually encrypted for.
pub fn decrypt(ciphertext: &[u8], identities: &[age::x25519::Identity]) -> Result<Vec<u8>> {
    if identities.is_empty() {
        anyhow::bail!("no identities given — see `cryptenv keygen`");
    }
    let armored = age::armor::ArmoredReader::new(ciphertext);
    let decryptor = age::Decryptor::new(armored).context("reading age header")?;

    let identity_refs: Vec<&dyn age::Identity> =
        identities.iter().map(|i| i as &dyn age::Identity).collect();

    let mut reader = decryptor
        .decrypt(identity_refs.into_iter())
        .context("no matching identity for this ciphertext's recipients")?;
    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext)?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{generate_identity, public_string};

    #[test]
    fn encrypt_then_decrypt_round_trips() {
        let id = generate_identity();
        let recipients = vec![public_string(&id)];
        let plaintext = b"DATABASE_URL=postgres://secret\nAPI_KEY=sk-abc123\n";

        let ciphertext = encrypt(plaintext, &recipients).unwrap();
        assert_ne!(ciphertext, plaintext, "ciphertext must not equal plaintext");
        assert!(
            !String::from_utf8_lossy(&ciphertext).contains("sk-abc123"),
            "the secret value must not appear in ciphertext"
        );

        let decrypted = decrypt(&ciphertext, &[id]).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_identity_cannot_decrypt() {
        let id_a = generate_identity();
        let id_b = generate_identity();
        let recipients = vec![public_string(&id_a)];
        let ciphertext = encrypt(b"top secret", &recipients).unwrap();

        let result = decrypt(&ciphertext, &[id_b]);
        assert!(
            result.is_err(),
            "an unrelated identity must not decrypt this"
        );
    }

    #[test]
    fn multiple_recipients_each_independently_decrypt() {
        let id_a = generate_identity();
        let id_b = generate_identity();
        let recipients = vec![public_string(&id_a), public_string(&id_b)];
        let ciphertext = encrypt(b"shared secret", &recipients).unwrap();

        assert_eq!(decrypt(&ciphertext, &[id_a]).unwrap(), b"shared secret");
        assert_eq!(decrypt(&ciphertext, &[id_b]).unwrap(), b"shared secret");
    }

    #[test]
    fn rejects_when_no_recipients_given() {
        assert!(encrypt(b"anything", &[]).is_err());
    }

    #[test]
    fn looks_like_age_armor_recognizes_real_ciphertext() {
        let id = generate_identity();
        let ciphertext = encrypt(b"hello", &[public_string(&id)]).unwrap();
        assert!(looks_like_age_armor(&ciphertext));
    }

    #[test]
    fn looks_like_age_armor_rejects_plaintext() {
        assert!(!looks_like_age_armor(b"DATABASE_URL=postgres://secret\n"));
        assert!(!looks_like_age_armor(b""));
    }

    #[test]
    fn looks_like_age_armor_tolerates_leading_whitespace() {
        let id = generate_identity();
        let ciphertext = encrypt(b"hello", &[public_string(&id)]).unwrap();
        let mut padded = b"\n\n  ".to_vec();
        padded.extend_from_slice(&ciphertext);
        assert!(looks_like_age_armor(&padded));
    }
}
