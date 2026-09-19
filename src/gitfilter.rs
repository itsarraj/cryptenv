//! The logic behind `cryptenv git-clean` / `cryptenv git-smudge` — the two
//! ends of a git filter driver (see `gitattributes(5)`, "Filters"). git
//! pipes a blob's content into the filter's stdin and takes the filter's
//! stdout as the replacement content, one direction on `git add`/`commit`
//! (clean: worktree -> object database) and the other on
//! `git checkout`/`clone` (smudge: object database -> worktree).
//!
//! This module only holds the pure content transforms (bytes in, bytes
//! out, no stdio) so they're unit-testable without spawning a process or a
//! real git repo — `main.rs` does the actual stdin/stdout plumbing and
//! wires up recipients/identities the same way `encrypt`/`decrypt` do.
//!
//! Two edge cases drive the shape of this module, both called out in the
//! README's git-filter section:
//!
//! - `git diff` (and `git status`, internally) also invokes the *clean*
//!   filter, to compare the worktree's cleaned content against what's
//!   already in the index/object database. If clean re-encrypted content
//!   that's already ciphertext (e.g. because smudge left ciphertext behind
//!   per the next point), every diff would show a full-file change even
//!   with nothing edited, since age's output isn't deterministic (fresh
//!   ephemeral key per encryption). So `clean` must be idempotent: if the
//!   input already looks like armored age ciphertext, pass it through
//!   unchanged instead of re-encrypting it.
//! - A checkout/clone on a machine with no identity available (a CI
//!   runner that only needs to read the encrypted file, not decrypt it)
//!   must not fail or hang. `smudge` never treats "no usable identity" or
//!   "decryption failed" as an error it propagates — it logs why (via the
//!   `PassedThrough` reason, which `main.rs` prints to stderr) and passes
//!   the ciphertext through unchanged, leaving `.env` as armored
//!   ciphertext in the working tree rather than blocking the checkout.
//!   The corresponding `filter.cryptenv.required = true` git config (set
//!   by `cryptenv filter install`) then only ever blocks on a *clean*
//!   failure (e.g. no `.cryptenv-recipients` file — see
//!   `resolve_recipients` in `main.rs`), which is the direction where
//!   failing loudly matters: a clean that silently fell back to
//!   unfiltered content would commit plaintext straight into the object
//!   database. Smudge is designed to never hit that non-zero-exit path
//!   for the missing-identity case in the first place, so the same
//!   `required = true` setting cannot block a checkout on it.

use anyhow::Result;

use crate::crypto;

/// Outcome of running the clean filter (worktree content -> what gets
/// stored in the object database).
#[derive(Debug, PartialEq, Eq)]
pub enum CleanOutcome {
    /// Input was plaintext; this is its freshly encrypted form.
    Encrypted(Vec<u8>),
    /// Input already looked like armored age ciphertext; returned
    /// unchanged so clean(clean(x)) == clean(x).
    AlreadyEncrypted(Vec<u8>),
}

impl CleanOutcome {
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            CleanOutcome::Encrypted(b) | CleanOutcome::AlreadyEncrypted(b) => b,
        }
    }
}

/// Runs the clean-filter transform: encrypt `input` to `recipients`,
/// unless it's already ciphertext. Errors (no recipients, an invalid
/// recipient string) are real failures — `main.rs` exits non-zero on
/// them, and with `filter.cryptenv.required = true` that blocks the
/// `git add`/`commit` rather than letting plaintext slip into a blob.
pub fn clean(input: &[u8], recipients: &[String]) -> Result<CleanOutcome> {
    if crypto::looks_like_age_armor(input) {
        return Ok(CleanOutcome::AlreadyEncrypted(input.to_vec()));
    }
    let ciphertext = crypto::encrypt(input, recipients)?;
    Ok(CleanOutcome::Encrypted(ciphertext))
}

/// Outcome of running the smudge filter (object database content ->
/// what's written to the worktree).
#[derive(Debug, PartialEq, Eq)]
pub enum SmudgeOutcome {
    /// Input was ciphertext and an available identity decrypted it.
    Decrypted(Vec<u8>),
    /// Input was passed through unchanged — either it wasn't age
    /// ciphertext to begin with, no identity was available, or the
    /// identities on hand couldn't decrypt it. `reason` is a
    /// human-readable explanation `main.rs` logs to stderr; this variant
    /// is deliberately not an `Err` — see the module docs on why smudge
    /// never fails.
    PassedThrough { reason: String, content: Vec<u8> },
}

impl SmudgeOutcome {
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            SmudgeOutcome::Decrypted(b) => b,
            SmudgeOutcome::PassedThrough { content, .. } => content,
        }
    }
}

/// Runs the smudge-filter transform. Never returns an `Err` — a missing
/// or non-matching identity degrades to passing the ciphertext through
/// unchanged rather than blocking the checkout that invoked it.
pub fn smudge(input: &[u8], identities: &[age::x25519::Identity]) -> SmudgeOutcome {
    if !crypto::looks_like_age_armor(input) {
        return SmudgeOutcome::PassedThrough {
            reason: "input isn't armored age ciphertext (already plaintext, or already \
                     smudged) — passing through unchanged"
                .to_string(),
            content: input.to_vec(),
        };
    }
    if identities.is_empty() {
        return SmudgeOutcome::PassedThrough {
            reason: "no identity available to decrypt — passing through ciphertext unchanged \
                     (this is expected on a machine that only needs to read the encrypted \
                     file, e.g. CI without the private key)"
                .to_string(),
            content: input.to_vec(),
        };
    }
    match crypto::decrypt(input, identities) {
        Ok(plaintext) => SmudgeOutcome::Decrypted(plaintext),
        Err(e) => SmudgeOutcome::PassedThrough {
            reason: format!(
                "decryption failed ({e}) — passing through ciphertext unchanged instead of \
                 failing the checkout"
            ),
            content: input.to_vec(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{generate_identity, public_string};

    #[test]
    fn clean_encrypts_plaintext() {
        let id = generate_identity();
        let recipients = vec![public_string(&id)];
        let outcome = clean(b"DATABASE_URL=secret\n", &recipients).unwrap();
        match outcome {
            CleanOutcome::Encrypted(bytes) => {
                assert!(crypto::looks_like_age_armor(&bytes));
                assert!(!String::from_utf8_lossy(&bytes).contains("secret"));
            }
            CleanOutcome::AlreadyEncrypted(_) => panic!("plaintext should not be classified as already-encrypted"),
        }
    }

    #[test]
    fn clean_is_idempotent_on_already_encrypted_content() {
        let id = generate_identity();
        let recipients = vec![public_string(&id)];
        let first = clean(b"DATABASE_URL=secret\n", &recipients)
            .unwrap()
            .into_bytes();

        // Re-cleaning the already-encrypted output (as `git diff` or a
        // second `git add` would trigger) must return it byte-for-byte
        // unchanged, not wrap it in a second layer of encryption.
        let second = clean(&first, &recipients).unwrap();
        assert_eq!(second, CleanOutcome::AlreadyEncrypted(first));
    }

    #[test]
    fn clean_fails_when_no_recipients_are_available() {
        // No `.cryptenv-recipients` file and no explicit -r: this must be
        // a real error so `filter.cryptenv.required = true` blocks the
        // commit instead of the plaintext silently becoming the blob.
        assert!(clean(b"plaintext", &[]).is_err());
    }

    #[test]
    fn smudge_decrypts_valid_ciphertext() {
        let id = generate_identity();
        let recipients = vec![public_string(&id)];
        let ciphertext = crypto::encrypt(b"top secret", &recipients).unwrap();

        let outcome = smudge(&ciphertext, &[id]);
        assert_eq!(outcome, SmudgeOutcome::Decrypted(b"top secret".to_vec()));
    }

    #[test]
    fn smudge_passes_through_plaintext_unchanged() {
        // Content that was never encrypted (or was already smudged) must
        // come back byte-for-byte identical, not error.
        let plaintext = b"DATABASE_URL=secret\n";
        let outcome = smudge(plaintext, &[]);
        assert_eq!(outcome.into_bytes(), plaintext);
    }

    #[test]
    fn smudge_passes_through_when_no_identity_available() {
        let id = generate_identity();
        let recipients = vec![public_string(&id)];
        let ciphertext = crypto::encrypt(b"top secret", &recipients).unwrap();

        // No identities at all (e.g. a CI runner without the private
        // key): must not panic or error, must hand back the ciphertext.
        let outcome = smudge(&ciphertext, &[]);
        match outcome {
            SmudgeOutcome::PassedThrough { content, reason } => {
                assert_eq!(content, ciphertext);
                assert!(reason.contains("no identity available"));
            }
            SmudgeOutcome::Decrypted(_) => panic!("must not decrypt with zero identities"),
        }
    }

    #[test]
    fn smudge_passes_through_on_wrong_identity_instead_of_crashing() {
        let id_a = generate_identity();
        let id_b = generate_identity();
        let ciphertext = crypto::encrypt(b"top secret", &[public_string(&id_a)]).unwrap();

        let outcome = smudge(&ciphertext, &[id_b]);
        match outcome {
            SmudgeOutcome::PassedThrough { content, .. } => assert_eq!(content, ciphertext),
            SmudgeOutcome::Decrypted(_) => panic!("wrong identity must not decrypt"),
        }
    }

    #[test]
    fn clean_then_smudge_round_trips() {
        let id = generate_identity();
        let recipients = vec![public_string(&id)];
        let plaintext = b"DATABASE_URL=secret\nAPI_KEY=sk-abc123\n";

        let ciphertext = clean(plaintext, &recipients).unwrap().into_bytes();
        let restored = smudge(&ciphertext, &[id]).into_bytes();
        assert_eq!(restored, plaintext);
    }

    #[test]
    fn smudge_smudge_is_stable() {
        // "smudge->smudge should be equivalent to smudge" (gitattributes(5)):
        // running smudge on already-plaintext content (as if smudge ran
        // twice) must not error or alter it further.
        let id = generate_identity();
        let recipients = vec![public_string(&id)];
        let plaintext = b"DATABASE_URL=secret\n";
        let ciphertext = clean(plaintext, &recipients).unwrap().into_bytes();

        let once = smudge(&ciphertext, std::slice::from_ref(&id)).into_bytes();
        let twice = smudge(&once, &[id]).into_bytes();
        assert_eq!(once, twice);
        assert_eq!(twice, plaintext);
    }
}
