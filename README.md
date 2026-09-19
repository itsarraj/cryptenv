# cryptenv

Encrypted secrets in git — a `sops` alternative built on `age`. Go has
`sops`; Rust has the crypto primitive (the `age` crate, same as `rage`) but
no tool that takes a `.env` file and gives you back something safe to
commit.

The problem this exists for is concrete, not hypothetical: this monorepo's
own `.gitignore` says outright that `.env`/`.env.*` files are "intentionally
tracked" across every app in `apps/`. That's plaintext secrets in git
history. `cryptenv` doesn't change that convention — it gives it a safe
version: encrypt the file, commit `.env.age` instead of `.env`.

## Usage

```bash
cryptenv keygen                              # writes ~/.config/cryptenv/key.txt, prints your public key (age1...)
echo "age1yourpublickeyhere..." > .cryptenv-recipients

cryptenv encrypt .env                        # .env -> .env.age
cryptenv decrypt .env.age                    # .env.age -> .env
cryptenv decrypt .env.age --stdout           # print without writing a file
cryptenv edit .env.age                       # decrypt to a temp file, $EDITOR, re-encrypt on save
```

Multiple recipients (e.g. you + a teammate) just means multiple lines in
`.cryptenv-recipients` — anyone whose identity matches any recipient the
file was encrypted to can decrypt it, same as `sops`'s multi-key model, just
without the KMS integration.

## Git filter: transparent `git add .env` (sops's signature feature)

The above is explicit: you run `encrypt`/`edit` yourself. `cryptenv filter
install` wires up a git `clean`/`smudge` filter instead, so the working
tree always holds plaintext and the git object database only ever holds
ciphertext — `git add .env` / `git commit` transparently encrypt, and
`git checkout` / `git clone` transparently decrypt, with no `.age` file or
separate command in the loop.

```bash
cryptenv keygen                              # once per machine
echo "age1yourpublickeyhere..." > .cryptenv-recipients
cryptenv filter install                      # wires .gitattributes + git config, in the current dir's repo
git add --renormalize .                      # if .env was already tracked in plaintext, re-clean it now
git add .env && git commit -m "..."          # .env stays plaintext on disk; the commit stores ciphertext
```

`filter install` adds `.env filter=cryptenv`, `.env.* filter=cryptenv`, and
`*.age -filter` to `.gitattributes` (the last line keeps the explicit
`encrypt`/`decrypt` workflow's `.env.age` files out of the transparent
filter, since gitattributes patterns are last-match-wins), and sets
`filter.cryptenv.{clean,smudge,required}` in the repo's local git config.
Two deliberate decisions on the edge cases `gitattributes(5)` warns about:

- **`filter.cryptenv.required = true`.** By git's own default, a filter
  that exits non-zero is treated as a no-op and git silently falls back to
  *unfiltered* content — for a `clean` failure (e.g. no
  `.cryptenv-recipients` file) that would mean the plaintext itself
  silently becomes the committed blob, exactly the leak this tool exists
  to prevent. `required = true` turns that into a hard failure of
  `git add`/`commit` instead. This also affects `git diff`/`git status`,
  which invoke the clean filter to compare the worktree against the
  index — see the verified caveat below.
- **`git-smudge` never fails on a missing/wrong identity.** `required =
  true` would normally make *any* filter failure fatal, which would break
  `git clone`/`checkout` on a machine that only needs to read the
  ciphertext (no private key present — e.g. CI). Instead,
  `cryptenv git-smudge` treats "no identity available" and "decryption
  failed" as non-fatal: it logs why to stderr and writes the ciphertext
  through to the worktree unchanged, always exiting 0. So `required` only
  ever blocks on the clean/encrypt direction, never on checkout.
- **Both directions are idempotent**, per `gitattributes(5)`'s
  "clean→clean should be equivalent to clean" guidance: `git-clean`
  recognizes input that's already armored age ciphertext and passes it
  through rather than re-encrypting it, and `git-smudge` recognizes input
  that isn't armored ciphertext (already plaintext, or already smudged)
  and passes it through rather than trying to decrypt it.

## Deliberate scope cut vs. `sops`

`sops` encrypts individual values inside a structured file (each YAML/JSON
key gets its own data key), so a git diff of an edited secret shows which
*key* changed even though you can't see the value. `cryptenv` v1 encrypts
the **whole file** as one age payload — simpler, works identically for
`.env`, YAML, JSON, or anything else, but a diff of two commits' `.env.age`
is opaque (the entire ciphertext changes even for a one-line edit, since
age's payload encryption isn't seekable/patchable). Per-key encryption is
the natural v2 if the opaque-diff tradeoff turns out to matter in practice;
left out here to ship a working v1 rather than a part-built one.

## Format compatibility

Identity and recipient files are exactly the standard age format — a
`cryptenv keygen`-generated `key.txt` is a normal age identity file, and
`.env.age` is a normal armored age file. `age -d -i key.txt .env.age` (the
real `age`/`rage` CLI) decrypts it too; nothing here is a proprietary format
riding on top of age, it's a workflow wrapper around it.

## Status: built and verified

All of the below was actually run, not just written:

- **25 unit/property tests** (`cargo test --lib`). The original 13: path
  derivation (`.env` → `.env.age`, idempotent on a second encrypt,
  non-`.age` files get `.dec` rather than a guessed name), recipients-file
  parsing (comments, blank lines), identity round-tripping through its own
  string form, and — the actual security property, not just plumbing —
  **encrypt→decrypt round trips, a wrong identity failing to decrypt,
  multiple independent recipients each decrypting on their own, and the
  plaintext secret value provably absent from the ciphertext bytes**
  (`assert!(!ciphertext.contains("sk-abc123"))`). Plus 12 new ones for the
  git filter's logic (`src/gitfilter.rs`, `looks_like_age_armor` in
  `src/crypto.rs`): clean encrypting plaintext, clean passing its own
  output through unchanged instead of double-encrypting it, clean failing
  when no recipients are available, smudge decrypting valid ciphertext,
  smudge passing plaintext/no-identity/wrong-identity content through
  unchanged instead of erroring, a full clean→smudge round trip, and
  `smudge→smudge` being stable (`gitattributes(5)`'s own idempotency
  wording) on already-plaintext content.
- **Full CLI smoke test**: `keygen` → `whoami` → wrote a fake `.env` with a
  fake DB password and API key → `encrypt` (confirmed via `grep` that the
  secret literally does not appear in `.env.age`) → `decrypt --stdout` →
  deleted the plaintext → `decrypt` back to a file → byte-for-byte `diff`
  against the original.
- **`edit` verified with a scripted fake `$EDITOR`** (a shell script that
  appends a line and exits) — confirmed the appended line survives the
  decrypt → edit → re-encrypt → decrypt cycle.
- **Wrong-identity rejection verified live**: generated a second, unrelated
  identity and confirmed it cannot decrypt a file encrypted to the first
  one's recipient (`No matching keys found`), not just asserted in a unit
  test but reproduced via the actual CLI.
- **Git filter verified end-to-end in a real, throwaway repo** (a scratch
  directory under `/tmp`, with `$HOME` pointed at a sandbox config so the
  real `~/.config/cryptenv` was never touched): `git init` → `cryptenv
  keygen` → `.cryptenv-recipients` → `cryptenv filter install` →
  `git check-attr filter -- .env .env.production some/dir/.env.age`
  confirmed `.env`/`.env.production` resolve to `filter: cryptenv` and
  `.env.age` correctly resolves to `filter: unset` → wrote a real `.env`
  with a fake DB password and API key, `git add .env && git commit` →
  **`git show HEAD:.env` is armored age ciphertext, and `grep`-ing that
  blob for the fake secret returns zero matches, while `cat .env` in the
  working tree is still the original plaintext.** Then deleted `.env` and
  ran `git checkout -- .env`: the restored file was byte-for-byte
  identical (`diff`) to the original.
- **The CI-without-identity case verified live, not assumed**: cloned that
  same repo into a second sandbox `$HOME` with no
  `~/.config/cryptenv/key.txt` at all. The clone succeeded (exit 0, no
  hang, no error), and `.env` in its working tree came out as the armored
  ciphertext — readable text, not garbage, not plaintext — proving a
  machine with no private key can still clone/checkout a repo using this
  filter. `git status` in that clone was clean, because smudge's
  ciphertext-passthrough and clean's ciphertext-passthrough exactly cancel
  out for a file nobody there can decrypt.
- **Fail-closed on a broken `clean` verified live**: with
  `.cryptenv-recipients` temporarily moved aside and a new fake secret
  appended to `.env`, `git add .env` failed outright —
  `fatal: .env: clean filter 'cryptenv' failed`, exit 128 — and a `grep`
  across the index (`git show :.env`) and the full history
  (`git log --all -p -- .env`) confirmed the new secret never reached any
  git object. That's `filter.cryptenv.required = true` doing its job:
  git's own default behavior for a failed filter is to silently commit
  the *unfiltered* (plaintext) content instead, which is exactly the leak
  this exists to prevent.
- **`cryptenv filter install` is idempotent**: run twice against the same
  repo, `.gitattributes` gained no duplicate lines on the second run.

**Known limitation, found by this same live verification, not
hypothetical**: on a machine that *has* the identity, `git status`/`git
diff` show an untouched `.env` as perpetually modified. Confirmed root
cause: `age`'s recipient-based encryption generates a fresh ephemeral
X25519 key on every call by design, so `cryptenv git-clean` run twice on
byte-identical plaintext and recipients produces two different (but both
valid) ciphertexts — verified directly with `diff` on two successive
invocations. Since git recomputes the clean filter's output to compare
against the stored blob for status/diff on any path with a filter
attribute, that mismatch shows as a spurious `M .env` every time, even
immediately after a fresh commit with nothing touched. This is not a
correctness or security bug — decrypting always recovers the exact
original plaintext (verified above), and the CI-without-identity case
above doesn't hit it at all, since that path never re-encrypts (clean's
own idempotency check passes matching ciphertext straight through
unchanged). Tools like `git-crypt` avoid this by deriving a deterministic
IV from the plaintext itself; doing the same here would mean hand-rolling
age's stanza-wrapping with a seeded RNG instead of using the `age` crate's
stock `Encryptor` (which doesn't expose that knob) — left as a known
quirk rather than a silent gap.

**Not done / deliberately deferred**:
- Per-key encryption (see above).
- KMS-backed recipients (`sops`'s AWS/GCP KMS integration) — plain age
  keypairs only.
- Deterministic clean-filter output, so `git status`/`diff` stay quiet on
  an unmodified `.env` — see the known limitation directly above for why
  it's not just an oversight.
