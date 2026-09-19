use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use cryptenv::{crypto, gitfilter, identity, paths};

#[derive(Parser)]
#[command(
    name = "cryptenv",
    about = "Encrypted secrets in git — a sops alternative built on age"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new identity (keypair) and print its public recipient.
    Keygen {
        /// Where to write the identity file. Defaults to
        /// $XDG_CONFIG_HOME/cryptenv/key.txt (refuses to overwrite an
        /// existing file — move it aside first if you want a fresh one).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Print the public recipient for an existing identity file, without
    /// generating anything.
    Whoami {
        #[arg(long)]
        identity: Option<PathBuf>,
    },
    /// Encrypt a file in place: `.env` -> `.env.age`.
    Encrypt {
        file: PathBuf,
        /// Recipient public key (age1...), repeatable.
        #[arg(short = 'r', long = "recipient")]
        recipients: Vec<String>,
        /// File of recipients, one per line. Defaults to
        /// `.cryptenv-recipients` next to `file`.
        #[arg(long)]
        recipients_file: Option<PathBuf>,
    },
    /// Decrypt `.env.age` -> `.env` (or print to stdout with --stdout).
    Decrypt {
        file: PathBuf,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        stdout: bool,
    },
    /// Decrypt to a temp file, open $EDITOR, re-encrypt on save, then wipe
    /// the temp file's contents before removing it.
    Edit {
        file: PathBuf,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(short = 'r', long = "recipient")]
        recipients: Vec<String>,
        #[arg(long)]
        recipients_file: Option<PathBuf>,
    },
    /// git clean-filter half: reads worktree content from stdin, writes
    /// ciphertext to stdout. Not meant to be run by hand — this is what
    /// `filter.cryptenv.clean` in git config invokes on `git add`/`commit`/
    /// `diff`. See `cryptenv filter install`.
    #[command(name = "git-clean")]
    GitClean {
        /// Path of the file being cleaned, exactly as git substitutes it
        /// for `%f` (repo-root-relative) — used only to find the sibling
        /// `.cryptenv-recipients` file, the same lookup `encrypt` does.
        /// Per gitattributes(5), clean/smudge must not read the file
        /// itself from disk; only `path`'s *location* is used here.
        path: PathBuf,
        #[arg(short = 'r', long = "recipient")]
        recipients: Vec<String>,
        #[arg(long)]
        recipients_file: Option<PathBuf>,
    },
    /// git smudge-filter half: reads ciphertext from stdin, writes
    /// plaintext to stdout. Not meant to be run by hand — this is what
    /// `filter.cryptenv.smudge` in git config invokes on `git checkout`/
    /// `clone`. See `cryptenv filter install`.
    ///
    /// Never fails on a missing or non-matching identity: it passes the
    /// ciphertext through unchanged instead (with a note on stderr), so a
    /// checkout on a machine without the private key still succeeds —
    /// see the module docs on `cryptenv::gitfilter` for why.
    #[command(name = "git-smudge")]
    GitSmudge {
        /// Path of the file being smudged, as git substitutes it for
        /// `%f`. Only used in the stderr note when decryption doesn't
        /// happen — not read from disk.
        path: Option<PathBuf>,
        #[arg(long)]
        identity: Option<PathBuf>,
    },
    /// Wire up the git clean/smudge filter so `.env` files are
    /// transparently encrypted on `git add`/commit and decrypted on
    /// checkout, instead of the explicit `encrypt`/`decrypt` workflow.
    Filter {
        #[command(subcommand)]
        action: FilterCommand,
    },
}

#[derive(Subcommand)]
enum FilterCommand {
    /// Add the `filter=cryptenv` pattern to `.gitattributes` and point
    /// `git config filter.cryptenv.{clean,smudge,required}` at this
    /// binary. Safe to run more than once (both steps are idempotent).
    Install {
        /// Directory to install into: `.gitattributes` is written here,
        /// and `git config` runs with this as its working directory
        /// (git resolves it to the enclosing repo's local config).
        /// Defaults to the current directory.
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
}

fn load_identities(path: Option<PathBuf>) -> anyhow::Result<Vec<age::x25519::Identity>> {
    let path = path.unwrap_or_else(identity::default_identity_path);
    let contents = fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("reading identity file {}: {e}", path.display()))?;
    identity::parse_identity_file(&contents)
}

fn resolve_recipients(
    explicit: Vec<String>,
    recipients_file: Option<PathBuf>,
    target: &Path,
) -> anyhow::Result<Vec<String>> {
    if !explicit.is_empty() {
        return Ok(explicit);
    }
    let file = recipients_file.unwrap_or_else(|| paths::default_recipients_file(target));
    let contents = fs::read_to_string(&file).map_err(|e| {
        anyhow::anyhow!(
            "no --recipient given and couldn't read recipients file {}: {e}\n\
             (create it with one age1... public key per line, or pass -r explicitly)",
            file.display()
        )
    })?;
    Ok(paths::parse_recipients_file(&contents))
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen { out } => {
            let path = out.unwrap_or_else(identity::default_identity_path);
            if path.exists() {
                anyhow::bail!(
                    "{} already exists — refusing to overwrite an existing identity",
                    path.display()
                );
            }
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let id = identity::generate_identity();
            let secret = identity::identity_secret_string(&id);
            let public = identity::public_string(&id);
            fs::write(&path, format!("# created by cryptenv keygen\n{secret}\n"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            }
            println!("identity written to {}", path.display());
            println!("public recipient (share this, add it to .cryptenv-recipients):");
            println!("{public}");
        }
        Command::Whoami {
            identity: identity_path,
        } => {
            let ids = load_identities(identity_path)?;
            for id in ids {
                println!("{}", identity::public_string(&id));
            }
        }
        Command::Encrypt {
            file,
            recipients,
            recipients_file,
        } => {
            let plaintext =
                fs::read(&file).map_err(|e| anyhow::anyhow!("reading {}: {e}", file.display()))?;
            let recipients = resolve_recipients(recipients, recipients_file, &file)?;
            let ciphertext = crypto::encrypt(&plaintext, &recipients)?;
            let out_path = paths::encrypted_path(&file);
            fs::write(&out_path, &ciphertext)?;
            println!(
                "{} -> {} ({} recipient{})",
                file.display(),
                out_path.display(),
                recipients.len(),
                if recipients.len() == 1 { "" } else { "s" }
            );
        }
        Command::Decrypt {
            file,
            identity: identity_path,
            stdout,
        } => {
            let ids = load_identities(identity_path)?;
            let ciphertext =
                fs::read(&file).map_err(|e| anyhow::anyhow!("reading {}: {e}", file.display()))?;
            let plaintext = crypto::decrypt(&ciphertext, &ids)?;
            if stdout {
                std::io::stdout().write_all(&plaintext)?;
            } else {
                let out_path = paths::decrypted_path(&file);
                fs::write(&out_path, &plaintext)?;
                println!("{} -> {}", file.display(), out_path.display());
            }
        }
        Command::Edit {
            file,
            identity: identity_path,
            recipients,
            recipients_file,
        } => {
            let ids = load_identities(identity_path)?;
            let recipients = resolve_recipients(recipients, recipients_file, &file)?;

            let plaintext = if file.exists() {
                let ciphertext = fs::read(&file)?;
                crypto::decrypt(&ciphertext, &ids)?
            } else {
                Vec::new()
            };

            let mut tmp = tempfile::NamedTempFile::new()?;
            {
                tmp.write_all(&plaintext)?;
                tmp.flush()?;
            }
            let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
            let status = std::process::Command::new(&editor)
                .arg(tmp.path())
                .status()?;
            if !status.success() {
                anyhow::bail!("editor '{editor}' exited with a non-zero status, not re-encrypting");
            }
            let edited = fs::read(tmp.path())?;
            let ciphertext = crypto::encrypt(&edited, &recipients)?;
            fs::write(&file, &ciphertext)?;

            // Best-effort wipe: overwrite the temp file's contents before
            // it's removed. Not a rigorous secure-delete (the filesystem
            // may have already copy-on-write'd blocks elsewhere) — a real
            // guarantee there would need direct block-device access, out of
            // scope for a v1 CLI. NamedTempFile's own Drop still removes
            // the (now-zeroed) file afterward.
            let zeros = vec![0u8; edited.len()];
            fs::write(tmp.path(), &zeros).ok();

            println!("re-encrypted {}", file.display());
        }
        Command::GitClean {
            path,
            recipients,
            recipients_file,
        } => {
            let mut input = Vec::new();
            std::io::stdin()
                .read_to_end(&mut input)
                .map_err(|e| anyhow::anyhow!("reading stdin: {e}"))?;
            // Resolving recipients (not identity) is deliberate: cleaning
            // (encrypting) only ever needs public keys, so it works with
            // no private key present at all — see the smudge side below.
            let recipients = resolve_recipients(recipients, recipients_file, &path)?;
            let output = gitfilter::clean(&input, &recipients)?.into_bytes();
            std::io::stdout().write_all(&output)?;
        }
        Command::GitSmudge { path, identity } => {
            let mut input = Vec::new();
            std::io::stdin()
                .read_to_end(&mut input)
                .map_err(|e| anyhow::anyhow!("reading stdin: {e}"))?;
            // A missing/unreadable/malformed identity file must degrade
            // to "no identities available", never abort the smudge — see
            // `cryptenv::gitfilter`'s module docs for why.
            let ids = load_identities(identity).unwrap_or_default();
            let outcome = gitfilter::smudge(&input, &ids);
            if let gitfilter::SmudgeOutcome::PassedThrough { reason, .. } = &outcome {
                let label = path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "<stdin>".to_string());
                eprintln!("cryptenv: git-smudge {label}: {reason}");
            }
            std::io::stdout().write_all(&outcome.into_bytes())?;
        }
        Command::Filter { action } => match action {
            FilterCommand::Install { dir } => install_filter(&dir)?,
        },
    }
    Ok(())
}

/// Adds the `filter=cryptenv` gitattributes pattern (if not already
/// present) and wires up `git config filter.cryptenv.*` in the repo
/// containing `dir`. Both steps are idempotent, so re-running `cryptenv
/// filter install` is safe.
fn install_filter(dir: &Path) -> anyhow::Result<()> {
    let attrs_path = dir.join(".gitattributes");
    let existing = fs::read_to_string(&attrs_path).unwrap_or_default();
    let mut lines: Vec<String> = existing.lines().map(str::to_string).collect();

    // `.env`/`.env.*` are the patterns this monorepo's own convention
    // (see README) tracks in plaintext today; the trailing `*.age -filter`
    // makes sure a file already using the explicit `encrypt`/`decrypt`
    // workflow (which commits `<name>.age`) never also gets run through
    // this filter — gitattributes uses last-match-wins, so this line
    // overrides the `.env.*` pattern for anything ending in `.age`.
    let desired = [
        ".env filter=cryptenv",
        ".env.* filter=cryptenv",
        "*.age -filter",
    ];
    for line in desired {
        if !lines.iter().any(|l| l.trim() == line) {
            lines.push(line.to_string());
        }
    }
    let mut new_contents = lines.join("\n");
    if !new_contents.is_empty() {
        new_contents.push('\n');
    }
    fs::write(&attrs_path, &new_contents)
        .map_err(|e| anyhow::anyhow!("writing {}: {e}", attrs_path.display()))?;

    let run_git = |args: &[&str]| -> anyhow::Result<()> {
        let status = std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .status()
            .map_err(|e| anyhow::anyhow!("running `git {}`: {e}", args.join(" ")))?;
        if !status.success() {
            anyhow::bail!(
                "`git {}` failed (exit {:?}) — is {} inside a git repository?",
                args.join(" "),
                status.code(),
                dir.display()
            );
        }
        Ok(())
    };
    run_git(&["config", "filter.cryptenv.clean", "cryptenv git-clean %f"])?;
    run_git(&[
        "config",
        "filter.cryptenv.smudge",
        "cryptenv git-smudge %f",
    ])?;
    // Required so a *clean* failure (e.g. no .cryptenv-recipients file)
    // hard-blocks `git add`/`commit` instead of git's default "filter
    // failed -> fall back to unfiltered content", which for clean would
    // mean committing plaintext straight into the object database. The
    // smudge side is written to never fail on a missing identity (it
    // passes ciphertext through instead — see `cryptenv::gitfilter`), so
    // this same setting never blocks a checkout for that reason.
    run_git(&["config", "filter.cryptenv.required", "true"])?;

    println!("wired up {}:", attrs_path.display());
    for line in desired {
        println!("  {line}");
    }
    println!("git config (local to this repo):");
    println!("  filter.cryptenv.clean = cryptenv git-clean %f");
    println!("  filter.cryptenv.smudge = cryptenv git-smudge %f");
    println!("  filter.cryptenv.required = true");
    println!();
    println!(
        "note: if any of these paths are already tracked, run `git add --renormalize .`\n\
         now to re-clean them through the filter (gitattributes(5) recommends this\n\
         whenever a clean filter is (re)configured)."
    );
    Ok(())
}
