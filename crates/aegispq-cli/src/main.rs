//! AegisPQ command-line interface.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};

use aegispq_api::{encrypt, identity, sign, RevocationReason};
use aegispq_api::error::Error as ApiError;
use aegispq_api::types::EncryptOptions;
use aegispq_core::kdf::Argon2Params;
use aegispq_protocol::padding::PaddingScheme;
use aegispq_protocol::Suite;
use aegispq_store::fs::FileStore;
use serde::Serialize;
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Exit codes — stable contract for JSON consumers and scripts.
// ---------------------------------------------------------------------------

/// Success.
const EXIT_OK: i32 = 0;
/// General or unknown error.
const EXIT_GENERAL: i32 = 1;
/// Authentication or passphrase error.
const EXIT_AUTH: i32 = 2;
/// Integrity, verification, or revocation failure.
const EXIT_INTEGRITY: i32 = 3;
/// File I/O or storage error.
const EXIT_IO: i32 = 4;
/// Invalid usage or bad arguments.
const EXIT_USAGE: i32 = 5;

/// Return testing Argon2 params if `AEGISPQ_FAST_KDF=1` is set in the
/// environment, otherwise the hardened defaults.
///
/// This is a deliberate, hidden escape hatch for automated test harnesses
/// that need to create identities quickly. It should never be set in
/// production — enabling it drops the memory and time cost of the
/// passphrase KDF to values that are trivially brute-forceable.
fn argon2_params_from_env() -> Argon2Params {
    match std::env::var("AEGISPQ_FAST_KDF").as_deref() {
        Ok("1") => Argon2Params::testing(),
        _ => Argon2Params::default(),
    }
}

#[derive(Parser)]
#[command(
    name = "aegispq",
    about = "AegisPQ — Post-quantum-ready encryption platform",
    version,
    propagate_version = true
)]
struct Cli {
    /// Data directory (default: ~/.aegispq).
    #[arg(long, global = true, env = "AEGISPQ_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Emit machine-readable JSON output instead of human text.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage local identities.
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },
    /// Manage imported contacts.
    Contact {
        #[command(subcommand)]
        action: ContactAction,
    },
    /// Encrypt a file for one or more recipients.
    Encrypt {
        /// Path to the file to encrypt.
        #[arg(long)]
        file: PathBuf,
        /// Recipient contact ID (hex). Repeat for multiple recipients.
        #[arg(long = "to")]
        recipients: Vec<String>,
        /// File containing recipient IDs (one hex ID per line).
        #[arg(long)]
        recipients_file: Option<PathBuf>,
        /// Local identity ID (hex) to sign with.
        #[arg(long)]
        identity: String,
        /// Output path (default: <file>.apq).
        #[arg(long, short)]
        output: Option<PathBuf>,
        /// Algorithm suite: aes (default) or xchacha.
        #[arg(long, default_value = "aes")]
        suite: String,
    },
    /// Decrypt a file.
    Decrypt {
        /// Path to the encrypted file.
        #[arg(long)]
        file: PathBuf,
        /// Local identity ID (hex) to decrypt with.
        #[arg(long)]
        identity: String,
        /// Output path (default: strip .apq extension, or <file>.dec).
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Sign a file.
    Sign {
        /// Path to the file to sign.
        #[arg(long)]
        file: PathBuf,
        /// Local identity ID (hex) to sign with.
        #[arg(long)]
        identity: String,
        /// Output path for the signature (default: <file>.apqsig).
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Verify a file signature.
    Verify {
        /// Path to the original file.
        #[arg(long)]
        file: PathBuf,
        /// Path to the signature file.
        #[arg(long)]
        signature: PathBuf,
        /// Signer's contact ID (hex).
        #[arg(long)]
        signer: String,
    },
    /// Show version, protocol, and capability information.
    Version,
}

#[derive(Subcommand)]
enum IdentityAction {
    /// Create a new identity.
    Create {
        /// Display name for the identity.
        #[arg(long)]
        name: String,
    },
    /// List all local identities.
    List,
    /// Export public key package to a file.
    Export {
        /// Identity ID (hex).
        id: String,
        /// Output file path (default: <id>.pub.apq).
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Revoke an identity (generates a revocation certificate for distribution).
    Revoke {
        /// Identity ID (hex).
        id: String,
        /// Revocation reason: compromised, superseded, or retired.
        #[arg(long, default_value = "retired")]
        reason: String,
        /// Output path for the revocation certificate (default: <id>.rev.apq).
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Rotate an identity (generates new keys and a rotation certificate).
    Rotate {
        /// Identity ID (hex) of the identity to rotate.
        id: String,
        /// Display name for the new identity (defaults to old name).
        #[arg(long)]
        name: Option<String>,
        /// Output path for the rotation certificate (default: <id>.rot.apq).
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Show the fingerprint of a local identity (for out-of-band verification).
    Fingerprint {
        /// Identity ID (hex).
        id: String,
    },
}

#[derive(Subcommand)]
enum ContactAction {
    /// Import a public key package file.
    Import {
        /// Path to the key package file.
        file: PathBuf,
    },
    /// Import a revocation certificate for a contact.
    ImportRevocation {
        /// Path to the revocation certificate file.
        file: PathBuf,
    },
    /// Import a rotation certificate from a contact.
    ImportRotation {
        /// Path to the rotation certificate file.
        file: PathBuf,
    },
    /// List all imported contacts.
    List,
    /// Show details and fingerprint of an imported contact (for verification).
    Inspect {
        /// Contact ID (hex).
        id: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let json = cli.json;

    if let Err(e) = run(cli) {
        let (error_kind, exit_code) = classify_error(e.as_ref());
        if json {
            emit_json(&serde_json::json!({
                "error": e.to_string(),
                "error_kind": error_kind,
            }));
        } else {
            eprintln!("error: {e}");
        }
        process::exit(exit_code);
    }
}

/// Emit a JSON value to stdout (for --json mode).
fn emit_json(value: &impl Serialize) {
    println!("{}", serde_json::to_string_pretty(value).unwrap());
}

/// Classify an error into a stable `(error_kind, exit_code)` pair.
///
/// `error_kind` values are part of the stable CLI contract for `--json` consumers.
/// Do not rename or remove existing kinds without a deprecation cycle.
///
/// ## Error kinds and exit codes
///
/// | error_kind     | exit_code | Meaning                                    |
/// |----------------|-----------|--------------------------------------------|
/// | `auth`         | 2         | Invalid passphrase or passphrase mismatch  |
/// | `integrity`    | 3         | Authentication or integrity check failed   |
/// | `not_recipient`| 3         | Local identity is not a recipient          |
/// | `revoked`      | 3         | Identity has been revoked                  |
/// | `unsupported`  | 1         | Unsupported protocol version or suite      |
/// | `io`           | 4         | File I/O or storage error                  |
/// | `corrupt`      | 1         | Invalid key material or truncated input    |
/// | `too_large`    | 1         | Input exceeds maximum size                 |
/// | `usage`        | 5         | Invalid arguments or usage                 |
/// | `unknown`      | 1         | Uncategorized error                        |
fn classify_error(e: &(dyn std::error::Error + 'static)) -> (&'static str, i32) {
    // Try structured matching against known API error types first.
    if let Some(api_err) = e.downcast_ref::<ApiError>() {
        return match api_err {
            ApiError::InvalidPassphrase => ("auth", EXIT_AUTH),
            ApiError::AuthenticationFailed => ("integrity", EXIT_INTEGRITY),
            ApiError::IntegrityError { .. } => ("integrity", EXIT_INTEGRITY),
            ApiError::NotARecipient => ("not_recipient", EXIT_INTEGRITY),
            ApiError::IdentityRevoked { .. } => ("revoked", EXIT_INTEGRITY),
            ApiError::UnsupportedVersion { .. } | ApiError::UnsupportedSuite { .. } => {
                ("unsupported", EXIT_GENERAL)
            }
            ApiError::InputTooLarge { .. } => ("too_large", EXIT_GENERAL),
            ApiError::IoError { .. } => ("io", EXIT_IO),
            ApiError::StorageError(_) => ("io", EXIT_IO),
            ApiError::InvalidKeyMaterial { .. } => ("corrupt", EXIT_GENERAL),
            ApiError::TruncatedInput => ("corrupt", EXIT_GENERAL),
            ApiError::InvalidFormat => ("corrupt", EXIT_GENERAL),
            ApiError::UnknownFormat { .. } => ("corrupt", EXIT_GENERAL),
            ApiError::TrailingData => ("corrupt", EXIT_GENERAL),
            ApiError::TooManyRecipients { .. } => ("usage", EXIT_USAGE),
            ApiError::KeyExhausted => ("auth", EXIT_AUTH),
            #[allow(deprecated)]
            ApiError::Internal => ("unknown", EXIT_GENERAL),
            ApiError::Core(_) => ("unknown", EXIT_GENERAL),
        };
    }

    // Fallback: classify by message string for non-API errors (e.g., CLI-level
    // argument validation errors, std::io::Error, hex decode errors).
    let msg = e.to_string();
    if msg.contains("passphrase") {
        ("auth", EXIT_AUTH)
    } else if msg.contains("No such file") || msg.contains("not found") {
        ("io", EXIT_IO)
    } else if msg.contains("identity ID must be") || msg.contains("no recipients specified")
        || msg.contains("unknown suite") || msg.contains("unknown revocation reason")
    {
        ("usage", EXIT_USAGE)
    } else if msg.contains("Invalid character") || msg.contains("Odd number of digits") {
        // hex::FromHexError messages
        ("usage", EXIT_USAGE)
    } else {
        ("unknown", EXIT_GENERAL)
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let json = cli.json;

    // Version command does not require the store.
    if let Commands::Version = &cli.command {
        return run_version(json);
    }

    let store = open_store(cli.data_dir.as_deref())?;

    match cli.command {
        Commands::Identity { action } => run_identity(action, json, &store),
        Commands::Contact { action } => run_contact(action, json, &store),
        Commands::Version => unreachable!(), // handled above
        Commands::Encrypt {
            file,
            recipients,
            recipients_file,
            identity: id,
            output,
            suite,
        } => {
            let mut all_recipients = recipients;
            if let Some(rf) = recipients_file {
                let contents = std::fs::read_to_string(&rf)?;
                for line in contents.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() && !trimmed.starts_with('#') {
                        all_recipients.push(trimmed.to_string());
                    }
                }
            }
            if all_recipients.is_empty() {
                return Err("no recipients specified (use --to or --recipients-file)".into());
            }
            run_encrypt(&file, &all_recipients, &id, output.as_deref(), &suite, json, &store)
        }
        Commands::Decrypt {
            file,
            identity: id,
            output,
        } => run_decrypt(&file, &id, output.as_deref(), json, &store),
        Commands::Sign {
            file,
            identity: id,
            output,
        } => run_sign(&file, &id, output.as_deref(), json, &store),
        Commands::Verify {
            file,
            signature,
            signer,
        } => run_verify(&file, &signature, &signer, json, &store),
    }
}

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

fn run_version(json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let version = env!("CARGO_PKG_VERSION");
    let protocol_version = aegispq_protocol::version::CURRENT;
    let min_protocol_version = aegispq_protocol::version::MIN_SUPPORTED;

    if json {
        emit_json(&serde_json::json!({
            "command": "version",
            "version": version,
            "protocol_version": protocol_version,
            "min_protocol_version": min_protocol_version,
            "suites": ["HybridV1", "HybridV1XChaCha"],
            "capabilities": [
                "encrypt",
                "decrypt",
                "sign",
                "verify",
                "identity.create",
                "identity.export",
                "identity.revoke",
                "identity.rotate",
                "contact.import",
                "contact.import_revocation",
                "contact.import_rotation",
                "recipients_file",
                "streaming_io",
                "json_output",
            ],
            "exit_codes": {
                "success": EXIT_OK,
                "general": EXIT_GENERAL,
                "auth": EXIT_AUTH,
                "integrity": EXIT_INTEGRITY,
                "io": EXIT_IO,
                "usage": EXIT_USAGE,
            },
        }));
    } else {
        println!("aegispq {version}");
        println!("  Protocol: v{protocol_version} (min: v{min_protocol_version})");
        println!("  Suites:   HybridV1 (AES-256-GCM), HybridV1XChaCha (XChaCha20-Poly1305)");
        println!("  Crypto:   X25519+ML-KEM-768, Ed25519+ML-DSA-65, BLAKE3, Argon2id");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

fn open_store(data_dir: Option<&std::path::Path>) -> Result<FileStore, Box<dyn std::error::Error>> {
    let dir = match data_dir {
        Some(d) => d.to_path_buf(),
        None => default_data_dir()?,
    };
    Ok(FileStore::open(dir)?)
}

fn default_data_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let home = dirs::home_dir().ok_or("cannot determine home directory")?;
    Ok(home.join(".aegispq"))
}

// ---------------------------------------------------------------------------
// Passphrase
// ---------------------------------------------------------------------------

fn read_passphrase(prompt: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use std::io::{BufRead, IsTerminal};

    // When stdin is a tty, prompt interactively with echo disabled.
    // Otherwise, read a line from piped stdin. This keeps scripted and
    // test usage possible without exposing a passphrase-in-environment flag.
    let mut pass = if std::io::stdin().is_terminal() {
        rpassword::prompt_password(prompt)?
    } else {
        let mut line = String::new();
        let stdin = std::io::stdin();
        let mut locked = stdin.lock();
        locked.read_line(&mut line)?;
        // Strip a single trailing newline (LF or CRLF).
        if line.ends_with('\n') {
            line.pop();
            if line.ends_with('\r') {
                line.pop();
            }
        }
        line
    };

    if pass.is_empty() {
        pass.zeroize();
        return Err("passphrase cannot be empty".into());
    }
    let bytes = pass.as_bytes().to_vec();
    pass.zeroize();
    Ok(bytes)
}

fn read_passphrase_confirm() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let pass = read_passphrase("Passphrase: ")?;
    let mut confirm = read_passphrase("Confirm passphrase: ")?;
    if pass != confirm {
        confirm.zeroize();
        // pass is dropped and zeroized below via scope exit
        return Err("passphrases do not match".into());
    }
    confirm.zeroize();
    Ok(pass)
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

fn parse_identity_id(hex_str: &str) -> Result<[u8; 16], Box<dyn std::error::Error>> {
    let bytes = hex::decode(hex_str)?;
    let arr: [u8; 16] = bytes
        .try_into()
        .map_err(|_| "identity ID must be 16 bytes (32 hex chars)")?;
    Ok(arr)
}

fn format_id(id: &[u8; 16]) -> String {
    hex::encode(id)
}

fn parse_revocation_reason(s: &str) -> Result<RevocationReason, Box<dyn std::error::Error>> {
    match s {
        "compromised" => Ok(RevocationReason::Compromised),
        "superseded" => Ok(RevocationReason::Superseded),
        "retired" => Ok(RevocationReason::Retired),
        other => Err(format!(
            "unknown revocation reason: {other} (use 'compromised', 'superseded', or 'retired')"
        )
        .into()),
    }
}

fn status_str(s: aegispq_store::record::IdentityStatus) -> &'static str {
    use aegispq_store::record::IdentityStatus;
    match s {
        IdentityStatus::Active => "active",
        IdentityStatus::Rotated => "rotated",
        IdentityStatus::Revoked => "revoked",
    }
}

fn reason_str(r: RevocationReason) -> &'static str {
    match r {
        RevocationReason::Compromised => "compromised",
        RevocationReason::Superseded => "superseded",
        RevocationReason::Retired => "retired",
    }
}

// ---------------------------------------------------------------------------
// Identity commands
// ---------------------------------------------------------------------------

fn run_identity(
    action: IdentityAction,
    json: bool,
    store: &FileStore,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        IdentityAction::Create { name } => {
            let mut passphrase = read_passphrase_confirm()?;
            let ident = identity::create_identity_with_params(
                &name,
                &passphrase,
                store,
                argon2_params_from_env(),
            )?;
            passphrase.zeroize();
            let fp = ident.fingerprint();
            let id_hex = format_id(&ident.identity_id);

            if json {
                emit_json(&serde_json::json!({
                    "command": "identity.create",
                    "id": id_hex,
                    "name": ident.display_name,
                    "fingerprint": fp.to_string(),
                }));
            } else {
                println!("Identity created.");
                println!("  ID:          {id_hex}");
                println!("  Name:        {}", ident.display_name);
                println!("  Fingerprint: {fp}");
            }
        }
        IdentityAction::List => {
            let ids = identity::list_identities(store)?;
            if json {
                let entries: Vec<_> = ids
                    .iter()
                    .map(|id| {
                        let name = identity::load_identity_name(id, store)
                            .unwrap_or_else(|_| "(error)".to_string());
                        let status = identity::load_identity_status(id, store)
                            .map(status_str)
                            .unwrap_or("unknown");
                        serde_json::json!({
                            "id": format_id(id),
                            "name": name,
                            "status": status,
                        })
                    })
                    .collect();
                emit_json(&serde_json::json!({
                    "command": "identity.list",
                    "identities": entries,
                }));
            } else if ids.is_empty() {
                println!("No identities found. Create one with: aegispq identity create --name <name>");
            } else {
                for id in &ids {
                    let name = identity::load_identity_name(id, store)
                        .unwrap_or_else(|_| "(error)".to_string());
                    let status = identity::load_identity_status(id, store)
                        .map(status_str)
                        .unwrap_or("unknown");
                    println!("  {} — {} [{}]", format_id(id), name, status);
                }
            }
        }
        IdentityAction::Export { id, output } => {
            let identity_id = parse_identity_id(&id)?;
            let mut passphrase = read_passphrase("Passphrase: ")?;
            let ident = identity::load_identity(&identity_id, &passphrase, store)?;
            passphrase.zeroize();
            let pkg_bytes = identity::export_key_package(&ident)?;

            let out_path = output.unwrap_or_else(|| PathBuf::from(format!("{id}.pub.apq")));
            std::fs::write(&out_path, &pkg_bytes)?;
            let fp = ident.fingerprint();

            if json {
                emit_json(&serde_json::json!({
                    "command": "identity.export",
                    "id": format_id(&ident.identity_id),
                    "name": ident.display_name,
                    "fingerprint": fp.to_string(),
                    "path": out_path.display().to_string(),
                    "bytes": pkg_bytes.len(),
                }));
            } else {
                println!("Public key exported to: {}", out_path.display());
                println!("  Fingerprint: {fp}");
            }
        }
        IdentityAction::Revoke { id, reason, output } => {
            let identity_id = parse_identity_id(&id)?;
            let reason = parse_revocation_reason(&reason)?;
            let mut passphrase = read_passphrase("Passphrase: ")?;
            let ident = identity::load_identity(&identity_id, &passphrase, store)?;
            passphrase.zeroize();
            let cert_bytes = identity::revoke_identity(&ident, reason, store)?;

            let out_path = output.unwrap_or_else(|| PathBuf::from(format!("{id}.rev.apq")));
            std::fs::write(&out_path, &cert_bytes)?;

            if json {
                emit_json(&serde_json::json!({
                    "command": "identity.revoke",
                    "id": format_id(&ident.identity_id),
                    "reason": reason_str(reason),
                    "certificate": out_path.display().to_string(),
                }));
            } else {
                println!("Identity revoked.");
                println!("  Reason: {reason}");
                println!("  Certificate: {}", out_path.display());
                println!();
                println!("Distribute this certificate to your contacts.");
            }
        }
        IdentityAction::Rotate { id, name, output } => {
            let identity_id = parse_identity_id(&id)?;
            let mut old_passphrase = read_passphrase("Current passphrase: ")?;
            let old_ident = identity::load_identity(&identity_id, &old_passphrase, store)?;
            old_passphrase.zeroize();

            let new_name = name.unwrap_or_else(|| old_ident.display_name.clone());
            if !json {
                println!("Enter passphrase for the NEW identity:");
            }
            let mut new_passphrase = read_passphrase_confirm()?;

            let (new_ident, cert_bytes) = identity::rotate_identity_with_params(
                &old_ident,
                &new_name,
                &new_passphrase,
                store,
                argon2_params_from_env(),
            )?;
            new_passphrase.zeroize();

            let out_path = output.unwrap_or_else(|| PathBuf::from(format!("{id}.rot.apq")));
            std::fs::write(&out_path, &cert_bytes)?;
            let fp = new_ident.fingerprint();

            if json {
                emit_json(&serde_json::json!({
                    "command": "identity.rotate",
                    "old_id": format_id(&old_ident.identity_id),
                    "new_id": format_id(&new_ident.identity_id),
                    "new_name": new_ident.display_name,
                    "fingerprint": fp.to_string(),
                    "certificate": out_path.display().to_string(),
                }));
            } else {
                println!("Identity rotated.");
                println!("  Old ID:      {}", format_id(&old_ident.identity_id));
                println!("  New ID:      {}", format_id(&new_ident.identity_id));
                println!("  New name:    {}", new_ident.display_name);
                println!("  Fingerprint: {fp}");
                println!("  Certificate: {}", out_path.display());
                println!();
                println!("Distribute this certificate to your contacts.");
            }
        }
        IdentityAction::Fingerprint { id } => {
            let identity_id = parse_identity_id(&id)?;
            let mut passphrase = read_passphrase("Passphrase: ")?;
            let ident = identity::load_identity(&identity_id, &passphrase, store)?;
            passphrase.zeroize();
            let fp = ident.fingerprint();
            let status = identity::load_identity_status(&identity_id, store)
                .map(status_str)
                .unwrap_or("unknown");

            if json {
                emit_json(&serde_json::json!({
                    "command": "identity.fingerprint",
                    "id": format_id(&ident.identity_id),
                    "name": ident.display_name,
                    "fingerprint": fp.to_string(),
                    "status": status,
                }));
            } else {
                println!("Identity: {} ({})", ident.display_name, format_id(&ident.identity_id));
                println!("  Fingerprint: {fp}");
                println!("  Status:      {status}");
                println!();
                println!("Verify this fingerprint out-of-band with your contacts.");
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Contact commands
// ---------------------------------------------------------------------------

fn run_contact(
    action: ContactAction,
    json: bool,
    store: &FileStore,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        ContactAction::Import { file } => {
            let bytes = std::fs::read(&file)?;
            let public = identity::import_key_package(&bytes, store)?;
            let fp = public.fingerprint();

            if json {
                emit_json(&serde_json::json!({
                    "command": "contact.import",
                    "id": format_id(&public.identity_id),
                    "name": public.display_name,
                    "fingerprint": fp.to_string(),
                    "status": status_str(public.status),
                }));
            } else {
                println!("Contact imported: {} ({})", public.display_name, format_id(&public.identity_id));
                println!();
                println!("  Fingerprint: {fp}");
                println!();
                println!("  IMPORTANT: Verify this fingerprint with {} via a trusted", public.display_name);
                println!("  channel (phone, in person) before encrypting sensitive data.");
            }
        }
        ContactAction::ImportRevocation { file } => {
            let bytes = std::fs::read(&file)?;
            let revoked_id = identity::import_revocation(&bytes, store)?;

            let name = identity::load_contact_name(&revoked_id, store)
                .unwrap_or_else(|_| "(unknown)".to_string());

            if json {
                emit_json(&serde_json::json!({
                    "command": "contact.import_revocation",
                    "id": format_id(&revoked_id),
                    "name": name,
                    "status": "revoked",
                }));
            } else {
                println!("Revocation imported for: {} ({})", name, format_id(&revoked_id));
                println!("  Status: REVOKED");
                println!();
                println!("  This contact's keys are no longer trusted for new encryption.");
                println!("  Existing files encrypted by them can still be decrypted.");
            }
        }
        ContactAction::ImportRotation { file } => {
            let bytes = std::fs::read(&file)?;
            let new_id = identity::import_rotation(&bytes, store)?;

            let name = identity::load_contact_name(&new_id, store)
                .unwrap_or_else(|_| "(unknown)".to_string());

            if json {
                emit_json(&serde_json::json!({
                    "command": "contact.import_rotation",
                    "new_id": format_id(&new_id),
                    "name": name,
                    "status": "active",
                }));
            } else {
                println!("Rotation imported: {} ({})", name, format_id(&new_id));
                println!("  Status: ACTIVE");
                println!();
                println!("  Use the new ID above for future encryption to this contact.");
                println!("  The old identity has been marked as rotated.");
            }
        }
        ContactAction::List => {
            let ids = identity::list_contacts(store)?;
            if json {
                let entries: Vec<_> = ids
                    .iter()
                    .map(|id| {
                        let name = identity::load_contact_name(id, store)
                            .unwrap_or_else(|_| "(error)".to_string());
                        let status = identity::load_contact(id, store)
                            .map(|c| status_str(c.status))
                            .unwrap_or("unknown");
                        serde_json::json!({
                            "id": format_id(id),
                            "name": name,
                            "status": status,
                        })
                    })
                    .collect();
                emit_json(&serde_json::json!({
                    "command": "contact.list",
                    "contacts": entries,
                }));
            } else if ids.is_empty() {
                println!("No contacts found. Import one with: aegispq contact import <file>");
            } else {
                for id in &ids {
                    let name = identity::load_contact_name(id, store)
                        .unwrap_or_else(|_| "(error)".to_string());
                    let status = identity::load_contact(id, store)
                        .map(|c| status_str(c.status))
                        .unwrap_or("unknown");
                    println!("  {} — {} [{}]", format_id(id), name, status);
                }
            }
        }
        ContactAction::Inspect { id } => {
            let contact_id = parse_identity_id(&id)?;
            let public = identity::load_contact(&contact_id, store)?;
            let fp = public.fingerprint();
            let status = status_str(public.status);

            if json {
                emit_json(&serde_json::json!({
                    "command": "contact.inspect",
                    "id": format_id(&public.identity_id),
                    "name": public.display_name,
                    "fingerprint": fp.to_string(),
                    "status": status,
                }));
            } else {
                println!("Contact: {} ({})", public.display_name, format_id(&public.identity_id));
                println!("  Fingerprint: {fp}");
                println!("  Status:      {status}");
                println!();
                println!("Verify this fingerprint with the contact via a trusted channel.");
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Encrypt / Decrypt
// ---------------------------------------------------------------------------

fn run_encrypt(
    file: &std::path::Path,
    recipient_ids: &[String],
    identity_id_hex: &str,
    output: Option<&std::path::Path>,
    suite: &str,
    json: bool,
    store: &FileStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let identity_id = parse_identity_id(identity_id_hex)?;
    let mut passphrase = read_passphrase("Passphrase: ")?;
    let sender = identity::load_identity(&identity_id, &passphrase, store)?;
    passphrase.zeroize();

    let mut recipients = Vec::with_capacity(recipient_ids.len());
    for rid in recipient_ids {
        let rid_bytes = parse_identity_id(rid)?;
        let contact = identity::load_contact(&rid_bytes, store)?;
        recipients.push(contact);
    }
    let recipient_refs: Vec<&aegispq_api::types::PublicIdentity> =
        recipients.iter().collect();

    let suite_name = suite;
    let suite = match suite {
        "aes" => Suite::HybridV1,
        "xchacha" => Suite::HybridV1XChaCha,
        other => return Err(format!("unknown suite: {other} (use 'aes' or 'xchacha')").into()),
    };
    let options = EncryptOptions {
        suite,
        padding: PaddingScheme::PowerOfTwo,
        chunk_size: 0,
    };

    let out_path = output
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| {
            let mut p = file.to_path_buf();
            let ext = p
                .extension()
                .map(|e| format!("{}.apq", e.to_string_lossy()))
                .unwrap_or_else(|| "apq".to_string());
            p.set_extension(ext);
            p
        });

    let input_size = std::fs::metadata(file)?.len();
    let mut input_file = std::fs::File::open(file)?;
    let mut output_file = std::fs::File::create(&out_path)?;

    encrypt::encrypt_file_stream(
        &mut input_file,
        &mut output_file,
        input_size,
        &sender,
        &recipient_refs,
        &options,
    )?;

    let output_size = std::fs::metadata(&out_path)?.len();
    if json {
        let recipient_details: Vec<_> = recipients
            .iter()
            .map(|r| serde_json::json!({"id": format_id(&r.identity_id), "name": &r.display_name}))
            .collect();
        emit_json(&serde_json::json!({
            "command": "encrypt",
            "input": file.display().to_string(),
            "output": out_path.display().to_string(),
            "input_bytes": input_size,
            "output_bytes": output_size,
            "sender_id": format_id(&sender.identity_id),
            "recipients": recipient_details,
            "suite": suite_name,
        }));
    } else {
        println!("Encrypted: {} -> {}", file.display(), out_path.display());
        println!("  Suite: {suite_name}");
        println!("  Recipients:");
        for r in &recipients {
            println!("    {} ({})", r.display_name, format_id(&r.identity_id));
        }
        println!("  Output: {} bytes", output_size);
    }
    Ok(())
}

fn run_decrypt(
    file: &std::path::Path,
    identity_id_hex: &str,
    output: Option<&std::path::Path>,
    json: bool,
    store: &FileStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let identity_id = parse_identity_id(identity_id_hex)?;
    let mut passphrase = read_passphrase("Passphrase: ")?;
    let recipient = identity::load_identity(&identity_id, &passphrase, store)?;
    passphrase.zeroize();

    let out_path = output
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| {
            let p = file.to_path_buf();
            // Strip .apq extension if present.
            match p.extension() {
                Some(ext) => {
                    let ext_str = ext.to_string_lossy();
                    if ext_str.ends_with(".apq") || ext_str == "apq" {
                        p.with_extension("")
                    } else {
                        p.with_extension(format!("{ext_str}.dec"))
                    }
                }
                None => p.with_extension("dec"),
            }
        });

    // Decrypt to a temp file in the same directory, then atomically rename.
    // This ensures no plaintext is left on disk if signature verification fails.
    let out_dir = out_path.parent().unwrap_or(std::path::Path::new("."));
    let temp_name = format!(
        ".aegispq-dec-{}.tmp",
        std::process::id()
    );
    let temp_path = out_dir.join(&temp_name);

    // Read the encrypted file and stream-decrypt into the temp file.
    let ciphertext = std::fs::read(file)?;
    let result = {
        let mut temp_file = std::fs::File::create(&temp_path)?;
        let r = encrypt::decrypt_file_stream_with_store(
            &ciphertext,
            &mut temp_file,
            &recipient,
            store,
        );
        // Flush before rename.
        if r.is_ok() {
            use std::io::Write;
            temp_file.flush()?;
            temp_file.sync_all()?;
        }
        r
    };

    match result {
        Ok((bytes_written, sender_id)) => {
            // Signature verified — promote temp file to final output.
            std::fs::rename(&temp_path, &out_path)?;

            let sender_name = identity::load_contact_name(&sender_id, store)
                .unwrap_or_else(|_| "(unknown)".to_string());

            if json {
                emit_json(&serde_json::json!({
                    "command": "decrypt",
                    "input": file.display().to_string(),
                    "output": out_path.display().to_string(),
                    "sender_id": format_id(&sender_id),
                    "sender_name": sender_name,
                    "bytes": bytes_written,
                }));
            } else {
                println!("Decrypted: {} -> {}", file.display(), out_path.display());
                println!("  Sender verified: {} ({})", sender_name, format_id(&sender_id));
                println!("  {} bytes recovered", bytes_written);
            }
            Ok(())
        }
        Err(e) => {
            // Verification failed — remove temp file so no unauthenticated
            // plaintext remains on disk.
            let _ = std::fs::remove_file(&temp_path);
            Err(e.into())
        }
    }
}

// ---------------------------------------------------------------------------
// Sign / Verify
// ---------------------------------------------------------------------------

fn run_sign(
    file: &std::path::Path,
    identity_id_hex: &str,
    output: Option<&std::path::Path>,
    json: bool,
    store: &FileStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let identity_id = parse_identity_id(identity_id_hex)?;
    let mut passphrase = read_passphrase("Passphrase: ")?;
    let ident = identity::load_identity(&identity_id, &passphrase, store)?;
    passphrase.zeroize();

    let data = std::fs::read(file)?;
    let sig_bytes = sign::sign(&ident, &data)?;

    let out_path = output
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| {
            let mut p = file.to_path_buf();
            let ext = p
                .extension()
                .map(|e| format!("{}.apqsig", e.to_string_lossy()))
                .unwrap_or_else(|| "apqsig".to_string());
            p.set_extension(ext);
            p
        });

    std::fs::write(&out_path, &sig_bytes)?;

    if json {
        emit_json(&serde_json::json!({
            "command": "sign",
            "input": file.display().to_string(),
            "output": out_path.display().to_string(),
            "signer_id": format_id(&ident.identity_id),
            "signature_bytes": sig_bytes.len(),
        }));
    } else {
        println!("Signed: {} -> {}", file.display(), out_path.display());
        println!("  {} bytes signature", sig_bytes.len());
    }
    Ok(())
}

fn run_verify(
    file: &std::path::Path,
    signature_path: &std::path::Path,
    signer_id_hex: &str,
    json: bool,
    store: &FileStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let signer_id = parse_identity_id(signer_id_hex)?;
    let signer = identity::load_contact(&signer_id, store)?;

    let data = std::fs::read(file)?;
    let sig_bytes = std::fs::read(signature_path)?;

    let valid = sign::verify(&signer, &data, &sig_bytes)?;

    if valid {
        if json {
            emit_json(&serde_json::json!({
                "command": "verify",
                "valid": true,
                "signer_id": format_id(&signer_id),
                "signer_name": signer.display_name,
            }));
        } else {
            println!("Signature VALID.");
            println!("  Signer: {} ({})", signer.display_name, format_id(&signer_id));
        }
        Ok(())
    } else {
        // Return through the normal error path so JSON mode and exit codes
        // are handled consistently.
        Err(Box::new(ApiError::AuthenticationFailed) as Box<dyn std::error::Error>)
    }
}
