use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use secrecy::ExposeSecret;
use serde::Serialize;

use crate::config::Config;
use crate::crypto;
use crate::error::S2Error;
use crate::parser;
use crate::permissions;
use crate::provider::{self, ProviderRegistry, SecretUri};

/// Health-check secret files and emit one JSON report per file (JSONL) so a machine
/// consumer (e.g. a CI/deploy secrets preflight) can branch on *why* a file is unhealthy.
///
/// The check is a detection-gated escalation — each stage runs only if it applies and
/// every prior stage passed:
///
///   existence → permissions → decryption (passphrase test for encrypted files;
///                                          trivially ok for plaintext)
///             → provider (only if the content references `ssm:///` URIs)
///
/// Every outcome is classified into a stable [`Reason`] code (see the enum) rather than
/// collapsed into a single exit(1). Nothing is ever written.
///
/// Output mirrors `s2 scan` (see [`crate::commands::scan`]): a human-readable summary on
/// **stderr** by default, or — with `json` — one compact JSON object per file on
/// **stdout** (JSONL), so a machine consumer can pipe straight into `jq`. In JSON mode the
/// `reason`/`stages` are the intended surface; a consumer should branch on those, not the
/// exit code (a provider/AWS hiccup fails the process yet leaves `stages.decryption ==
/// "ok"`, which is what a self-heal keys off).
///
/// Exit code is 0 when every file is healthy, 1 otherwise — a negative *result*, not an
/// error (health did its job and reported), so it exits directly like `scan`/`check`
/// rather than routing a non-error through the `S2Error` channel.
///
/// Files are checked in one aggregating pass — every file is reported even if an earlier
/// one failed, so a preflight surfaces all problems at once.
///
/// Note: with `biometric = true`, decrypting each encrypted file triggers a Touch ID
/// prompt on macOS, so `s2 health` is NOT non-interactive there. On Linux/EKS biometric
/// is ignored. See README.
pub fn run(
    config: &Config,
    files: Vec<PathBuf>,
    profile: Option<String>,
    json: bool,
) -> Result<(), S2Error> {
    let files = config.resolve_files(&files, &profile)?;

    let reports: Vec<HealthReport> = files
        .iter()
        .map(|path| evaluate(path, config, &profile))
        .collect();

    if json {
        // Machine-readable: one compact JSON object per line on stdout.
        for report in &reports {
            println!(
                "{}",
                serde_json::to_string(report).expect("report serializes")
            );
        }
    } else {
        // Human-readable: everything on stderr, keeping stdout clean (matches `scan`).
        print_human(&reports);
    }

    if reports.iter().any(|r| r.status == Status::Fail) {
        // A negative result, not an error: output is already emitted, and nothing
        // sensitive is live here (no SecretString, no cache, no temp file), so exit
        // directly with a non-zero code — same as `scan`/`check`. Routing this through
        // `S2Error` would print an error line over the report and mismodel a result as
        // a failure.
        std::process::exit(1);
    }
    Ok(())
}

/// Human summary to stderr — one line per file plus a tally (mirrors `scan`'s stderr).
fn print_human(reports: &[HealthReport]) {
    for r in reports {
        match r.status {
            Status::Ok => eprintln!("  {}  ok ({})", r.file, reason_str(r.reason)),
            Status::Fail => {
                let detail = r
                    .detail
                    .as_deref()
                    .map(|d| format!("  ({d})"))
                    .unwrap_or_default();
                eprintln!("  {}  FAIL: {}{}", r.file, reason_str(r.reason), detail);
            }
        }
    }
    let unhealthy = reports.iter().filter(|r| r.status == Status::Fail).count();
    if unhealthy == 0 {
        eprintln!("\n{} file(s) healthy", reports.len());
    } else {
        eprintln!("\n{} of {} file(s) unhealthy", unhealthy, reports.len());
    }
}

/// The wire string for a reason (same value serde emits), for human output.
fn reason_str(reason: Reason) -> &'static str {
    match reason {
        Reason::Healthy => "healthy",
        Reason::NotFound => "not_found",
        Reason::BadPermissions => "bad_permissions",
        Reason::Unreadable => "unreadable",
        Reason::PassphraseMissing => "passphrase_missing",
        Reason::DecryptionFailed => "decryption_failed",
        Reason::ParseError => "parse_error",
        Reason::ProviderUnreachable => "provider_unreachable",
        Reason::AccessDenied => "access_denied",
    }
}

/// Overall verdict for a file. `ok` iff every applicable stage passed.
#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
enum Status {
    Ok,
    Fail,
}

/// Outcome of a single stage.
#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
enum StageState {
    /// Stage ran and passed.
    Ok,
    /// Stage ran and failed.
    Fail,
    /// Stage did not apply (not detected) or a prior stage failed.
    Skipped,
}

/// Classified reason for the verdict. Stable machine codes — consumers branch on these.
/// Each maps to a remediation lane:
/// - `healthy` — no action
/// - `not_found` / `bad_permissions` / `unreadable` — config/deploy problem
/// - `passphrase_missing` — keychain passphrase evicted/churned → re-import / re-key (self-heal)
/// - `decryption_failed` — wrong passphrase or corrupted ciphertext → restore from backup
/// - `parse_error` — decrypts but content isn't valid `KEY=value`
/// - `provider_unreachable` — creds/region/endpoint couldn't be reached → transient; do NOT re-key
/// - `access_denied` — provider reached but IAM denies the path → grant the policy
#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
enum Reason {
    Healthy,
    NotFound,
    BadPermissions,
    Unreadable,
    PassphraseMissing,
    DecryptionFailed,
    ParseError,
    ProviderUnreachable,
    AccessDenied,
}

#[derive(Serialize, Debug)]
struct Stages {
    existence: StageState,
    permissions: StageState,
    decryption: StageState,
    provider: StageState,
}

#[derive(Serialize, Debug)]
struct HealthReport {
    file: String,
    status: Status,
    reason: Reason,
    stages: Stages,
    /// Human-readable detail (the underlying error message), omitted when healthy.
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

impl HealthReport {
    fn healthy(file: String, stages: Stages) -> Self {
        Self {
            file,
            status: Status::Ok,
            reason: Reason::Healthy,
            stages,
            detail: None,
        }
    }

    fn fail(file: String, reason: Reason, stages: Stages, detail: impl Into<String>) -> Self {
        Self {
            file,
            status: Status::Fail,
            reason,
            stages,
            detail: Some(detail.into()),
        }
    }
}

/// Run the detection-gated chain for one file and produce its report. Never panics on a
/// bad file: every failure mode is caught and classified.
fn evaluate(path: &Path, config: &Config, profile: &Option<String>) -> HealthReport {
    let file = path.display().to_string();
    let mut stages = Stages {
        existence: StageState::Fail,
        permissions: StageState::Skipped,
        decryption: StageState::Skipped,
        provider: StageState::Skipped,
    };

    // ── existence ─────────────────────────────────────────────────────────
    let canonical = match path.canonicalize() {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return HealthReport::fail(file, Reason::NotFound, stages, e.to_string());
        }
        // Permission-denied / broken symlink / etc. — a real I/O fault, not "missing".
        Err(e) => return HealthReport::fail(file, Reason::Unreadable, stages, e.to_string()),
    };
    stages.existence = StageState::Ok;

    // ── permissions (must be 0600) ────────────────────────────────────────
    if let Err(e) = permissions::check_permissions(&canonical) {
        stages.permissions = StageState::Fail;
        return HealthReport::fail(file, Reason::BadPermissions, stages, e.to_string());
    }
    stages.permissions = StageState::Ok;

    let bytes = match std::fs::read(&canonical) {
        Ok(b) => b,
        Err(e) => return HealthReport::fail(file, Reason::Unreadable, stages, e.to_string()),
    };

    // ── decryption (only if age-encrypted; plaintext is a legitimate state) ─
    let content = if crypto::is_age_encrypted(&bytes) {
        match crypto::decrypt_file_content(&canonical, &bytes, config.biometric) {
            Ok(c) => {
                stages.decryption = StageState::Ok;
                c
            }
            // Keychain/file-store miss — passphrase evicted or churned.
            Err(S2Error::Keychain(m)) => {
                stages.decryption = StageState::Fail;
                return HealthReport::fail(file, Reason::PassphraseMissing, stages, m);
            }
            // Wrong passphrase or corrupted ciphertext.
            Err(e) => {
                stages.decryption = StageState::Fail;
                return HealthReport::fail(file, Reason::DecryptionFailed, stages, e.to_string());
            }
        }
    } else {
        // Plaintext (`--no-encrypt`) file: a legitimate state. The content is trivially
        // accessible (no passphrase needed), so the decryption stage PASSES — health
        // does not enforce encryption, and a consumer branching on `stages.decryption
        // == "ok"` must treat plaintext as healthy. Continue to the provider stage.
        match String::from_utf8(bytes) {
            Ok(c) => {
                stages.decryption = StageState::Ok;
                c
            }
            Err(e) => return HealthReport::fail(file, Reason::Unreadable, stages, e.to_string()),
        }
    };

    // ── provider (only if the content references provider URIs) ────────────
    let uris = match collect_provider_uris(&canonical, &content) {
        Ok(u) => u,
        Err(e) => return HealthReport::fail(file, Reason::ParseError, stages, e.to_string()),
    };
    if uris.is_empty() {
        return HealthReport::healthy(file, stages);
    }
    match probe_providers(&uris, config, profile) {
        Ok(()) => {
            stages.provider = StageState::Ok;
            HealthReport::healthy(file, stages)
        }
        Err((reason, detail)) => {
            stages.provider = StageState::Fail;
            HealthReport::fail(file, reason, stages, detail)
        }
    }
}

/// Parse a file's plaintext and return every provider URI it references (literal values
/// skipped). Used to scope the provider probe to the exact paths the file will read.
fn collect_provider_uris(path: &Path, content: &str) -> Result<Vec<SecretUri>, S2Error> {
    let entries = parser::parse_file(path, content)?;
    Ok(entries
        .into_iter()
        .filter_map(|e| provider::parse_uri(e.value.expose_secret()))
        .collect())
}

/// Probe each referenced provider for reachability + authorization (no secret values
/// pulled, no cache written). Returns the classified reason on the first failure.
fn probe_providers(
    uris: &[SecretUri],
    config: &Config,
    profile: &Option<String>,
) -> Result<(), (Reason, String)> {
    let mut by_scheme: BTreeMap<String, Vec<SecretUri>> = BTreeMap::new();
    for uri in uris {
        by_scheme
            .entry(uri.scheme.clone())
            .or_default()
            .push(uri.clone());
    }

    let registry = ProviderRegistry::from_config(config.effective_providers(profile))
        .map_err(|e| (Reason::ProviderUnreachable, e.to_string()))?;

    for (scheme, hints) in &by_scheme {
        let prov = registry.get(scheme).ok_or_else(|| {
            (
                Reason::ProviderUnreachable,
                format!("no provider for scheme '{scheme}' (is the feature flag enabled?)"),
            )
        })?;
        if let Err(e) = prov.health_check(hints) {
            return Err((classify_provider_error(&e), e.to_string()));
        }
    }
    Ok(())
}

/// Distinguish "reached but forbidden" from "couldn't reach / no creds". The provider
/// layer classifies AWS failures from the typed error code and surfaces an authorization
/// denial as `S2Error::ProviderAccessDenied`; every other failure (dispatch failure, no
/// credentials, region/DNS) arrives as `S2Error::Provider` and is treated as unreachable.
fn classify_provider_error(err: &S2Error) -> Reason {
    match err {
        S2Error::ProviderAccessDenied(_) => Reason::AccessDenied,
        _ => Reason::ProviderUnreachable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn to_value(r: &HealthReport) -> Value {
        serde_json::from_str(&serde_json::to_string(r).unwrap()).unwrap()
    }

    #[test]
    fn healthy_report_serializes_typed_fields() {
        let r = HealthReport::healthy(
            "/x/.secrets".into(),
            Stages {
                existence: StageState::Ok,
                permissions: StageState::Ok,
                decryption: StageState::Ok,
                provider: StageState::Skipped,
            },
        );
        let v = to_value(&r);
        assert_eq!(v["file"], "/x/.secrets");
        assert_eq!(v["status"], "ok");
        assert_eq!(v["reason"], "healthy");
        assert_eq!(v["stages"]["decryption"], "ok");
        assert_eq!(v["stages"]["provider"], "skipped");
        // detail omitted when healthy
        assert!(v.get("detail").is_none());
    }

    #[test]
    fn fail_report_carries_reason_stage_and_detail() {
        let r = HealthReport::fail(
            "/x/.secrets".into(),
            Reason::PassphraseMissing,
            Stages {
                existence: StageState::Ok,
                permissions: StageState::Ok,
                decryption: StageState::Fail,
                provider: StageState::Skipped,
            },
            "passphrase not found in keychain or file store",
        );
        let v = to_value(&r);
        assert_eq!(v["status"], "fail");
        assert_eq!(v["reason"], "passphrase_missing");
        assert_eq!(v["stages"]["decryption"], "fail");
        assert_eq!(
            v["detail"],
            "passphrase not found in keychain or file store"
        );
    }

    #[test]
    fn reason_codes_are_snake_case() {
        // Guard the exact wire strings consumers branch on.
        for (reason, wire) in [
            (Reason::Healthy, "healthy"),
            (Reason::NotFound, "not_found"),
            (Reason::BadPermissions, "bad_permissions"),
            (Reason::Unreadable, "unreadable"),
            (Reason::PassphraseMissing, "passphrase_missing"),
            (Reason::DecryptionFailed, "decryption_failed"),
            (Reason::ParseError, "parse_error"),
            (Reason::ProviderUnreachable, "provider_unreachable"),
            (Reason::AccessDenied, "access_denied"),
        ] {
            assert_eq!(serde_json::to_value(reason).unwrap(), wire);
            // The human-output mapping must not drift from the JSON wire string.
            assert_eq!(reason_str(reason), wire);
        }
    }

    #[test]
    fn access_denied_maps_from_typed_variant_not_message() {
        // The provider layer classifies AWS failures from the typed error code and hands
        // back distinct variants (see `ssm::classify_probe_error`). The health layer maps
        // the variant, never the message string — so an IAM denial reaches `access_denied`
        // and everything else reaches `provider_unreachable`.
        assert_eq!(
            classify_provider_error(&S2Error::ProviderAccessDenied("denied on '/p/'".into())),
            Reason::AccessDenied
        );
        assert_eq!(
            classify_provider_error(&S2Error::Provider("dispatch failure".into())),
            Reason::ProviderUnreachable
        );
    }

    #[test]
    fn collect_provider_uris_extracts_and_skips_literals() {
        let content = "\
LITERAL=plain-value
DB=ssm:///prod/apps/service-a/secrets/db
API=ssm:///prod/apps/service-a/secrets/api
";
        let uris = collect_provider_uris(Path::new("test.env"), content).unwrap();
        assert_eq!(uris.len(), 2);
        assert!(uris.iter().all(|u| u.scheme == "ssm"));
    }
}
