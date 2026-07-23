# s2 — Simple Secrets

## Build & Test

```bash
cargo build                        # default (includes SSM provider)
cargo build --all-features         # includes SSM + Vault providers
cargo test                         # run all tests
cargo clippy --all-features -- -D warnings  # lint
cargo fmt --check                  # format check
```

## Module Layout

- `src/main.rs` — CLI entry point, dispatches to commands. Provider/cache init is lazy (only for commands that need them).
- `src/cli.rs` — Clap derive structs. All subcommands defined as `Command` enum variants.
- `src/config.rs` — TOML config from `~/.config/s2/config.toml`. Profiles, hook config, provider config.
- `src/commands/` — One file per subcommand (exec, list, check, set, hook, etc.).
- `src/provider/` — `SecretProvider` trait + implementations (SSM, Vault, env). Feature-gated. Cache with TTL + offline fallback.
- `src/store.rs` — `SecretStore` loads files, resolves provider URIs, holds secrets in memory.
- `src/crypto.rs` — age encryption/decryption with keychain-backed passphrases.
- `src/parser.rs` — Parses `KEY=value` / `export KEY=value` formats.

## Key Conventions

- **Secret values use `secrecy::SecretString`** — never log, print, or expose them. Values are zeroized on drop.
- **`execve` replaces the process** in `s2 exec` — no parent process persists after exec.
- **File permissions are enforced** — s2 refuses to read files that aren't 0600.
- **stdin-only for secret values** — `s2 set` reads from stdin, never CLI args.
- **Bulk import via `s2 migrate`** — reads a plaintext `.env`-style file (permissions not enforced on the source; it's treated as throwaway input) and upserts each `KEY=value` into the target secret file. `*` prefix-import keys are skipped. Pass `--ssm <prefix>` to discard source values and rewrite each entry as `KEY=ssm:///<prefix>/<KEY>` (the file becomes a reference file that resolves against AWS SSM at exec time; the plaintext warning is suppressed since on-disk values are URIs, not secrets).
- **`s2 health` is a non-destructive probe** — human summary on stderr by default, `--json` for one JSON report per file (JSONL) on stdout (both modeled on `scan`: machine output → stdout, human → stderr, exit 0 healthy / 1 unhealthy). It walks a detection-gated escalation: existence → permissions → decryption (passphrase test for encrypted files; trivially ok for plaintext) → provider (only if `ssm:///` refs present). Every outcome is a stable `reason` code (`healthy`, `not_found`, `bad_permissions`, `unreadable`, `passphrase_missing`, `decryption_failed`, `parse_error`, `provider_unreachable`, `access_denied`) + `stages.{existence,permissions,decryption,provider}` = `ok|fail|skipped` — consumers branch on the JSON, not the exit code (a provider/AWS hiccup fails the process but leaves `stages.decryption == "ok"`, which is what a self-heal keys off). Reasons are classified from `S2Error` variants (`Keychain`→`passphrase_missing`, `Encryption`→`decryption_failed`, `UnsafePermissions`→`bad_permissions`, `ProviderAccessDenied`→`access_denied`, `Provider`→`provider_unreachable`). The `access_denied`/`provider_unreachable` split is decided in the provider layer from the typed AWS error code (`ProvideErrorMetadata::code() == "AccessDeniedException"`), **not** from the error's `Display` string — `SdkError`'s `Display` collapses every service error to the literal `"service error"`, so a substring match would misfile every IAM denial as `provider_unreachable` (the "transient, do not re-key" lane). Plaintext (`--no-encrypt`) files are healthy with `decryption: ok` (content is trivially accessible, so the stage passes rather than skips) — health does not enforce encryption, and consumers branching on `stages.decryption == "ok"` treat plaintext as healthy. The provider stage is a reachability+auth probe via `SecretProvider::health_check`: one SSM `GetParametersByPath` per referenced prefix (`max_results(1)` + `with_decryption(false)`), scoped to the file's prefixes (not root, since IAM is typically `.../secrets/*`), pulling no secret values and writing no cache. A self-heal guard consumes the JSON via `jq -e '.stages.decryption == "ok"'` so a provider hiccup never triggers a needless re-key.
- **Encrypted by default** — `s2 init` creates encrypted files. `s2 set`/`s2 unset` transparently decrypt, modify, and re-encrypt. Pass `--no-encrypt` to init for plaintext.
- **Keychain with file fallback** — passphrases stored in macOS Keychain or Linux Secret Service (D-Bus). On headless systems without a keyring, falls back to `~/.config/s2/keys/` with 0600 permissions.
- **Feature flags**: `provider-ssm` (default), `provider-vault` (opt-in). SSM deps are heavy; Vault needs `reqwest`.
- **`s2 scan` must be instant** — designed as a pre-commit hook, runs on every commit. No network calls, no heavy deps. Pure compiled regexes + O(n) Shannon entropy. No external databases, API calls, or signature downloads.
- **Hook guard blocks secret exposure** — when AI agent hooks are configured, the guard blocks commands that would read secret files (`cat`, `grep`, etc.) or dump env vars (bare `env`/`printenv`). Enabled by default, configurable via `[hook.guard]`.
- **Silent-failure integrations need explicit proof of life.** For features whose failure mode is "appears to work but does nothing" (hook output, guard blocks, webhook posts), add a test or invariant that proves the integration is actively intercepting — not just a test that the output *shape* looks right. Precedent: the Claude hook shipped without `hookEventName` for 17 days (2026-04-03 → 2026-04-24, fixed in PR #17) because "command ran normally" is indistinguishable from "command was wrapped and ran normally," and the guard-block path had the same omission — so `cat .secrets` under an AI agent was silently *not* blocked.

## External Schema Adapters

When a struct is serialized as input to an external tool's schema (AI agent hooks, webhooks, CI integrations), the following rules are merge-blocking:

- **Link the schema from the source.** Each such struct (e.g. `ClaudeOutput`, `ClaudeBlockOutput`, `CursorOutput` in `src/commands/hook.rs`) must carry a doc-comment with a URL to the current published schema. Re-fetch the schema when adding or modifying the adapter — do not work from memory or a stale sample.
- **Tests must parse serialized JSON and assert typed fields.** Use `serde_json::Value` + `assert_eq!` on named fields under the full path, not `output.contains("…")`. Substring checks pass whether or not required fields exist, so they cannot catch schema-omission bugs and create a false sense of coverage.
- **Capture a fixture from the consumer's docs** and diff serialized output against it. Unit tests prove *our* struct serializes the way *we* expect; a fixture test proves it matches what the *consumer* expects. This is what catches schema drift between releases of the external tool.
- **Any new format variant in a shared enum arm** (e.g. `HookFormat::Claude | HookFormat::Copilot => …`) must be justified in the PR description with a link to the new consumer's schema, confirming it genuinely accepts the shared struct. Extra fields are usually ignored, but missing required fields fail silently.

## Platform Support

- **macOS** (arm64, x86_64) — uses Apple Keychain via `keyring` crate with `apple-native` feature
- **Linux** (x86_64, aarch64) — uses D-Bus Secret Service via `keyring` crate with `linux-native` feature; file-based fallback for headless servers
- Linux builds require `libdbus-1-dev` and `pkg-config` to compile

## PR Requirements

Every PR must update relevant documentation. This is a merge-blocking requirement.

- **New/changed commands or flags** → update `README.md` (Commands table, Quick Start) and `CLAUDE.md` (Key Conventions)
- **Architecture or design changes** → update `ARCHITECTURE.md`
- **New config options** → update `README.md` (Configuration section)
- **Security model changes** → update `README.md` (Security Model) and `ARCHITECTURE.md` (Security Architecture)
- **Platform changes** → update `CLAUDE.md` (Platform Support), `install.sh`, and release workflow

If a PR changes behavior but not docs, it is not ready to merge.

## Release

Tag `vX.Y.Z` and push to trigger the release workflow. Builds macOS arm64 + x86_64 with `--all-features`, creates a GitHub Release, and publishes to crates.io.
