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
- **Encrypted by default** — `s2 init` creates encrypted files. `s2 set`/`s2 unset` transparently decrypt, modify, and re-encrypt. Pass `--no-encrypt` to init for plaintext.
- **Keychain with file fallback** — passphrases stored in macOS Keychain or Linux Secret Service (D-Bus). On headless systems without a keyring, falls back to `~/.config/s2/keys/` with 0600 permissions.
- **Feature flags**: `provider-ssm` (default), `provider-vault` (opt-in). SSM deps are heavy; Vault needs `reqwest`.

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
