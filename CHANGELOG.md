# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `s2 scan --allowlist <file>` to read/write the allowlist at a chosen path (default remains `.s2allowlist` in the cwd)
- Optional `S2_ALLOWLIST` environment variable and `[scan] allowlist` config key (precedence: `--allowlist` > env > config > `.s2allowlist`)

## [1.2.0] - 2026-04-08

### Added
- Per-profile provider overrides: `[profiles.X.providers.ssm]` replaces global provider config for that profile

## [1.1.2] - 2026-04-08

### Fixed
- Re-release of v1.1.1 fixes (early v1.1.1 binaries were built before the ArmoredReader fix landed)

## [1.1.1] - 2026-04-08

### Fixed
- Armored age files could not be decrypted — `Decryptor::new()` requires `ArmoredReader` wrapper in age 0.11
- `s2 init` stored keychain passphrase with relative path key, causing lookup failures on subsequent commands that use the canonical (absolute) path

## [1.1.0] - 2026-04-07

### Added
- Touch ID / biometric authentication for secret access (macOS only)
  - Set `biometric = true` in config to require Touch ID for all decrypt/exec operations
  - Existing keychain items auto-migrate to biometric protection on next access
  - Falls back to device passcode when no biometric hardware is available
  - Linux and CI/headless environments are unaffected (config option ignored)
- Hook guard: blocks AI agents from reading secret files or dumping environment variables
  - Detects `cat`, `head`, `grep`, `base64`, `cp`, `curl`, etc. targeting configured secret files
  - Blocks bare `env` and `printenv` (allows `env VAR=val cmd` and `printenv HOME`)
  - Detects input redirects (`< file`) and @-syntax (`curl -d @file`)
  - Configurable via `[hook.guard]` in config (enabled by default)

## [1.0.1] - 2026-04-06

### Fixed
- `s2 scan /dev/stdin` now works for piped input on macOS and Linux (#3)

## [1.0.0] - 2026-04-06

### Added
- `s2 completions` command for shell completion scripts (bash, zsh, fish, powershell)
- `s2 scan --list-rules` flag to display all built-in and custom scan rules
- Scan patterns for Supabase, Datadog, Heroku, and Azure (keyword-gated where needed)
- CHANGELOG.md

## [0.5.1] - 2026-04-04

### Fixed
- Entropy detection no longer fires on non-KEY=value files (e.g., scripts, markdown)

### Changed
- Added global pre-commit hook setup instructions to README

## [0.5.0] - 2026-04-04

### Added
- `s2 scan` command with pattern matching and Shannon entropy analysis
- 19 built-in scan rules for AWS, GitHub, Stripe, Slack, Google, Twilio, SendGrid, and more
- Custom scan rules via `[[scan.rules]]` in config
- `--learn` mode to test coverage against known secrets and suggest new rules
- `--allow` flag and `.s2allowlist` for suppressing known false positives
- Provider-specific patterns for Shopify, GitLab, DigitalOcean, Anthropic, OpenAI, npm, PyPI
- Placeholder value filtering to reduce false positives on sensitive key names

## [0.4.0] - 2026-04-03

### Added
- Multi-agent hook support: GitHub Copilot, Cursor, Codex, and OpenCode formats
- ARCHITECTURE.md with design decisions and ADRs
- CONTRIBUTING.md with development guidelines

### Fixed
- Vault provider skips initialization when unconfigured

## [0.3.0] - 2026-04-03

### Added
- Linux support for x86_64 and aarch64 architectures
- CI workflow with clippy, rustfmt, and cross-platform test matrix

### Changed
- `s2 init` now encrypts by default (use `--no-encrypt` for plaintext)
- `s2 set` and `s2 unset` transparently handle encrypted files

## [0.2.0] - 2026-04-03

### Added
- Claude Code PreToolUse hook for automatic secret injection
- AWS profile support in SSM provider config
- `--user` flag for single-user install to `~/.local/bin`
- MIT license

### Changed
- SSM provider enabled by default in builds and releases

### Fixed
- Auto-elevate with sudo when install directory is not writable
- macOS SIP workaround for install script

## [0.1.0] - 2026-04-03

### Added
- Core CLI commands: `exec`, `list`, `check`, `init`, `set`, `unset`, `encrypt`, `decrypt`, `edit`, `redact`
- Secret injection into subprocesses via execve (no parent process persists)
- age encryption with keychain-backed passphrases (macOS Keychain, Linux Secret Service)
- Provider architecture with URI scheme dispatch (SSM, Vault, env)
- Provider cache with TTL and offline fallback
- Binary distribution via GitHub Releases, crates.io, and curl installer

[Unreleased]: https://github.com/ags-slc/s2/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/ags-slc/s2/compare/v1.1.2...v1.2.0
[1.1.2]: https://github.com/ags-slc/s2/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/ags-slc/s2/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/ags-slc/s2/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/ags-slc/s2/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/ags-slc/s2/compare/v0.5.1...v1.0.0
[0.5.1]: https://github.com/ags-slc/s2/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/ags-slc/s2/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/ags-slc/s2/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ags-slc/s2/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ags-slc/s2/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ags-slc/s2/releases/tag/v0.1.0
