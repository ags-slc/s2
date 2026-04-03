# Contributing to s2

Welcome! We appreciate your interest in contributing to s2.

## Quick Links

- [Report an Issue](../../issues/new)
- [Open Pull Requests](../../pulls)
- [Architecture Documentation](ARCHITECTURE.md) — design docs, data flow, ADRs
- [CLAUDE.md](CLAUDE.md) — build commands, module layout, PR requirements

---

## What is s2?

**s2 (Simple Secrets)** is a CLI tool that injects secrets into subprocess environments without ambient shell exposure. Secrets are encrypted at rest, never enter your parent shell, and are zeroized from memory after use.

---

## Ways to Contribute

| Type | Examples |
|------|----------|
| **Report** | File an issue with steps to reproduce, expected vs actual behavior |
| **Fix** | Bug fixes, security improvements |
| **Build** | New providers, new agent hooks, new commands |
| **Review** | Review open PRs, test changes locally |
| **Document** | Improve docs, add examples, clarify security model |

---

## Design Philosophy

Five principles guide every s2 design decision. Understanding them helps you write contributions that fit naturally.

### Secrets Never Enter the Parent Shell

`s2 exec` uses `execve` to replace the process. The parent shell never holds secrets. Any feature that leaks secrets into the parent environment (export, eval, source) is out of scope by design.

### Encrypted by Default

`s2 init` creates encrypted files. `set`/`unset` transparently handle encrypted files. Features should default to the secure path. Insecure options (like `--no-encrypt`) should be explicit opt-ins, not defaults.

### Fail Secure

When in doubt, refuse. s2 refuses to read files that aren't 0600. Values never appear in CLI args, logs, or Debug/Display output. If a feature could accidentally expose secrets, it shouldn't exist.

### Local-First

s2 works fully offline with local encrypted files. Remote providers (SSM, Vault) are optional. Features should not require network access or external services to function.

### Zero Residue

Secret memory is zeroized on drop. After `execve`, the original process is gone. Features should not create new paths for secrets to persist (temp files, logs, crash dumps).

---

## Development Setup

### Prerequisites

- Rust 1.91+ (`rustup update stable`)
- macOS or Linux
- On Linux: `sudo apt-get install libdbus-1-dev pkg-config`

### Build & Test

```bash
cargo build                                # default (includes SSM)
cargo test                                 # run all tests
cargo clippy --all-features -- -D warnings # lint (must pass)
cargo fmt --check                          # format (must pass)
```

### Project Structure

See [CLAUDE.md](CLAUDE.md) for the module layout and [ARCHITECTURE.md](ARCHITECTURE.md) for the full design documentation.

---

## Pull Request Requirements

Every PR must:

1. **Pass CI** — `cargo fmt --check`, `cargo clippy --all-features -- -D warnings`, `cargo test`
2. **Update docs** — if your PR changes behavior, update the relevant docs:
   - New/changed commands or flags → `README.md` and `CLAUDE.md`
   - Architecture or design changes → `ARCHITECTURE.md`
   - New config options → `README.md` (Configuration section)
   - Security model changes → `README.md` and `ARCHITECTURE.md`
   - Platform changes → `CLAUDE.md`, `install.sh`, release workflow
3. **Include tests** — new features need tests; bug fixes should include a regression test when feasible
4. **Keep scope focused** — one feature or fix per PR. Don't bundle unrelated changes.

If a PR changes behavior but not docs, it is not ready to merge.

---

## Adding a New Provider

Providers resolve URI-formatted secret values (e.g., `ssm:///path`, `vault://host/path`).

1. Create `src/provider/yourprovider.rs` implementing the `SecretProvider` trait
2. Gate it behind a feature flag in `Cargo.toml`
3. Register it in `ProviderRegistry::from_config()` in `src/provider/mod.rs`
4. Add config parsing in the `[providers.yourprovider]` section
5. Update `README.md`, `CLAUDE.md`, and `ARCHITECTURE.md`

See `src/provider/ssm.rs` and `src/provider/vault.rs` for examples.

---

## Adding a New Agent Hook

s2 supports AI agent hooks via `s2 hook --format <agent>`.

1. Add a variant to `HookFormat` in `src/cli.rs`
2. Add output serialization in `emit_rewrite()` and `passthrough()` in `src/commands/hook.rs`
3. If the agent needs a wrapper file (shell script, TypeScript plugin), add it to `hooks/<agent>/`
4. Update the "AI Agent Integration" section in `README.md`
5. Update the "Hook System" section in `ARCHITECTURE.md`

The rewrite logic is shared — only the JSON output format differs per agent.

---

## Security Considerations

s2 is a security tool. Contributions that could introduce vulnerabilities will be scrutinized carefully.

- **Never log, print, or expose secret values** — use `secrecy::SecretString` for all secret data
- **Never accept secret values as CLI arguments** — stdin only (prevents shell history exposure)
- **Never create files with permissions other than 0600** — use `permissions::set_secure_permissions()`
- **Never skip permission checks** — always call `permissions::check_permissions()` before reading secret files
- **Test for security properties** — not just functionality

If you're unsure whether a change has security implications, ask in the PR.

---

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
