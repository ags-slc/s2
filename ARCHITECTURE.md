# s2 Architecture

> System design, data flow, and key decisions for s2 (Simple Secrets).

---

## Table of Contents

1. [Design Principles](#design-principles)
2. [Data Flow](#data-flow)
3. [Module Organization](#module-organization)
4. [Security Architecture](#security-architecture)
5. [Encryption & Keychain](#encryption--keychain)
6. [Provider System](#provider-system)
7. [Hook System](#hook-system)
8. [Architecture Decision Records](#architecture-decision-records)

---

## Design Principles

1. **Secrets never enter the parent shell** — `s2 exec` uses `execve` to replace the process, not `fork`+`exec`. The parent process ceases to exist.
2. **Encrypted by default** — `s2 init` creates encrypted files. `set`/`unset` transparently decrypt-modify-re-encrypt.
3. **Fail secure** — refuses to read files with permissions other than 0600. Values never appear in CLI args, logs, or Debug/Display output.
4. **Zero residue** — `secrecy::SecretString` and `zeroize` clear secret memory on drop. After `execve`, the original process (and its memory) is gone.
5. **Local-first** — works fully offline with local encrypted files. Remote providers (SSM, Vault) are optional and cached with offline fallback.

---

## Data Flow

### Secret Injection (`s2 exec`)

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌─────────────┐
│ Config       │────▶│ Load Files   │────▶│ Resolve      │────▶│ execve()    │
│ Resolution   │     │ (auto-       │     │ Provider URIs│     │ (process    │
│              │     │  decrypt)    │     │ (SSM, Vault) │     │  replaced)  │
│ CLI flags    │     │              │     │              │     │             │
│ > profile    │     │ 0600 check   │     │ Cache w/     │     │ env = secrets│
│ > defaults   │     │ age detect   │     │ TTL fallback │     │ + inherited │
└─────────────┘     └──────────────┘     └──────────────┘     └─────────────┘
```

1. **Config resolution** (`config.rs`): CLI `-f`/`-p` flags → profile → `default_files`. Determines which files to load and which keys to inject.
2. **File loading** (`store.rs`): Reads each file, auto-detects age encryption (magic bytes), decrypts in-memory via keychain passphrase. Parses `KEY=value` format.
3. **Provider resolution** (`provider/`): If a value is a URI (e.g., `ssm:///path`), resolves it via the provider registry. Results are cached with TTL and offline fallback.
4. **Process replacement** (`exec.rs`): Builds env vars (inherited + secrets overlay), flushes provider cache (destructors won't run after execve), then calls `nix::unistd::execve`. The s2 process is gone — only the target command remains.

### Secret Modification (`s2 set`, `s2 unset`)

```
Read file → detect encryption → decrypt if needed → parse → modify → serialize → re-encrypt if needed → write
```

Both commands transparently handle encrypted files by checking `crypto::is_age_encrypted()` before parsing and re-encrypting with the same passphrase after modification.

---

## Module Organization

```
src/
├── main.rs              Entry point. CLI parse, config load, lazy provider init, dispatch.
├── cli.rs               Clap derive structs. Command enum with all subcommands.
├── config.rs            TOML config (~/.config/s2/config.toml). Profiles, hook config,
│                        provider config. File/key resolution priority logic.
├── error.rs             S2Error enum (thiserror). All error variants.
│
├── commands/            One file per subcommand.
│   ├── exec.rs          Secret injection via execve. PATH resolution. Env building.
│   ├── list.rs          List key names + source files (never values).
│   ├── check.rs         Existence check (exit 0/1).
│   ├── init.rs          Create new file, encrypted by default.
│   ├── set.rs           Add/update key (stdin only). Handles encrypted files.
│   ├── unset.rs         Remove key. Handles encrypted files.
│   ├── encrypt.rs       Encrypt plaintext file with age.
│   ├── decrypt.rs       Decrypt age file to plaintext.
│   ├── edit.rs          Decrypt → $EDITOR → re-encrypt.
│   ├── redact.rs        Aho-Corasick multi-pattern replacement on stdin.
│   └── hook.rs          Claude Code PreToolUse handler. JSON stdin/stdout.
│
├── store.rs             SecretStore: in-memory HashMap of secrets. Loads files,
│                        resolves provider URIs, builds env maps.
├── parser.rs            Parses KEY=value, export KEY=value, quoted values.
│                        Serializes entries back to file format.
├── crypto.rs            age encryption/decryption. Passphrase generation.
│                        Auto-detection via magic bytes.
├── keychain.rs          System keyring (macOS Keychain / Linux Secret Service)
│                        with file-based fallback (~/.config/s2/keys/).
├── permissions.rs       Unix 0600 check and enforcement.
├── audit.rs             Append-only audit log.
│
└── provider/            Dynamic secret resolution from external sources.
    ├── mod.rs           SecretProvider trait. ProviderRegistry. URI parsing.
    ├── cache.rs         Encrypted on-disk cache with TTL. Offline fallback.
    ├── env.rs           env:// provider (reads from current environment).
    ├── ssm.rs           AWS SSM Parameter Store (feature-gated).
    └── vault.rs         HashiCorp Vault KV v2 (feature-gated).
```

### Dependency Flow

```
main.rs → cli.rs (parse) → config.rs (load) → commands/* (dispatch)
                                                    │
commands/* → store.rs → parser.rs (parse files)
                     → crypto.rs → keychain.rs (decrypt)
                     → provider/* (resolve URIs)
                     → permissions.rs (0600 checks)
```

Provider and cache initialization is **lazy** — only commands that load secrets (exec, list, check, redact) construct the `ProviderRegistry` and `ProviderCache`. The hook command skips this entirely for fast startup.

---

## Security Architecture

### Process Model

```
Parent shell                s2 exec                    Target command
┌──────────┐    fork()     ┌──────────┐   execve()    ┌──────────┐
│ no secrets│───────────▶  │ loads    │──────────────▶ │ secrets  │
│ in env    │              │ secrets  │                │ in env   │
└──────────┘              │ into mem │                └──────────┘
                          └──────────┘
                          (this process
                           ceases to exist)
```

Key: `execve` **replaces** the process. There is no parent process holding secrets after exec. This differs from `fork`+`exec` where a parent persists.

### Memory Safety

- All secret values are `secrecy::SecretString` — `Debug` and `Display` are redacted.
- `zeroize` attribute on structs ensures memory is zeroed on drop.
- Provider cache is flushed to disk **before** `execve` (since destructors won't run).

### File Security

- `permissions.rs` enforces 0600 (owner read/write only) on all secret files.
- s2 **refuses to read** files that are group or world readable.
- Audit log is created with 0600 permissions.

### Value Handling

- `s2 set` reads from **stdin only** — values never appear in CLI args or shell history.
- `s2 list` shows key names, never values.
- `s2 redact` uses Aho-Corasick for efficient multi-pattern replacement in streams.

---

## Encryption & Keychain

### Encryption Layer

s2 uses [age](https://age-encryption.org/) with passphrase-based encryption (scrypt KDF). Files are armored (ASCII-safe).

Detection is automatic via magic bytes:
- `-----BEGIN AGE ENCRYPTED FILE-----` (armored)
- `age-encryption.org/` (binary)

### Keychain Architecture

```
store_passphrase() / get_passphrase()
         │
         ▼
   ┌─────────────┐
   │ System       │ ──── macOS: Apple Keychain (security-framework)
   │ Keyring      │ ──── Linux: D-Bus Secret Service (GNOME Keyring / KDE Wallet)
   │ (keyring     │
   │  crate)      │
   └──────┬───────┘
          │ on failure
          ▼
   ┌─────────────┐
   │ File-based   │ ──── ~/.config/s2/keys/<sha256>.key
   │ Fallback     │ ──── 0600 permissions, 0700 directory
   └─────────────┘
```

The fallback is transparent — callers never know which backend stored the passphrase. This enables headless Linux servers and CI environments where no desktop keyring is available.

### Platform Dependencies

| Platform | Keyring Feature | Backend | Fallback |
|----------|----------------|---------|----------|
| macOS | `apple-native` | Apple Keychain | File-based |
| Linux | `linux-native` | D-Bus Secret Service | File-based |
| WSL | `linux-native` | (usually unavailable) | File-based |

---

## Provider System

Providers resolve URI-formatted secret values at runtime.

### URI Format

```
scheme://[authority]/path[#fragment]

ssm:///prod/apps/myapp/secrets/DB_PASSWORD
vault://vault.example.com/secret/data/myapp#password
env://HOME
```

### Provider Trait

```rust
pub trait SecretProvider: Send + Sync {
    fn scheme(&self) -> &str;
    fn resolve(&self, uri: &SecretUri) -> Result<SecretString, S2Error>;
    fn display_name(&self) -> &str;
}
```

### Provider Cache

Provider-resolved values are cached in an age-encrypted file with per-entry TTL:

1. On resolve: check cache → if fresh, return cached value.
2. On cache miss or stale: call provider → cache result with timestamp.
3. On provider failure: if stale cache exists, use it (offline fallback).
4. Cache is flushed before `execve` (destructors won't run).

---

## Hook System

The `s2 hook` subcommand integrates with AI coding agents as a PreToolUse handler. The `--format` flag selects the output JSON format for each agent.

### Flow

```
AI Agent                       s2 hook                     AI Agent
┌──────────┐    JSON stdin    ┌──────────┐    JSON stdout  ┌──────────┐
│ agent     │────────────────▶│ detect   │───────────────▶ │ runs     │
│ runs      │                 │ command, │                  │ rewritten│
│ "aws s3"  │                 │ rewrite  │                  │ command  │
└──────────┘                 └──────────┘                 └──────────┘
```

### Format Adapters

The rewrite logic (input parsing, guard conditions, `build_wrapped_command`) is shared. Only the output serialization differs:

| Format | Flag | Output (rewrite) | Output (passthrough) |
|--------|------|-------------------|---------------------|
| Claude Code | `--format claude` (default) | `{"hookSpecificOutput":{"updatedInput":{"command":"..."}}}` | empty |
| Copilot | `--format copilot` | same as claude | empty |
| Cursor | `--format cursor` | `{"permission":"allow","updated_input":{"command":"..."}}` | `{}` |

Agents without programmatic hooks:
- **Codex**: prompt-level awareness file (`hooks/codex/s2-awareness.md`)
- **OpenCode**: TypeScript plugin (`hooks/opencode/s2.ts`) that calls `s2 hook --format cursor`

### Guard Conditions (passthrough)

- Tool is not `Bash`
- Command starts with `s2` or contains `s2 exec` (prevents infinite loops)
- Root command not in configured `commands` allowlist
- Root command is in `skip` list
- No files/profile configured (can't construct valid `s2 exec`)

### Command Wrapping

- **Simple commands**: `aws s3 ls` → `s2 exec -p aws -- aws s3 ls`
- **Complex commands** (pipes, chains): `aws s3 ls | grep x` → `s2 exec -p aws -- bash -c 'aws s3 ls | grep x'`

---

## Architecture Decision Records

### ADR-1: `execve` over `fork+exec`

**Decision:** Use `nix::unistd::execve` to replace the process rather than spawning a child.

**Why:** After execve, the s2 process no longer exists. Secrets are only in the target process's memory. With fork+exec, the parent process would persist with secrets in its address space, visible via `/proc/pid/environ`. Signals also forward correctly since the target IS the process.

**Tradeoff:** s2 can't do post-exec cleanup (destructors don't run). Provider cache must be flushed explicitly before execve.

### ADR-2: Encrypted by Default

**Decision:** `s2 init` creates encrypted files by default.

**Why:** Plaintext secret files on disk are the most common secret leak vector. Encrypting by default means accidental git commits, backup tools, or file sharing only expose ciphertext. The `--no-encrypt` flag is available for CI/dev scenarios.

### ADR-3: Keychain with File Fallback

**Decision:** Try system keyring first, fall back to file-based storage.

**Why:** System keyrings (macOS Keychain, GNOME Keyring) provide the best security — passphrases are protected by the OS login session. But headless servers and CI runners don't have desktop keyrings. File-based fallback (`~/.config/s2/keys/`, 0600 permissions) enables these environments without requiring `--no-encrypt`.

### ADR-4: Lazy Provider Initialization

**Decision:** `ProviderRegistry` and `ProviderCache` are only constructed for commands that load secrets (exec, list, check, redact).

**Why:** The `s2 hook` command runs on every Bash invocation in Claude Code. It must be fast (<5ms). Loading the provider cache involves file I/O and potentially age decryption. Lazy init keeps the hook path minimal: config parse + JSON parse + string match.

### ADR-5: stdin-Only for Secret Values

**Decision:** `s2 set` reads values exclusively from stdin, never from CLI arguments.

**Why:** CLI arguments are visible in `ps` output, shell history (`~/.bash_history`, `~/.zsh_history`), and process audit logs. Reading from stdin (`echo "val" | s2 set KEY`) avoids all three vectors. The pipe is ephemeral and not logged.
