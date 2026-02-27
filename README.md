# s2 — Simple Secrets

Inject secrets into subprocess environments without ambient shell exposure. Secrets never enter your parent shell, never appear in `env`/`printenv`, and are encrypted at rest with keychain-backed passphrases.

## Install

```bash
cargo install --path .
```

## Quick Start

```bash
# Create a secret file
s2 init ~/.secrets

# Add a secret (reads value from stdin, never from CLI args)
echo "my-token" | s2 set PEERDB_AUTH_TOKEN -f ~/.secrets

# Run a command with secrets injected
s2 exec -f ~/.secrets -- novahub mirror list

# List available keys (never shows values)
s2 list -f ~/.secrets

# Check if required keys exist
s2 check PEERDB_AUTH_TOKEN API_KEY -f ~/.secrets

# Encrypt the file at rest
s2 encrypt ~/.secrets

# Edit encrypted file (decrypts → $EDITOR → re-encrypts)
s2 edit ~/.secrets

# Filter sensitive output through redact
kubectl logs pod | s2 redact -f ~/.secrets
```

## Commands

| Command | Description |
|---------|-------------|
| `s2 exec` | Load secrets and exec a command with them in the environment |
| `s2 list` | List secret key names and source files (never values) |
| `s2 check` | Exit 0 if all specified keys exist, exit 1 with missing names |
| `s2 init` | Create a new secret file with 0600 permissions |
| `s2 set` | Set a secret (reads value from stdin) |
| `s2 unset` | Remove a secret from a file |
| `s2 encrypt` | Encrypt a file with age (passphrase stored in keychain) |
| `s2 decrypt` | Decrypt an age-encrypted file |
| `s2 edit` | Decrypt → $EDITOR → re-encrypt |
| `s2 redact` | Pipe filter replacing secret values with `[REDACTED]` |

## Configuration

Create `~/.config/s2/config.toml`:

```toml
default_files = ["~/.secrets"]
audit_log = "~/.config/s2/audit.log"

[profiles.peerdb]
files = ["~/.secrets"]
keys = ["PEERDB_AUTH_TOKEN"]

[profiles.deploy]
files = ["~/.secrets", ".env.local"]
```

Then use profiles:

```bash
s2 exec -p peerdb -- novahub mirror list
```

## Security Model

### How is this different from `source ~/.secrets`?

**With `source ~/.secrets` (current):**
- `env` / `printenv` shows all secrets in cleartext
- `echo $SECRET` prints the value
- `cat ~/.secrets` reads the plaintext file
- Every subprocess inherits all secrets automatically
- AI coding agents see secrets via process environment

**With `s2 exec`:**
- `env` / `printenv` shows nothing (parent shell has no secrets)
- `echo $SECRET` prints empty
- `cat ~/.secrets` shows ciphertext (encrypted at rest)
- `s2 list` shows key names only, never values
- Only the exec'd subprocess receives secrets

### Security layers

| Threat | Mitigation |
|--------|-----------|
| `env`/`printenv` in parent shell | Secrets never loaded into parent — only in exec'd subprocess |
| stdout/stderr | CLI never prints values; `SecretString` redacts Debug/Display |
| Shell history | `set` reads from stdin, not args; `exec` args are the target command |
| Files on disk | Encrypted at rest with keychain-backed passphrase; 0600 enforced |
| `/proc/<pid>/environ` | `execvp` replaces process; `--clean-env` reduces surface |
| Memory after use | `secrecy`/`zeroize` clear memory on drop |
| Process listing (`ps`) | Values never in argv |

### Key design decisions

- **`execve` replaces the process**: After exec, only the child command remains. Secrets never persist in a parent process. Signals forward correctly since the child IS the process.
- **Transparent encryption**: When loading files, s2 auto-detects age-encrypted content and decrypts in-memory using the keychain passphrase. No manual decrypt step needed.
- **0600 enforcement**: s2 refuses to read any file that is group or world readable.
- **stdin-only for values**: `s2 set` reads from stdin, never from CLI arguments, preventing shell history exposure.

## File Format

Supports both formats, auto-detected per line:

```bash
# Shell-sourceable format
export API_KEY=my-key
export DB_PASSWORD="has spaces"

# Dotenv format
API_KEY=my-key
DB_PASSWORD="has spaces"

# Single-quoted (literal, no escapes)
PATTERN='foo$bar'

# Comments and blank lines are skipped
```
