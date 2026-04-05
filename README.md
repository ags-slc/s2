```
       .-------.
      /         \
     |           |
  .--+-----------+--.
  |                  |
  |      //S2        |
  |  Simple Secrets  |
  |                  |
  '------------------'
```

Inject secrets into subprocess environments without ambient shell exposure. Secrets never enter your parent shell, never appear in `env`/`printenv`, and are encrypted at rest with keychain-backed passphrases.

## Install

```bash
# All users (/usr/local/bin, may prompt for sudo)
curl -fsSL https://raw.githubusercontent.com/ags-slc/s2/main/install.sh | sh

# Single user (~/.local/bin)
curl -fsSL https://raw.githubusercontent.com/ags-slc/s2/main/install.sh | sh -s -- --user
```

Or with Rust:

```bash
cargo install s2-simple-secrets   # from crates.io
cargo install --path .      # from source
```

**Windows:** use [WSL](https://learn.microsoft.com/en-us/windows/wsl/install) and follow the Linux instructions.

## Quick Start

```bash
# Create a secret file (encrypted by default, passphrase stored in keychain)
s2 init ~/.secrets

# Add secrets (reads values from stdin, never from CLI args)
# set/unset transparently handle encrypted files
echo "AKIA..." | s2 set AWS_SECRET_ACCESS_KEY -f ~/.secrets

# Run any command with secrets injected
s2 exec -f ~/.secrets -- aws s3 ls
s2 exec -f ~/.secrets -- terraform apply
s2 exec -f ~/.secrets -- kubectl get pods

# List available keys (never shows values)
s2 list -f ~/.secrets

# Check if required keys exist
s2 check AWS_SECRET_ACCESS_KEY -f ~/.secrets

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
| `s2 init` | Create a new secret file (encrypted by default, `--no-encrypt` for plaintext) |
| `s2 set` | Set a secret (reads value from stdin, handles encrypted files) |
| `s2 unset` | Remove a secret from a file (handles encrypted files) |
| `s2 encrypt` | Encrypt an existing plaintext file with age |
| `s2 decrypt` | Decrypt an age-encrypted file |
| `s2 edit` | Decrypt → $EDITOR → re-encrypt |
| `s2 redact` | Pipe filter replacing secret values with `[REDACTED]` |
| `s2 scan` | Scan files for secrets (regex patterns + entropy analysis) |

## Secret Scanning

Detect secrets in files before they're committed.

```bash
# Scan current directory
s2 scan .

# Scan specific files
s2 scan src/config.rs .env

# Pre-commit hook mode (only git staged files)
s2 scan --staged

# JSON output for CI
s2 scan . --json
```

Exit code 1 if secrets are found (blocks commits when used as a hook).

### Custom Rules

Add company-specific patterns to `~/.config/s2/config.toml`:

```toml
[[scan.rules]]
id = "quickbooks-token"
description = "QuickBooks Online API Token"
pattern = 'qbo_[a-zA-Z0-9]{32}'

[[scan.rules]]
id = "vercel-token"
description = "Vercel API Token"
pattern = '[a-zA-Z0-9]{24}'
keyword = "VERCEL"    # only flag if "VERCEL" appears on the same line
```

### Pattern Learning

Test scan coverage against a file of known secrets and auto-generate rules for anything missed:

```bash
s2 scan --learn known-secrets.txt
```

Output shows which secrets are covered, suggests regex rules for gaps, and optionally appends them to your config.

### Allowlist

When a finding is a false positive, allow it by hash so it doesn't block future scans:

```bash
# Scan shows a hash for each finding
s2 scan --staged
#   .env:5  DB_PASSWORD  high-entropy  xK9m████████  97eb0519eeb61ed6

# Allow a specific finding
s2 scan --allow 97eb0519eeb61ed6

# Future scans skip that finding
s2 scan --staged
#   No secrets found (1 files scanned, 1 allowed)
```

Hashes are stored in `.s2allowlist` in the current directory. Commit it to share with your team, or gitignore it for personal use. Prefix matching is supported (minimum 8 characters).

### Pre-commit Hook

**Global (all repos):**

```bash
# Create global hooks directory
mkdir -p ~/.config/git/hooks

# Create the hook (chains to repo-local hooks if they exist)
cat > ~/.config/git/hooks/pre-commit << 'EOF'
#!/bin/sh
s2 scan --staged || exit 1

# Chain to repo-local hook if it exists
if [ -x .git/hooks/pre-commit ]; then
    exec .git/hooks/pre-commit
fi
EOF
chmod +x ~/.config/git/hooks/pre-commit

# Tell git to use it
git config --global core.hooksPath ~/.config/git/hooks
```

**Per-repo:**

```bash
echo '#!/bin/sh
exec s2 scan --staged' > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

### What it Detects

**High confidence** (pattern matching): AWS access keys, GitHub tokens, Stripe keys, Slack tokens/webhooks, PEM private keys, JWTs, Google API keys, Twilio/SendGrid keys, Shopify tokens, GitLab PATs, DigitalOcean tokens, Anthropic/OpenAI API keys, npm/PyPI tokens.

**Medium confidence** (entropy analysis): Strings with high Shannon entropy (>4.5) and length >20 characters. Catches secrets without a known pattern format. Placeholder values (`changeme`, `REPLACE_ME`, `your-*-here`, etc.) are automatically excluded to reduce false positives.

## Configuration

Create `~/.config/s2/config.toml`:

```toml
default_files = ["~/.secrets"]
audit_log = "~/.config/s2/audit.log"

[profiles.aws]
files = ["~/.secrets"]
keys = ["AWS_SECRET_ACCESS_KEY"]

[profiles.deploy]
files = ["~/.secrets", ".env.local"]
```

Then use profiles:

```bash
s2 exec -p aws -- terraform apply
```

## CI/CD

s2 works in CI pipelines — secrets are scoped to individual steps, never leaked to the runner environment.

### GitHub Actions

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install s2
        run: curl -fsSL https://raw.githubusercontent.com/ags-slc/s2/main/install.sh | sh

      - name: Deploy
        run: |
          # Bridge CI secrets into s2, then inject into deploy script
          echo "${{ secrets.AWS_SECRET_ACCESS_KEY }}" | s2 set AWS_SECRET_ACCESS_KEY -f .secrets --no-encrypt
          s2 exec -f .secrets --clean-env -- ./deploy.sh
        # --clean-env ensures only secrets + minimal vars reach the subprocess

      - name: Scrub logs
        run: kubectl logs deploy/app | s2 redact -f .secrets
```

### SSM in CI

If your CI runner has AWS access, s2 can pull secrets directly from SSM — no pipeline variables needed:

```bash
# .secrets
DB_PASSWORD=ssm:///prod/apps/myapp/secrets/DB_PASSWORD
API_KEY=ssm:///prod/apps/myapp/secrets/API_KEY
```

```yaml
- name: Run migrations
  run: s2 exec -f .secrets --clean-env -- ./run-migrations.sh
```

### Why s2 in CI?

- **Scoped injection** — secrets only reach the subprocess, not the entire runner environment
- **`--clean-env`** — strips runner env pollution, subprocess gets only what it needs
- **`s2 redact`** — pipe build or deploy logs through s2 to scrub any leaked values
- **`execve` replacement** — secrets don't persist in `/proc/pid/environ` after the step

## AI Agent Integration

s2 includes hooks that automatically inject secrets when AI agents run commands. The agent runs `aws s3 ls` and s2 transparently wraps it with `s2 exec`. Supports Claude Code, GitHub Copilot, Cursor, Codex, and OpenCode.

### Shared Config

Add a `[hook]` section to `~/.config/s2/config.toml` (used by all agents):

```toml
[hook]
commands = ["aws", "terraform", "kubectl", "docker"]
profile = "aws"       # or use: files = ["~/.secrets"]
```

### Claude Code / GitHub Copilot

Add to `~/.claude/settings.json` (or `.github/copilot-instructions.md` hook config):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "s2 hook"
          }
        ]
      }
    ]
  }
}
```

For Copilot, use `s2 hook --format copilot` (same behavior, explicit format).

### Cursor

Add to `~/.cursor/hooks.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "s2 hook --format cursor"
          }
        ]
      }
    ]
  }
}
```

Or use the provided shell wrapper: `hooks/cursor/s2-rewrite.sh`.

### Codex

Copy `hooks/codex/s2-awareness.md` into your project's `AGENTS.md` or Codex instructions. Codex doesn't support programmatic hooks — the awareness file instructs the agent to use `s2 exec` directly.

### OpenCode

Copy `hooks/opencode/s2.ts` to `~/.config/opencode/plugins/s2.ts`. The plugin intercepts shell commands and pipes them through `s2 hook --format cursor`.

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
| Files on disk | Encrypted at rest with keychain-backed passphrase (file-based fallback on headless Linux); 0600 enforced |
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

## Similar Tools

| Tool | Description | Differentiator |
|------|-------------|----------------|
| [Teller](https://github.com/tellerops/teller) | Multi-provider secret injection via `teller run`. CNCF project, now archived. | Aggregates external backends; no local encrypted store. |
| [SOPS](https://github.com/getsops/sops) | Encrypts structured files at rest (age/PGP/KMS). Has `sops exec-env`. | File-format-centric (YAML/JSON field-level encryption), not a dedicated exec wrapper. |
| [Chamber](https://github.com/segmentio/chamber) | `chamber exec svc -- cmd` injects secrets from AWS SSM Parameter Store. | AWS-only backend. |
| [envconsul](https://github.com/hashicorp/envconsul) | Subprocess injection from Consul KV and Vault. | Locked to HashiCorp ecosystem. |
| [envchain](https://github.com/sorah/envchain) | Stores secrets in system keychain, injects via `envchain ns cmd`. | No encrypted files, no config profiles, no redact. |
| [Infisical](https://github.com/Infisical/infisical) | Full platform (server + dashboard + CLI) with `infisical run`. | Heavy; requires running a server. |
| [dotenvx](https://github.com/dotenvx/dotenvx) | Encrypts `.env` files with ECIES. `dotenvx run -- cmd`. | Focused on `.env` format, not subprocess security model. |
| [1Password CLI `op run`](https://developer.1password.com/docs/cli/reference/commands/run/) | Resolves `op://` references, injects into subprocess. | Proprietary, single-backend (1Password). |
| [Doppler CLI](https://github.com/DopplerHQ/cli) | `doppler run -- cmd` injects from Doppler cloud. | SaaS-only, not local-first. |

**Where s2 differs**: local-first encrypted store + `execve` process replacement (not child spawn) + `secrecy`/`zeroize` memory safety + 0600 enforcement + stream redaction. Most alternatives are either locked to a single backend, require a running server, or don't address the full threat surface (memory, process listing, parent shell leakage).
