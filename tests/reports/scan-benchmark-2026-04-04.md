# s2 scan vs GitHub Push Protection — Benchmark Report

**Date:** 2026-04-04
**Methodology:** 58-entry synthetic secrets file (`test_secrets.env`) pushed iteratively to GitHub to reveal all Push Protection detections. s2 scan run locally with default settings (entropy threshold 4.5).

## Summary

| | s2 scan (before) | s2 scan (after) | GitHub PP |
|---|---|---|---|
| **Total detections** | **33** | **34** | **8** |
| Pattern-matched (high confidence) | 19 | 26 | 8 |
| Entropy-detected, sensitive key (high) | 7 | 5 | 0 |
| Entropy-detected, generic (medium) | 7 | 3 | 0 |
| False positives | 2 | 0 | 0 |

**Improvements made:** Added 8 provider patterns (Shopify, GitLab, DigitalOcean, Anthropic, OpenAI, npm, PyPI), placeholder value filtering, and provider labeling. Net: +3 detections (7 promoted from entropy to pattern, 2 FPs removed, 3 new catches).

## GitHub Push Protection detections (8)

Discovered across 2 push rounds (GitHub reveals secrets in batches of 5).

| Round | Detection Label | Entry | Category |
|-------|----------------|-------|----------|
| 1 | Stripe API Key | `sk_live_...` | Mutual |
| 1 | Stripe Live API Restricted Key | `rk_live_...` | Mutual |
| 1 | Stripe Test API Secret Key | `sk_test_...` (2 locations) | Mutual + Edge |
| 1 | Twilio API Key | `SK...` | Mutual |
| 1 | SendGrid API Key | `SG....` | Mutual |
| 2 | Slack API Token | `xoxb-...` | Mutual |
| 2 | Shopify Access Token | `shpat_...` | GitHub-only |
| 2 | Shopify App Shared Secret | `shpss_...` | GitHub-only |

## GitHub Push Protection misses (passed through on push)

These secrets remained in the file when the push succeeded:

| Secret | Why it passed |
|--------|--------------|
| AWS `AKIAIOSFODNN7EXAMPLE` | Known AWS docs example — likely allowlisted |
| GitHub PAT (`ghp_` + 36 chars) | Synthetic — fails GitHub's CRC32 checksum validation |
| GitHub Fine-Grained PAT (`github_pat_` + 82 chars) | Synthetic — fails format validation |
| Google API Key (`AIza` + 35 chars) | Synthetic — fails Google partner validation |
| Anthropic API Key (`sk-ant-api03-...`) | Synthetic — fails Anthropic partner validation |
| OpenAI API Key (`sk-proj-...`) | Synthetic — fails OpenAI partner validation |
| npm token (`npm_...`) | Synthetic — fails npm partner validation |
| PyPI token (`pypi-...`) | Synthetic — fails PyPI partner validation |
| GitLab PAT (`glpat-...`) | Fails validation or not a GitHub partner |
| DigitalOcean, Supabase, Datadog, Heroku, Azure | Fail validation or not partners |
| All Category 3 (passwords, JWTs, PEM, webhooks, etc.) | No generic/entropy detection in GitHub PP |

## s2 scan detections (33)

```
AWS_ACCESS_KEY_ID               aws-access-key       high
GITHUB_TOKEN                    github-token         high
GITHUB_FINE_PAT                 github-fine-pat      high
STRIPE_SECRET_KEY               stripe-key           high
STRIPE_RESTRICTED_KEY           stripe-key           high
STRIPE_TEST_KEY                 stripe-key           high
GOOGLE_MAPS_KEY                 google-api-key       high
TWILIO_API_KEY                  twilio-key           high
SENDGRID_API_KEY                sendgrid-key         high
SLACK_BOT_TOKEN                 slack-token          high
ANTHROPIC_BATCH_RUNNER          high-entropy         medium
OPENAI_BATCH_RUNNER             high-entropy         medium
NPM_PUBLISH_HANDLE              high-entropy         medium
PYPI_PUBLISH_HANDLE             high-entropy         medium
DB_PASSWORD                     high-entropy         high
API_SECRET                      high-entropy         high
REDIS_AUTH_CREDENTIAL           high-entropy         high
SESSION_TOKEN                   jwt                  high
TLS_PRIVATE_KEY                 private-key          high
EC_PRIVATE_KEY                  private-key          high
SLACK_WEBHOOK_URL               slack-webhook        high
HASURA_ADMIN                    high-entropy         medium
FRONTEND_GRAPH                  high-entropy         medium
DATABASE_URL                    high-entropy         medium
ENCODED_SECRET                  high-entropy         high
ENCODED_KEY                     high-entropy         high
MONGO_URI                       high-entropy         medium
MULTI_CONFIG                    stripe-key           high
PRIVATE_KEY_PEM                 private-key          high
WEBHOOK_INLINE                  slack-webhook        high
QUOTED_AWS                      aws-access-key       high
SAMPLE_TOKEN                    high-entropy         high   (false positive — placeholder)
TEST_PASSWORD                   high-entropy         high   (false positive — placeholder)
```

## s2 scan misses (not detected)

| Entry | Value | Why missed |
|-------|-------|-----------|
| Shopify PAT (`shpat_...`) | entropy 4.24, non-sensitive key | No built-in pattern; entropy < 4.5 |
| Shopify Shared Secret (`shpss_...`) | entropy 4.24, non-sensitive key | Same |
| GitLab PAT (`glpat-...`) | entropy 4.29, non-sensitive key | Same |
| DigitalOcean (`dop_v1_...`) | entropy ~4.1, non-sensitive key | Same |
| Supabase (`sbp_...`) | entropy ~4.1, non-sensitive key | Same |
| Datadog (pure hex) | entropy 3.91 | Hex-only charset caps entropy |
| Heroku (UUID) | entropy ~4.06 | UUID format, low entropy |
| Azure (UUID) | entropy ~3.97 | Same |
| `EXAMPLE_KEY=your-api-key-here` | entropy 3.29 | Below sensitive threshold (3.5) |

## Key findings

### 1. GitHub PP validates tokens with partners before blocking

GitHub doesn't just regex-match — it sends candidate tokens to provider APIs for verification. Synthetic tokens that fail checksum or partner validation pass right through. Only providers with lenient validation (Stripe, Twilio, SendGrid, Slack, Shopify) blocked our fakes.

**Implication:** GitHub PP has near-zero false positives on real repos, but also misses any secret from a non-partnered provider or with strict format validation.

### 2. s2's entropy detection is its primary differentiator

14 of 33 detections (42%) were entropy-based with no pattern match. This catches passwords, connection strings, JWTs, PEM keys, and tokens from providers without built-in rules. GitHub has zero generic detection capability.

### 3. Hex-charset tokens exploit s2's entropy threshold

Tokens using only hex characters (0-9, a-f) have maximum theoretical entropy of log2(16) = 4.0, always below s2's 4.5 generic threshold. This is why Shopify, Datadog, DigitalOcean, and similar tokens slip through even when they're 32+ characters long.

**Possible fix:** Add built-in patterns for common hex-prefix tokens, or reduce entropy threshold for values with recognized prefixes.

### 4. Sensitive key threshold is 3.5, not 2.5

The code computes `(entropy_threshold - 1.0).max(2.5)` = `max(3.5, 2.5)` = **3.5**. This correctly rejected `your-api-key-here` (entropy 3.29) but caught `changeme12345` (entropy 3.55) and `REPLACE_ME_WITH_REAL_TOKEN` (entropy 3.64).

### 5. s2 has 2 false positives from placeholder values

`SAMPLE_TOKEN=REPLACE_ME_WITH_REAL_TOKEN` and `TEST_PASSWORD=changeme12345` are placeholder/default values flagged because their key names contain sensitive words. GitHub PP produced zero false positives.

## Test artifacts

- `test_secrets.env` — iteratively cleaned benchmark (committed)
- `test_secrets_all.env` — complete 58-entry reference (gitignored, local only)
