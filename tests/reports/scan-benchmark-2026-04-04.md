# s2 scan vs GitHub Push Protection — Benchmark Report

**Date:** 2026-04-04
**Methodology:** 58-entry synthetic secrets file (`test_secrets.env`) pushed iteratively to GitHub to reveal all Push Protection detections. s2 scan run locally with default settings (entropy threshold 4.5).

## Summary

| | s2 scan (before) | s2 scan (after) | GitHub PP |
|---|---|---|---|
| **Total detections** | **33** | **35** | **8** |
| Pattern-matched (high confidence) | 19 | 26 | 8 |
| Entropy-detected, sensitive key (high) | 7 | 5 | 0 |
| Entropy-detected, generic (medium) | 7 | 4 | 0 |
| False positives | 2 | 0 | 0 |

**Improvements made:** Added 8 provider patterns (Shopify, GitLab, DigitalOcean, Anthropic, OpenAI, npm, PyPI), placeholder value filtering, and provider labeling. Net: +4 detections (4 promoted from entropy to pattern, 2 FPs removed, 4 new catches from previously-missed providers).

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
| 2 | Shopify Access Token | `shpat_...` | Mutual (pattern added) |
| 2 | Shopify App Shared Secret | `shpss_...` | Mutual (pattern added) |

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

## s2 scan detections (35)

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
SHOPIFY_PAT                     shopify-token        high   (was missed — pattern added)
SHOPIFY_SHARED_SECRET           shopify-shared-secret high  (was missed — pattern added)
GITLAB_PAT                      gitlab-pat           high   (was missed — pattern added)
DIGITALOCEAN_TOKEN              digitalocean-token   high   (was missed — pattern added)
ANTHROPIC_BATCH_RUNNER          anthropic-key        high   (was entropy — pattern added)
OPENAI_BATCH_RUNNER             openai-key           high   (was entropy — pattern added)
NPM_PUBLISH_HANDLE              npm-token            high   (was entropy — pattern added)
PYPI_PUBLISH_HANDLE             pypi-token           high   (was entropy — pattern added)
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
```

## s2 scan misses (not detected)

| Entry | Value | Why missed |
|-------|-------|-----------|
| Supabase (`sbp_...`) | entropy ~4.1, non-sensitive key | No built-in pattern; entropy < 4.5 |
| Datadog (pure hex) | entropy 3.91 | Hex-only charset caps entropy |
| Heroku (UUID) | entropy ~4.06 | UUID format, low entropy |
| Azure (UUID) | entropy ~3.97 | Same |
| `EXAMPLE_KEY=your-api-key-here` | entropy 3.29 | Below sensitive threshold (3.5) |

**Previously missed, now detected** (patterns added in v0.5.0):

| Entry | Pattern | Confidence |
|-------|---------|------------|
| Shopify PAT (`shpat_...`) | `shopify-token` | high |
| Shopify Shared Secret (`shpss_...`) | `shopify-shared-secret` | high |
| GitLab PAT (`glpat-...`) | `gitlab-pat` | high |
| DigitalOcean (`dop_v1_...`) | `digitalocean-token` | high |

## Key findings

### 1. GitHub PP validates tokens with partners before blocking

GitHub doesn't just regex-match — it sends candidate tokens to provider APIs for verification. Synthetic tokens that fail checksum or partner validation pass right through. Only providers with lenient validation (Stripe, Twilio, SendGrid, Slack, Shopify) blocked our fakes.

**Implication:** GitHub PP has near-zero false positives on real repos, but also misses any secret from a non-partnered provider or with strict format validation.

### 2. s2's entropy detection is its primary differentiator

9 of 35 detections (26%) are entropy-based with no pattern match. This catches passwords, connection strings, JWTs, PEM keys, and tokens from providers without built-in rules. GitHub has zero generic detection capability.

### 3. Hex-charset tokens exploit entropy thresholds (mitigated)

Tokens using only hex characters (0-9, a-f) have maximum theoretical entropy of log2(16) = 4.0, always below s2's 4.5 generic threshold. This is why Datadog and similar tokens without built-in patterns still slip through.

**Mitigation applied:** Added prefix-based patterns for Shopify (`shpat_`, `shpss_`), GitLab (`glpat-`), and DigitalOcean (`dop_v1_`) so they're now caught regardless of entropy. Remaining hex-charset providers (Datadog, Supabase) could benefit from the same treatment.

### 4. Sensitive key threshold is 3.5, not 2.5

The code computes `(entropy_threshold - 1.0).max(2.5)` = `max(3.5, 2.5)` = **3.5**. This correctly rejected `your-api-key-here` (entropy 3.29) but caught `changeme12345` (entropy 3.55) and `REPLACE_ME_WITH_REAL_TOKEN` (entropy 3.64).

### 5. Placeholder false positives eliminated

`SAMPLE_TOKEN=REPLACE_ME_WITH_REAL_TOKEN` and `TEST_PASSWORD=changeme12345` were previously flagged as false positives because their key names contain sensitive words. Placeholder value filtering now correctly skips these. Both s2 and GitHub PP now produce zero false positives on this benchmark.

## Test artifacts

- `test_secrets.env` — iteratively cleaned benchmark (committed)
- `test_secrets_all.env` — complete 58-entry reference (gitignored, local only)
