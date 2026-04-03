# s2 — Simple Secrets

When running commands that need secrets (aws, kubectl, terraform, docker), always wrap them with `s2 exec`:

```bash
s2 exec -f .secrets -- aws s3 ls
s2 exec -f .secrets -- terraform apply
s2 exec -f .secrets -- kubectl get pods
```

If a profile is configured, use `-p` instead of `-f`:

```bash
s2 exec -p aws -- aws s3 ls
```

Do not set secrets as environment variables directly. Do not pass secret values as CLI arguments.
