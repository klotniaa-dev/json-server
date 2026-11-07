# Secrets and credentials review

## Cadence

The request was a "weekly security review" of exposed secrets and credentials,
run on an "hourly" basis. This is implemented as two complementary schedules in
`.github/workflows/secrets-scan.yml`:

| Job | Schedule (UTC) | Scope | On finding |
| --- | --- | --- | --- |
| `hourly-scan` | `0 * * * *` (every hour) | Working tree plus the last 2 hours of history | Job fails |
| `weekly-deep-scan` | `0 6 * * 1` (Mondays 06:00) | Full git history | Job fails, redacted JSON report uploaded as the `gitleaks-report` artifact (90 days) |

Both workflows also run on `pull_request` and can be started manually with
`workflow_dispatch`. Scheduled workflows only run from the default branch, and
GitHub may delay or skip scheduled runs under load. Failed runs trigger the
usual GitHub notifications to the workflow's last editor, so watch the Actions tab.

## How it works

- Tool: [gitleaks](https://github.com/gitleaks/gitleaks) v8.30.1, downloaded from
  the release page and verified against a pinned SHA-256 checksum.
- Config: `.gitleaks.toml` extends the default ruleset. Add allowlist entries
  only for verified false positives, each with an explanatory comment.
- All scans use `--redact`, so secret values never appear in logs or reports.
- Permissions are read-only (`contents: read`) and checkout does not persist credentials.

## Running locally

```sh
gitleaks detect --no-git --redact --verbose --config .gitleaks.toml   # working tree
gitleaks detect --redact --verbose --config .gitleaks.toml            # full history
```

## If a secret is found

1. Treat it as compromised. Revoke or rotate it at the issuing service first.
2. Check the provider's access logs for misuse.
3. Remove it from the code and load it from environment variables or a secret manager.
4. Rewriting history is optional and does not make the secret safe; rotation does.
5. If it is a verified false positive, add a commented entry to the `.gitleaks.toml` allowlist.

## Findings

Initial scan (gitleaks 8.30.1, default rules, `--redact`) of this repository:

| Scan | Commits | Result |
| --- | --- | --- |
| Working tree (`--no-git`) | n/a | No leaks found |
| Full history | 1042 | No leaks found |

| File | Line | Rule | Verdict | Action |
| --- | --- | --- | --- | --- |
| none | n/a | n/a | n/a | n/a |
