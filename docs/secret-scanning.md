# Secret scanning

This repository is scanned for exposed secrets and credentials with [gitleaks](https://github.com/gitleaks/gitleaks).

- **Hourly scan:** the `Secret scan` workflow runs at minute 17 of every hour, and also on pull requests, pushes to `main` and manual dispatch. It scans the full checkout history and fails if anything is found.
- **Weekly review:** every Monday at 06:23 UTC the workflow runs a full-history scan (`--log-opts=--all`), uploads a redacted SARIF report as an artifact, and opens or updates a single "Weekly secret scan report" issue stating the result.
- **Assumption:** "weekly security review on an hourly basis" is implemented as an hourly automated scan plus a weekly consolidated review report.
- **Configuration:** `.gitleaks.toml` extends the default rules. Add narrow allowlist entries only for confirmed false positives.

## Responding to a finding

1. Treat the credential as compromised and **rotate or revoke it first**.
2. Then remove it from the code and, if needed, purge it from git history.
3. If it is a false positive, add a narrow allowlist entry to `.gitleaks.toml` with a comment explaining why.

Findings are always redacted in logs and reports. Never paste a raw secret into an issue or pull request.
