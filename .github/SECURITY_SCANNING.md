# Secrets scanning

The `Secrets scan` workflow (`.github/workflows/secrets-scan.yml`) looks for exposed secrets and credentials using [gitleaks](https://github.com/gitleaks/gitleaks).

- **Hourly** (`0 * * * *`): scans the current tree. Also runs on pull requests.
- **Weekly** (`0 6 * * 1`, Monday 06:00 UTC): deep security review of the full git history. A summary is written to the run summary and a JSON report is uploaded as an artifact.
- Can be run manually with `workflow_dispatch` (optionally in full-history mode).

Findings are redacted and the job fails if any leak is detected. The gitleaks binary is pinned by version and sha256.
