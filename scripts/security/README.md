# Secrets & Credentials Security Review

This directory contains a recurring security-review automation that scans the
workspace repositories for **exposed secrets and credentials**.

## What it does

`secret-scan.sh` scans all three repositories that live side by side in the
workspace:

- `json-server` (the host repo, where this tooling lives)
- `gson`
- `click`

It resolves the **workspace root** as the parent directory of the `json-server`
repo so it can reach the sibling repos (`../gson`, `../click`). You can override
the root with the `SCAN_ROOT` environment variable:

```bash
SCAN_ROOT=/path/to/workspace bash scripts/security/secret-scan.sh
```

The scanner **prefers [gitleaks](https://github.com/gitleaks/gitleaks)** when it
is on `PATH`, and otherwise **falls back to a built-in regex scan** so it still
works on machines without gitleaks installed. The fallback covers common
patterns: AWS access key IDs (`AKIA...`), AWS secret-key-shaped 40-char values,
generic `api_key` / `secret` / `password` / `token` assignments, private key
headers (`-----BEGIN ... PRIVATE KEY-----`), GitHub tokens
(`ghp_` / `gho_` / `github_pat_` ...), Slack tokens (`xox[baprs]-`), and
high-entropy-looking assignments.

### Coverage: working tree **and** git history

When gitleaks is used and a repo has a `.git` directory, the scanner runs two
passes and **merges both** into the findings, counts, report, and exit code:

1. a `--no-git` filesystem scan of the current **working tree**, and
2. a full **git-history** scan.

History is a primary exposure vector (a credential committed and later deleted
still lives in history), so history findings are surfaced with the short commit
hash, e.g. `rule=github-pat (git history commit 3cd491eb)`. A secret present in
both the working tree and the latest commit may be reported twice; this is
intentional over-reporting so nothing is silently dropped.

The built-in regex fallback scans only the **working tree** (it does not read
git history). Install gitleaks for history coverage.

### Severity

Each finding is bucketed as `CRITICAL` / `HIGH` / `MEDIUM` / `LOW`. The fallback
assigns severity per rule. gitleaks' default JSON output has no per-finding
severity field, so the scanner maps each gitleaks `RuleID` to a bucket
(e.g. `aws-access-token`, `github-pat`, and private-key rules -> `CRITICAL`;
other `*-token` / `*secret*` / `*password*` rules -> `HIGH`; anything else ->
`MEDIUM`). This keeps the severity grouping meaningful regardless of which
scanner ran.

### Report path shape

In the JSON report the `file` field is always **workspace-relative** (e.g.
`gson/src/.../Foo.java`) on both the gitleaks and the fallback path, so a
consumer sees one consistent path shape.

## Reports

Each run writes a timestamped pair of reports under:

```
json-server/.security/reports/secret-scan-<UTC-timestamp>.md    # human-readable
json-server/.security/reports/secret-scan-<UTC-timestamp>.json  # machine-readable
```

These reports are runtime output and are **git-ignored** (see the
`.security/reports/` entry in `json-server/.gitignore`). The directory itself is
kept via a `.gitkeep` so a fresh clone has somewhere to write; the script also
`mkdir -p`'s the directory at runtime.

## Exit-code contract

| Exit code | Meaning                              |
|-----------|--------------------------------------|
| `0`       | Clean — no secrets found             |
| `2`       | One or more potential secrets found  |

This lets cron and CI detect failures. A non-zero (2) exit means a report with
details (repo, file path, line, severity, rule) was produced.

## Kiro hook

`json-server/.kiro/hooks/secrets-security-review.kiro.hook` is the in-Kiro entry
point to this same review. When triggered it asks the agent to run
`secret-scan.sh`, read the newest report, summarize findings grouped by severity
(CRITICAL / HIGH / MEDIUM / LOW), and flag any exposed secret with its repo, file
path, and line.

Kiro hooks do **not** have a native cron/time/schedule trigger type (the
supported `when.type` values are `fileEdited`, `fileCreated`, `fileDeleted`,
`fileSaved`, and `userTriggered`). The hook therefore uses `userTriggered`, and
the true recurring cadence is driven by the cron entry below. The hook and the
cron job invoke the exact same review.

## Scheduling (hourly cron)

There is no cron daemon in the Kiro sandbox, so install the schedule on **your
own machine**. To run the review **every hour**, add this crontab line
(`crontab -e`):

```cron
0 * * * * cd /path/to/workspace/json-server && bash scripts/security/secret-scan.sh >> .security/cron.log 2>&1
```

Replace `/path/to/workspace/json-server` with the absolute path to your
`json-server` checkout. The `.security/cron.log` file is git-ignored.

## Installing gitleaks (recommended)

The scanner works without gitleaks, but gitleaks gives much higher-quality
results (and scans git history). Install it with Go:

```bash
go install github.com/zricethezav/gitleaks/v8@latest
```

Or download a release binary from
<https://github.com/gitleaks/gitleaks/releases> and place it on your `PATH`.

## Scheduling ambiguity: weekly vs. hourly

The original request mixed two cadences: a *"weekly security review"* that
should happen *"on an hourly basis."* These conflict. **This implementation uses
HOURLY**, because the hourly instruction was the explicit cadence.

If a **weekly** review was actually intended, change only the cron schedule
field — the script and hook stay the same. For example, to run every **Monday at
09:00**:

```cron
# Hourly (this implementation's default):
0 * * * * cd /path/to/workspace/json-server && bash scripts/security/secret-scan.sh >> .security/cron.log 2>&1

# Weekly (Monday 09:00) — swap the schedule if weekly was intended:
0 9 * * 1 cd /path/to/workspace/json-server && bash scripts/security/secret-scan.sh >> .security/cron.log 2>&1
```
