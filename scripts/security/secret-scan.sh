#!/usr/bin/env bash
#
# secret-scan.sh - Recurring multi-repo secrets/credentials exposure scan.
#
# Scans the workspace repos (json-server, gson, click) for exposed secrets and
# credentials. Prefers gitleaks when it is on PATH; otherwise falls back to a
# self-contained grep/regex scan covering common secret patterns.
#
# Reports are written to json-server/.security/reports/secret-scan-<UTC>.{md,json}.
# A summary is printed to stdout.
#
# Exit codes:
#   0 - no findings (clean)
#   2 - one or more findings present
#
# See scripts/security/README.md for scheduling (hourly cron) and details.

set -euo pipefail

# ---------------------------------------------------------------------------
# Resolve paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Host repo root = two levels up from scripts/security/
HOST_REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Workspace root is the parent of the host repo so we can reach sibling repos.
# Overridable via SCAN_ROOT.
SCAN_ROOT="${SCAN_ROOT:-$(cd "${HOST_REPO_ROOT}/.." && pwd)}"

# Target repos to scan (relative to SCAN_ROOT).
TARGET_REPOS=("json-server" "gson" "click")

# Report output lives inside the host repo (gitignored).
REPORT_DIR="${HOST_REPO_ROOT}/.security/reports"
mkdir -p "${REPORT_DIR}"

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT_MD="${REPORT_DIR}/secret-scan-${TIMESTAMP}.md"
REPORT_JSON="${REPORT_DIR}/secret-scan-${TIMESTAMP}.json"

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
TOTAL_FINDINGS=0
# Accumulate JSON finding objects here.
JSON_FINDINGS=""

add_json_finding() {
  # args: repo file line severity rule
  local repo="$1" file="$2" line="$3" severity="$4" rule="$5"
  # Escape backslashes and double quotes for JSON safety.
  file="${file//\\/\\\\}"
  file="${file//\"/\\\"}"
  rule="${rule//\\/\\\\}"
  rule="${rule//\"/\\\"}"
  local obj
  obj="    {\"repo\": \"${repo}\", \"file\": \"${file}\", \"line\": ${line}, \"severity\": \"${severity}\", \"rule\": \"${rule}\"}"
  if [ -z "${JSON_FINDINGS}" ]; then
    JSON_FINDINGS="${obj}"
  else
    JSON_FINDINGS="${JSON_FINDINGS},
${obj}"
  fi
}

# ---------------------------------------------------------------------------
# Report header
# ---------------------------------------------------------------------------
{
  echo "# Secret Scan Report"
  echo ""
  echo "- Generated (UTC): ${TIMESTAMP}"
  echo "- Workspace root: ${SCAN_ROOT}"
  echo "- Target repos: ${TARGET_REPOS[*]}"
  echo ""
} > "${REPORT_MD}"

# ---------------------------------------------------------------------------
# gitleaks severity mapping
# ---------------------------------------------------------------------------
# gitleaks' default JSON output does not carry a per-finding severity field
# (and Tags is usually empty), so we map the RuleID to a severity bucket that
# matches the CRITICAL/HIGH/MEDIUM/LOW scheme the fallback and the hook use.
# Unknown rules default to MEDIUM so nothing is silently downgraded to LOW.
gitleaks_severity_for_rule() {
  case "$1" in
    # Direct, high-impact credentials -> CRITICAL.
    *private-key*|*private_key*|\
    aws-access-token|aws-secret-key|\
    github-pat|github-fine-grained-pat|github-oauth|github-app-token|github-refresh-token|\
    gcp-*|azure-*|\
    stripe-access-token|\
    slack-*|\
    rsa-private-key|ssh-*|pgp-private-key)
      echo "CRITICAL" ;;
    # Service API keys / tokens -> HIGH.
    *api-key*|*api_key*|*-token|*_token|*secret*|*password*|*credential*)
      echo "HIGH" ;;
    # Everything else gitleaks flags is still a real finding; default MEDIUM.
    *)
      echo "MEDIUM" ;;
  esac
}

# ---------------------------------------------------------------------------
# gitleaks path
# ---------------------------------------------------------------------------
# Parse a gitleaks JSON report and emit each finding as tab-separated
# "file<TAB>line<TAB>ruleid<TAB>commit". File paths are relative to the scan
# source, so the caller prefixes the repo name to make them workspace-relative.
emit_gitleaks_findings() {
  local report="$1" repo_path="$2"
  [ -f "${report}" ] || return 0
  # gitleaks' File is absolute for a --no-git filesystem scan but repo-relative
  # for a history scan. Normalize it to repo-relative here (strip the repo_path
  # prefix) so the caller can build a stable workspace-relative path.
  REPO_PATH="${repo_path}" python3 -c "import json,os,sys
root=os.environ.get('REPO_PATH','').rstrip('/')
try:
    data=json.load(open('${report}'))
except Exception:
    sys.exit(0)
if not isinstance(data,list):
    sys.exit(0)
for x in data:
    f=x.get('File','')
    if root and os.path.isabs(f):
        try:
            f=os.path.relpath(f, root)
        except Exception:
            pass
    print('%s\t%s\t%s\t%s' % (f, x.get('StartLine',0), x.get('RuleID',''), x.get('Commit','')))" 2>/dev/null || true
}

run_gitleaks_for_repo() {
  local repo_name="$1" repo_path="$2"
  local gl_report="${REPORT_DIR}/gitleaks-${repo_name}-${TIMESTAMP}.json"

  echo "## ${repo_name} (gitleaks)" >> "${REPORT_MD}"
  echo "" >> "${REPORT_MD}"

  # Filesystem scan (working tree, no git history).
  gitleaks detect --source "${repo_path}" --no-git --redact \
    --report-format json --report-path "${gl_report}" >/dev/null 2>&1 || true

  # If the repo has git history, also scan it. History is a primary exposure
  # vector (secrets committed then deleted), so its findings are parsed and
  # merged into the counts/report below, not just written to disk.
  local gl_hist=""
  if [ -d "${repo_path}/.git" ]; then
    gl_hist="${REPORT_DIR}/gitleaks-${repo_name}-history-${TIMESTAMP}.json"
    gitleaks detect --source "${repo_path}" --redact \
      --report-format json --report-path "${gl_hist}" >/dev/null 2>&1 || true
  fi

  local repo_findings=0
  local f ln rule commit rel severity scope

  # Working-tree findings.
  while IFS=$'\t' read -r f ln rule commit; do
    [ -z "${f}" ] && continue
    rel="${repo_name}/${f}"
    severity="$(gitleaks_severity_for_rule "${rule}")"
    add_json_finding "${repo_name}" "${rel}" "${ln:-0}" "${severity}" "${rule}"
    echo "- ${severity} \`${rel}:${ln}\` rule=${rule}" >> "${REPORT_MD}"
    repo_findings=$((repo_findings + 1))
  done < <(emit_gitleaks_findings "${gl_report}" "${repo_path}")

  # Git-history findings (commit-scoped). These are reported with the short
  # commit so a secret that only exists in history is still surfaced.
  if [ -n "${gl_hist}" ]; then
    while IFS=$'\t' read -r f ln rule commit; do
      [ -z "${f}" ] && continue
      rel="${repo_name}/${f}"
      severity="$(gitleaks_severity_for_rule "${rule}")"
      scope="${commit:0:8}"
      add_json_finding "${repo_name}" "${rel}" "${ln:-0}" "${severity}" "${rule} (history ${scope})"
      echo "- ${severity} \`${rel}:${ln}\` rule=${rule} (git history commit ${scope})" >> "${REPORT_MD}"
      repo_findings=$((repo_findings + 1))
    done < <(emit_gitleaks_findings "${gl_hist}" "${repo_path}")
  fi

  if [ "${repo_findings}" -eq 0 ]; then
    echo "No findings." >> "${REPORT_MD}"
  else
    echo "" >> "${REPORT_MD}"
    echo "Found ${repo_findings} potential secret(s) (working tree + git history)." >> "${REPORT_MD}"
  fi
  echo "" >> "${REPORT_MD}"
  TOTAL_FINDINGS=$((TOTAL_FINDINGS + repo_findings))
}

# ---------------------------------------------------------------------------
# Built-in regex fallback
# ---------------------------------------------------------------------------
# Each entry is TAB-separated: "SEVERITY<TAB>RULE<TAB>REGEX".
# A tab delimiter is used (not '|') because '|' is a regex metacharacter: the
# regexes below use '|' for alternation, so splitting on '|' would truncate
# them mid-expression. The fields are read with `IFS=$'\t'`, and tab cannot
# appear inside any of these regexes, so each regex survives intact.
declare -a PATTERNS=(
  "CRITICAL"$'\t'"AWS Access Key ID"$'\t'"AKIA[0-9A-Z]{16}"
  "CRITICAL"$'\t'"Private Key Header"$'\t'"-----BEGIN ([A-Z ]+ )?PRIVATE KEY-----"
  "CRITICAL"$'\t'"GitHub Token"$'\t'"(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[0-9A-Za-z_]{20,}"
  "HIGH"$'\t'"Slack Token"$'\t'"xox[baprs]-[0-9A-Za-z-]{10,}"
  "HIGH"$'\t'"AWS Secret Access Key"$'\t'"(aws_secret_access_key|aws_secret)[[:space:]]*[:=][[:space:]]*[\"']?[A-Za-z0-9/+=]{40}[\"']?"
  "MEDIUM"$'\t'"Generic Secret Assignment"$'\t'"(api[_-]?key|secret|password|passwd|token|access[_-]?key)[\"']?[[:space:]]*[:=][[:space:]]*[\"'][^\"']{8,}[\"']"
  "LOW"$'\t'"High-Entropy Assignment"$'\t'"[\"']?[A-Za-z0-9_]+[\"']?[[:space:]]*[:=][[:space:]]*[\"'][A-Za-z0-9+/]{32,}={0,2}[\"']"
)

# Directories/files to skip during the fallback scan.
should_skip_path() {
  case "$1" in
    */.git/*|*/node_modules/*|*/.security/*|*/dist/*|*/build/*|*/target/*|\
    */lib/*|*/__pycache__/*|*/.venv/*|*/vendor/*|*.min.js|*.lock|*.map) return 0 ;;
    *) return 1 ;;
  esac
}

run_fallback_for_repo() {
  local repo_name="$1" repo_path="$2"

  echo "## ${repo_name} (built-in regex scan)" >> "${REPORT_MD}"
  echo "" >> "${REPORT_MD}"

  local repo_findings=0
  local file
  # Find text files; skip binary via grep -I later.
  while IFS= read -r file; do
    should_skip_path "${file}" && continue
    local entry severity rule regex
    for entry in "${PATTERNS[@]}"; do
      # Split the three fields on the tab delimiter. Tab cannot appear inside
      # any regex, so alternation ('|') in the regex is preserved intact.
      IFS=$'\t' read -r severity rule regex <<< "${entry}"
      # grep -I skips binary files; -n gives line numbers; -E extended regex.
      local match
      while IFS= read -r match; do
        [ -z "${match}" ] && continue
        local ln="${match%%:*}"
        local rel="${file#${SCAN_ROOT}/}"
        add_json_finding "${repo_name}" "${rel}" "${ln}" "${severity}" "${rule}"
        echo "- ${severity} \`${rel}:${ln}\` rule=${rule}" >> "${REPORT_MD}"
        repo_findings=$((repo_findings + 1))
      done < <(grep -InE -e "${regex}" -- "${file}" 2>/dev/null | cut -d: -f1 | sed 's/$/:/' || true)
    done
  done < <(find "${repo_path}" -type f 2>/dev/null)

  if [ "${repo_findings}" -eq 0 ]; then
    echo "No findings." >> "${REPORT_MD}"
  fi
  echo "" >> "${REPORT_MD}"
  TOTAL_FINDINGS=$((TOTAL_FINDINGS + repo_findings))
}

# ---------------------------------------------------------------------------
# Main scan loop
# ---------------------------------------------------------------------------
USE_GITLEAKS=0
if command -v gitleaks >/dev/null 2>&1; then
  USE_GITLEAKS=1
  echo "Using gitleaks: $(command -v gitleaks)"
else
  echo "gitleaks not found on PATH; using built-in regex fallback scan."
fi

for repo in "${TARGET_REPOS[@]}"; do
  repo_path="${SCAN_ROOT}/${repo}"
  if [ ! -d "${repo_path}" ]; then
    echo "WARN: target repo not found, skipping: ${repo_path}"
    echo "## ${repo}" >> "${REPORT_MD}"
    echo "" >> "${REPORT_MD}"
    echo "Repository not found at ${repo_path}; skipped." >> "${REPORT_MD}"
    echo "" >> "${REPORT_MD}"
    continue
  fi
  echo "Scanning ${repo} (${repo_path})..."
  if [ "${USE_GITLEAKS}" -eq 1 ]; then
    run_gitleaks_for_repo "${repo}" "${repo_path}"
  else
    run_fallback_for_repo "${repo}" "${repo_path}"
  fi
done

# ---------------------------------------------------------------------------
# Finalize reports
# ---------------------------------------------------------------------------
{
  echo "## Summary"
  echo ""
  echo "- Total findings: ${TOTAL_FINDINGS}"
  echo "- Scanner: $([ "${USE_GITLEAKS}" -eq 1 ] && echo gitleaks || echo 'built-in regex fallback')"
  echo "- Exit code: $([ "${TOTAL_FINDINGS}" -gt 0 ] && echo 2 || echo 0)"
} >> "${REPORT_MD}"

SCANNER_NAME="$([ "${USE_GITLEAKS}" -eq 1 ] && echo gitleaks || echo fallback-regex)"
cat > "${REPORT_JSON}" <<EOF
{
  "generated_utc": "${TIMESTAMP}",
  "scan_root": "${SCAN_ROOT}",
  "target_repos": ["json-server", "gson", "click"],
  "scanner": "${SCANNER_NAME}",
  "total_findings": ${TOTAL_FINDINGS},
  "findings": [
${JSON_FINDINGS}
  ]
}
EOF

# ---------------------------------------------------------------------------
# stdout summary
# ---------------------------------------------------------------------------
echo ""
echo "=============================================="
echo " Secret scan complete"
echo "  Repos scanned : ${TARGET_REPOS[*]}"
echo "  Total findings: ${TOTAL_FINDINGS}"
echo "  Markdown report: ${REPORT_MD}"
echo "  JSON report    : ${REPORT_JSON}"
echo "=============================================="

if [ "${TOTAL_FINDINGS}" -gt 0 ]; then
  echo "SECRETS FOUND - review the report and rotate affected credentials."
  exit 2
fi

echo "No secrets found - clean."
exit 0
