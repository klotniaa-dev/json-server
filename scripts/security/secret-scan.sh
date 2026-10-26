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
# gitleaks path
# ---------------------------------------------------------------------------
run_gitleaks_for_repo() {
  local repo_name="$1" repo_path="$2"
  local gl_report="${REPORT_DIR}/gitleaks-${repo_name}-${TIMESTAMP}.json"

  echo "## ${repo_name} (gitleaks)" >> "${REPORT_MD}"
  echo "" >> "${REPORT_MD}"

  # Filesystem scan (working tree, no git history).
  gitleaks detect --source "${repo_path}" --no-git --redact \
    --report-format json --report-path "${gl_report}" >/dev/null 2>&1 || true

  # If the repo has git history, also scan it.
  if [ -d "${repo_path}/.git" ]; then
    local gl_hist="${REPORT_DIR}/gitleaks-${repo_name}-history-${TIMESTAMP}.json"
    gitleaks detect --source "${repo_path}" --redact \
      --report-format json --report-path "${gl_hist}" >/dev/null 2>&1 || true
  fi

  local count=0
  if [ -f "${gl_report}" ]; then
    # Count top-level JSON array entries using python3 (available in sandbox).
    count="$(python3 -c "import json,sys;
try:
    data=json.load(open('${gl_report}'))
    print(len(data) if isinstance(data,list) else 0)
except Exception:
    print(0)" 2>/dev/null || echo 0)"
  fi

  if [ "${count}" -gt 0 ]; then
    echo "Found ${count} potential secret(s). See ${gl_report}." >> "${REPORT_MD}"
    # Extract per-finding details.
    while IFS=$'\t' read -r f ln rule; do
      [ -z "${f}" ] && continue
      add_json_finding "${repo_name}" "${f}" "${ln:-0}" "HIGH" "${rule}"
      echo "- HIGH \`${f}:${ln}\` rule=${rule}" >> "${REPORT_MD}"
    done < <(python3 -c "import json;
data=json.load(open('${gl_report}'))
for x in data:
    print('%s\t%s\t%s' % (x.get('File',''), x.get('StartLine',0), x.get('RuleID','')))" 2>/dev/null || true)
    TOTAL_FINDINGS=$((TOTAL_FINDINGS + count))
  else
    echo "No findings." >> "${REPORT_MD}"
  fi
  echo "" >> "${REPORT_MD}"
}

# ---------------------------------------------------------------------------
# Built-in regex fallback
# ---------------------------------------------------------------------------
# Each entry: "SEVERITY|RULE|REGEX"
declare -a PATTERNS=(
  "CRITICAL|AWS Access Key ID|AKIA[0-9A-Z]{16}"
  "CRITICAL|Private Key Header|-----BEGIN ([A-Z ]+ )?PRIVATE KEY-----"
  "CRITICAL|GitHub Token|(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[0-9A-Za-z_]{20,}"
  "HIGH|Slack Token|xox[baprs]-[0-9A-Za-z-]{10,}"
  "HIGH|AWS Secret Access Key|(aws_secret_access_key|aws_secret)[[:space:]]*[:=][[:space:]]*[\"']?[A-Za-z0-9/+=]{40}[\"']?"
  "MEDIUM|Generic Secret Assignment|(api[_-]?key|secret|password|passwd|token|access[_-]?key)[\"']?[[:space:]]*[:=][[:space:]]*[\"'][^\"']{8,}[\"']"
  "LOW|High-Entropy Assignment|[\"']?[A-Za-z0-9_]+[\"']?[[:space:]]*[:=][[:space:]]*[\"'][A-Za-z0-9+/]{32,}={0,2}[\"']"
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
      severity="${entry%%|*}"
      rule="${entry#*|}"; rule="${rule%%|*}"
      regex="${entry##*|}"
      # grep -I skips binary files; -n gives line numbers; -E extended regex.
      local match
      while IFS= read -r match; do
        [ -z "${match}" ] && continue
        local ln="${match%%:*}"
        local rel="${file#${SCAN_ROOT}/}"
        add_json_finding "${repo_name}" "${rel}" "${ln}" "${severity}" "${rule}"
        echo "- ${severity} \`${rel}:${ln}\` rule=${rule}" >> "${REPORT_MD}"
        repo_findings=$((repo_findings + 1))
      done < <(grep -InE "${regex}" "${file}" 2>/dev/null | cut -d: -f1 | sed 's/$/:/' || true)
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
