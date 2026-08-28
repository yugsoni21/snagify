#!/bin/sh
set -e

SCAN_PATH="${1:-.}"
MIN_SCORE="${2:-}"
TARGET="$GITHUB_WORKSPACE/$SCAN_PATH"

echo "Snagify Action — scanning $TARGET"
echo ""

# A scanner that crashes must never look like a clean result — track failures
# so the summary says "unknown", not "0 findings".
SCANNER_ERRORS=""

# ── Semgrep ──────────────────────────────────────────────────────────────
echo "→ Semgrep (code vulnerabilities)…"
if semgrep --config=auto --json --quiet "$TARGET" > /tmp/semgrep.json 2>/tmp/semgrep.err \
   && jq -e '.results' /tmp/semgrep.json >/dev/null 2>&1; then
  SEMGREP_OK=1
else
  SEMGREP_OK=0
  SCANNER_ERRORS="${SCANNER_ERRORS}semgrep failed: $(tail -c 200 /tmp/semgrep.err 2>/dev/null | tr '\n' ' ')\n"
  echo "  ! semgrep failed — see warnings below"
fi
CODE_FINDINGS=$(jq '[.results[]?] | length' /tmp/semgrep.json 2>/dev/null || echo 0)
DEDUCT_CODE=$(jq '[.results[]? | (.extra.severity // "INFO") | if . == "ERROR" then 10 elif . == "WARNING" then 5 else 2 end] | add // 0' /tmp/semgrep.json 2>/dev/null || echo 0)

# ── Gitleaks ─────────────────────────────────────────────────────────────
echo "→ Gitleaks (secrets)…"
if gitleaks detect --source "$TARGET" --report-format=json --report-path=/tmp/gitleaks.json --no-git --exit-code 0 >/tmp/gitleaks.log 2>&1 \
   && [ -f /tmp/gitleaks.json ]; then
  GITLEAKS_OK=1
  SECRETS=$(jq 'length' /tmp/gitleaks.json 2>/dev/null || echo 0)
else
  GITLEAKS_OK=0
  SECRETS=0
  SCANNER_ERRORS="${SCANNER_ERRORS}gitleaks failed: $(tail -c 200 /tmp/gitleaks.log 2>/dev/null | tr '\n' ' ')\n"
  echo "  ! gitleaks failed — see warnings below"
fi
DEDUCT_SECRETS=$((SECRETS * 20))

# ── OSV-Scanner ──────────────────────────────────────────────────────────
echo "→ OSV-Scanner (dependency CVEs)…"
# osv-scanner exits non-zero when it finds vulns (expected) AND on real errors,
# so validate the JSON shape instead of trusting the exit code. Exit 128 means
# "no dependency manifests found" — nothing to scan, not a failure.
set +e
osv-scanner scan source -r --format json "$TARGET" > /tmp/osv.json 2>/tmp/osv.err
OSV_EXIT=$?
set -e
if jq -e 'has("results")' /tmp/osv.json >/dev/null 2>&1 || [ "$OSV_EXIT" -eq 128 ]; then
  OSV_OK=1
else
  OSV_OK=0
  SCANNER_ERRORS="${SCANNER_ERRORS}osv-scanner failed (exit $OSV_EXIT): $(tail -c 200 /tmp/osv.err 2>/dev/null | tr '\n' ' ')\n"
  echo "  ! osv-scanner failed — see warnings below"
fi
VULN_DEPS=$(jq '[.results[]?.packages[]?.groups[]?] | length' /tmp/osv.json 2>/dev/null || echo 0)
DEDUCT_OSV=$(jq '[.results[]?.packages[]?.groups[]? | (.max_severity // "0" | tonumber) | if . >= 9 then 20 elif . >= 7 then 10 elif . >= 4 then 5 else 2 end] | add // 0' /tmp/osv.json 2>/dev/null || echo 0)

# ── Score ────────────────────────────────────────────────────────────────
TOTAL_DEDUCT=$((DEDUCT_CODE + DEDUCT_SECRETS + DEDUCT_OSV))
SCORE=$((100 - TOTAL_DEDUCT))
if [ "$SCORE" -lt 0 ]; then SCORE=0; fi

[ "$SEMGREP_OK" -eq 1 ] && CODE_LABEL="$CODE_FINDINGS" || CODE_LABEL="unknown (scanner failed)"
[ "$GITLEAKS_OK" -eq 1 ] && SECRETS_LABEL="$SECRETS" || SECRETS_LABEL="unknown (scanner failed)"
[ "$OSV_OK" -eq 1 ] && DEPS_LABEL="$VULN_DEPS" || DEPS_LABEL="unknown (scanner failed)"

echo ""
echo "  Code findings           $CODE_LABEL"
echo "  Secrets                 $SECRETS_LABEL"
echo "  Vulnerable dependencies $DEPS_LABEL"
echo ""
echo "  Security score          $SCORE/100"
if [ -n "$SCANNER_ERRORS" ]; then
  echo ""
  echo "  WARNING: one or more scanners failed — this score is incomplete."
  printf "  %b" "$SCANNER_ERRORS"
fi

# ── Outputs ──────────────────────────────────────────────────────────────
if [ -n "$GITHUB_OUTPUT" ]; then
  {
    echo "score=$SCORE"
    echo "code-findings=$CODE_FINDINGS"
    echo "secrets=$SECRETS"
    echo "vulnerable-dependencies=$VULN_DEPS"
  } >> "$GITHUB_OUTPUT"
fi

# ── Job summary ──────────────────────────────────────────────────────────
if [ -n "$GITHUB_STEP_SUMMARY" ]; then
  {
    echo "## Snagify Security Scan"
    echo ""
    echo "| Metric | Count |"
    echo "|---|---|"
    echo "| Code findings | $CODE_FINDINGS |"
    echo "| Secrets | $SECRETS |"
    echo "| Vulnerable dependencies | $VULN_DEPS |"
    echo "| **Security score** | **$SCORE/100** |"
    if [ -n "$SCANNER_ERRORS" ]; then
      echo ""
      echo "> **Warning:** one or more scanners failed, so this score is incomplete."
      echo ""
      printf '```\n%b```\n' "$SCANNER_ERRORS"
    fi
  } >> "$GITHUB_STEP_SUMMARY"
fi

# ── Gate ─────────────────────────────────────────────────────────────────
if [ -n "$MIN_SCORE" ] && [ -n "$SCANNER_ERRORS" ]; then
  echo ""
  echo "FAIL: a scanner failed, so the score cannot be trusted against min-score $MIN_SCORE"
  exit 1
fi

if [ -n "$MIN_SCORE" ]; then
  if [ "$SCORE" -lt "$MIN_SCORE" ]; then
    echo ""
    echo "FAIL: score $SCORE is below required minimum $MIN_SCORE"
    exit 1
  fi
  echo ""
  echo "PASS: score $SCORE meets minimum $MIN_SCORE"
fi

exit 0
