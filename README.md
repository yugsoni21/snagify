# Snagify

**One command. Three scanners. One score.**

Snagify wraps [Semgrep](https://semgrep.dev) (code vulnerabilities), [Gitleaks](https://github.com/gitleaks/gitleaks) (secrets), and [OSV-Scanner](https://github.com/google/osv-scanner) (dependency CVEs) behind a single CLI and desktop app — then uses Claude to triage the combined output into one ranked list with fix suggestions, instead of three separate tools with three separate formats you have to cross-reference by hand.

```
$ snagify --scan .

Snagify Security Scan
Project: /Users/you/my-app

  Code findings           4
  Secrets                 1
  Vulnerable dependencies 7

  Security score          62/100

  Top findings:
   [CRITICAL] Hardcoded AWS secret key            (src/config.js:12)
   [HIGH    ] SQL injection via string concat     (src/db.js:44)
   [HIGH    ] tar 6.2.1 — CVE-2026-24842          (package-lock.json)
   ...
```

## Why

You already have Semgrep, Gitleaks, and a dependency scanner in your toolbox — running them separately, reading three JSON formats, and manually prioritizing across them is the actual friction. Snagify runs all three, deduplicates and normalizes the output, and (optionally) sends it to Claude for a single security score, an executive summary, and concrete per-finding fixes mapped to CWE/OWASP.

## Install

```sh
brew install snagify        # macOS (coming soon)
npm install -g snagify-cli  # cross-platform (coming soon)
```

Or build from source — see [Development](#development) below.

## Usage

```sh
snagify --scan <path>                # human-readable report
snagify --scan <path> --json         # machine-readable, full findings
snagify --scan <path> --min-score 80 # exit 1 if score is below 80 — for CI
snagify --scan <path> --no-ai        # skip AI triage, use deterministic scoring
```

### Pre-commit hook

```sh
snagify --install-hook <repo> --min-score 60
```

Blocks commits when the security score drops below the threshold. Bypass once with `git commit --no-verify`.

### GitHub Action

```yaml
- uses: snagify/snagify-action@v1
  with:
    path: .
    min-score: 70
```

Runs Semgrep + Gitleaks + OSV-Scanner in a container, posts a summary to the job, and fails the build below the threshold. See [action.yml](action.yml).

### Desktop app

The desktop app (macOS/Windows, built on Electron) adds AI-powered fix patches you can preview and apply with one click, scan history with trend comparison ("3 fixed, 1 new since last scan"), false-positive suppression, and PDF report export.

### Scalability analysis

Static scanners tell you what is insecure; they say nothing about what falls over under load. Snagify also reviews the load-bearing files in your project and reports a **load-readiness score** with concrete bottlenecks — unpaginated queries, in-memory state that breaks across instances, blocking work in request handlers, missing rate limits — each with what specifically happens as usage grows and how to fix it.

## What it scans

| Engine | Catches | License |
|---|---|---|
| [Semgrep](https://semgrep.dev) | Injection, auth bypass, insecure crypto, 1,000+ rules | LGPL 2.1 |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Hardcoded secrets, API keys, credentials | MIT |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Known CVEs in your dependencies (npm, pip, Go, Rust, Maven, ...) | Apache 2.0 |

AI triage (optional, requires an Anthropic API key) consolidates findings into a single score, deduplicates cross-tool noise, and writes fix suggestions.

## Development

```sh
git clone https://github.com/snagify/snagify
cd snagify
npm install
npm run dev        # desktop app, dev mode
npm run build       # production build
```

Requires `semgrep`, `gitleaks`, and `osv-scanner` on your PATH (or in `resources/binaries/`) for local scanning.

## Privacy

Semgrep's default ruleset (`--config=auto`) fetches rules from Semgrep's public registry over the network — no code is uploaded. AI triage sends only the deduplicated, slimmed finding metadata (rule ID, file, line, message) to the Anthropic API — never full source files — and only when you provide an API key. Everything else runs and stays local.

## License

MIT — see [LICENSE](LICENSE).
# snagify
