# snagify

**One command, three scanners, one score.**

```
$ snagify

  Snagify Security Scan
  /Users/you/my-app

  Code findings           4
  Secrets                 1
  Vulnerable dependencies 7

  Security score          62/100  (Fair, AI analysis)
  vs last scan            3 fixed · 1 new  +8 pts

  CRITICAL Hardcoded Stripe key committed to source
           src/config.js:12
           CWE-798 · A07:2021 Identification and Authentication Failures

  HIGH     SQL injection via string concatenation
           src/db.js:44
           CWE-89 · A03:2021 Injection
```

Snagify runs [Semgrep](https://semgrep.dev) (code vulnerabilities), [Gitleaks](https://github.com/gitleaks/gitleaks) (secrets), and [OSV-Scanner](https://github.com/google/osv-scanner) (dependency CVEs), then optionally uses an AI model to merge the three outputs into one ranked list with a single score and concrete fixes — instead of three tools with three formats you cross-reference by hand.

It also runs a **deep review** pass that reads your source directly, catching the class of bug pattern scanners structurally cannot find: missing authorization checks, business-logic flaws, trust-boundary mistakes, and security controls that are defined but never called.

Works with Claude, GPT, Gemini, Groq, or a **fully local Ollama model**.

## Install

```sh
npm install -g snagify
```

Then install the scanners you want (Snagify skips any that are missing):

```sh
pip install semgrep
brew install gitleaks osv-scanner
```

Check your setup any time:

```sh
snagify doctor
```

## Usage

```sh
snagify                              # scan the current directory
snagify scan ./api                   # scan a specific path
snagify scan . --scalability         # also assess what breaks under load
snagify scan . --min-score 80        # exit 1 if below 80 (CI gate)
snagify scan . --json > report.json  # machine-readable
snagify scan . --sarif results.sarif # upload to GitHub code scanning
snagify scan . --md report.md        # Markdown report
snagify fix .                        # review and apply AI patches
snagify hook install .               # block risky commits
```

Run `snagify --help` for the full list.

## AI providers (optional)

Triage, fix generation, deep review, and scalability analysis work with **any** of these. Everything else runs without one.

| Provider | Key | Notes |
|---|---|---|
| Anthropic (Claude) | `sk-ant-…` | |
| OpenAI (GPT) | `sk-…` | |
| Google (Gemini) | `AIza…` | free tier available |
| **Ollama** | none | **local — your code never leaves your machine** |
| Groq / OpenRouter / Together / LM Studio | varies | any OpenAI-compatible endpoint |

```sh
snagify config --key sk-ant-…                       # provider auto-detected from the key
snagify config --provider ollama --model llama3.1   # fully local, no key
snagify config --provider openai-compatible \
  --base-url https://api.groq.com/openai/v1 --key gsk_…
snagify config --test                               # verify it works
```

Or use environment variables — handy in CI:

```sh
ANTHROPIC_API_KEY=…   OPENAI_API_KEY=…   GOOGLE_API_KEY=…
SNAGIFY_PROVIDER=ollama            # local models
SNAGIFY_API_KEY=…                  # OpenAI-compatible endpoints
```

Running `snagify` with no provider configured prompts you to pick one. Without any, it falls back to deterministic scoring and still reports every finding.

> For sensitive codebases, Ollama keeps everything on your machine — no code, no metadata, no network calls.

## Scalability analysis

Static scanners tell you what is insecure; they say nothing about what falls over under load. `--scalability` reviews the load-bearing files in your project and reports a **load-readiness score** with concrete bottlenecks:

```
  HIGH     DATABASE      Unpaginated query over a growing table
           under load: At ~10k rows this loads the entire table into
           memory on every request

  MEDIUM   MEMORY        In-memory session store
           under load: Sessions vanish on restart and break entirely
           behind more than one instance
```

## CI

```yaml
- run: npm install -g snagify
- run: snagify scan . --min-score 70 --sarif results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: results.sarif }
```

The gate exits `1` below the threshold — and also **if a scanner crashed**, so a broken scan can never be mistaken for a clean one.

## Fixes

```sh
snagify fix .
```

For each finding, Snagify asks Claude for a minimal patch, verifies it matches your file byte-for-byte, shows the diff, and applies it only if you say yes. Every applied patch is backed up:

```sh
snagify fix --revert <backup-id>
```

## False positives

```sh
snagify ignore . --add      # pick a finding to ignore
snagify ignore .            # list ignored findings
snagify ignore . --remove <key>
```

Ignored findings are excluded from future scans of that project and the score is recomputed without them.

## Configuration

| Variable | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `GOOGLE_API_KEY` | Enables AI features |
| `SNAGIFY_PROVIDER` | `anthropic` \| `openai` \| `google` \| `ollama` \| `openai-compatible` |
| `SNAGIFY_MODEL` | Override the model |
| `SNAGIFY_BASE_URL` | Override the API base URL |
| `SNAGIFY_HOME` | Config/history dir (default `~/.snagify`) |
| `NO_COLOR` | Disable colored output |

## Privacy

Semgrep's default ruleset fetches rules from its public registry — no code is uploaded. AI features send finding metadata plus the relevant code excerpts to your chosen provider, and only when you configure one. Secrets are always redacted before being sent, and redacted in `--json` output. Everything else stays local.

**Choose Ollama and nothing leaves your machine at all.**

Zero runtime dependencies.

## Tests

```sh
npm test              # 94 tests: unit + integration
npm run test:unit     # fast, no scanners needed
```

Integration tests spawn the real CLI against fixture projects with planted
vulnerabilities, and skip cleanly when a scanner is not installed.

## License

MIT
