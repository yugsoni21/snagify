<div align="center">

<img src="resources/icon.png" width="96" height="96" alt="Snagify icon" />

# Snagify

**Scan your code for vulnerabilities, secrets, and vulnerable dependencies — in one click.**

Snagify is a desktop app that runs three security scanners at once, then uses AI to turn the results into one clear score with plain-English explanations and one-click fixes.

[**⬇ Download for macOS**](#-download) · [**⬇ Download for Windows**](#-download) · [Set up in 2 minutes](#-set-up-2-minutes)

</div>

---

## What you get

| | |
|---|---|
| 🛡️ **One security score** | Runs Semgrep, Gitleaks, and OSV-Scanner together and merges the results into a single 0–100 score |
| 🔑 **Secret detection** | Finds hardcoded API keys, passwords, and tokens before they leak |
| 📦 **Dependency CVEs** | Flags vulnerable packages with the exact version that fixes them |
| 🧠 **AI explanations** | Every finding gets a plain-English "why this matters" and a concrete fix |
| 🩹 **One-click patches** | Preview an AI-generated fix as a diff, apply it, undo it if you don't like it |
| 📈 **Scan history** | Track your score over time — see "3 fixed, 1 new" after every re-scan |
| 📄 **PDF reports** | Export a polished, shareable report — with your own logo, if you want |
| 🚀 **Scalability check** | Finds what will break under real-world load, not just what's insecure today |

---

## 📥 Download

> **Snagify is early — releases aren't published yet.** Until then, build it yourself in about 2 minutes (see [Set up](#-set-up-2-minutes) below). Once a release is published, it will appear on the [**Releases page**](https://github.com/yugsoni21/snagify/releases) as a `.dmg` (macOS) or installer (Windows) — no building required.

---

## 🚀 Set up (2 minutes)

You'll need [Node.js](https://nodejs.org) (v18 or newer) installed. That's it.

### 1. Get the code

```sh
git clone https://github.com/yugsoni21/snagify.git
cd snagify
```

### 2. Install and run

```sh
npm install
npm run dev
```

The app window opens automatically. That's the whole setup.

### 3. Add your AI key (optional, but recommended)

Without a key, Snagify still scans and gives you a raw list of findings. With a key, it adds a single score, plain-English explanations, one-click fixes, and load-testing insight.

Open **Settings → AI Provider** in the app and pick one:

| Provider | Where to get a key |
|---|---|
| **Anthropic (Claude)** | [console.anthropic.com](https://console.anthropic.com/settings/keys) |
| **OpenAI (GPT)** | [platform.openai.com](https://platform.openai.com/api-keys) |
| **Google (Gemini)** | [aistudio.google.com](https://aistudio.google.com/apikey) — has a free tier |
| **Ollama (local)** | [ollama.com](https://ollama.com/download) — no key needed, nothing leaves your machine |

Paste your key in, hit **Test**, and you're done.

### That's it — scan something

Click **New Scan**, pick a project folder, and watch the results come in.

---

## 📦 Building an installer yourself

If you'd rather have a proper `.app` / installer instead of running in dev mode:

```sh
npm run package:mac    # macOS — creates a .dmg in dist-electron/
npm run package:win    # Windows — creates a setup .exe in dist-electron/
```

> **macOS note:** the app isn't code-signed yet, so on first launch macOS will say it "cannot be opened" or is from an "unidentified developer." Right-click the app → **Open** → **Open** again. You only need to do this once.

---

## 🧑‍💻 For developers: the CLI

Snagify also ships as a standalone command-line tool — same three scanners, same AI analysis, runs anywhere (including CI). See [`cli/README.md`](cli/README.md) for the full guide, or the short version:

```sh
cd cli && npm install && npm run build && npm install -g .
snagify scan .
```

### GitHub Action

```yaml
- uses: yugsoni21/snagify@v1
  with:
    path: .
    min-score: 70
```

Runs Semgrep + Gitleaks + OSV-Scanner in CI and fails the build below your threshold. See [`action.yml`](action.yml).

---

## What it scans

| Engine | Catches | License |
|---|---|---|
| [Semgrep](https://semgrep.dev) | Injection, auth bypass, insecure crypto — 1,000+ rules | LGPL 2.1 |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Hardcoded secrets, API keys, credentials | MIT |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Known CVEs in your dependencies (npm, pip, Go, Rust, Maven…) | Apache 2.0 |

Plus a deep AI review pass that catches what pattern scanners structurally can't — missing authorization checks, business-logic flaws, and security controls that exist in code but are never actually called.

---

## 🔒 Privacy

- Semgrep's default ruleset fetches rules from its public registry — **no code is uploaded** to run a scan.
- AI features send finding details and relevant code snippets to whichever provider you choose, and **only when you configure one**.
- Choose **Ollama** and nothing ever leaves your machine — not even metadata.
- Your API key is stored encrypted via your OS's keychain, never in plain text.

---

## License

MIT — see [LICENSE](LICENSE).
