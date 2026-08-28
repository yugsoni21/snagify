import { readFileSync, statSync, existsSync, realpathSync } from 'fs'
import { sep, isAbsolute } from 'path'
import { resolveProvider } from './config.js'
import { complete, ProviderError } from './providers.js'
import { pickLoadBearingFiles } from './scanners.js'
import type {
  AIFinding, AnalysisResult, FixPatch, GitleaksFinding, OsvFinding,
  ScalabilityAssessment, ScalabilityBottleneck, SemgrepFinding
} from './types.js'

export class MissingApiKeyError extends Error {
  constructor() { super('No AI provider configured. Run: snagify config --key <key>   (Anthropic, OpenAI, Gemini, Groq, or local Ollama)') }
}

async function callClaude(system: string, user: string, maxTokens: number): Promise<string> {
  const cfg = resolveProvider()
  if (!cfg) throw new MissingApiKeyError()
  try {
    // Every prompt here demands strict JSON, so ask for the native JSON mode
    return await complete(cfg, { system, user, maxTokens, json: true })
  } catch (e) {
    if (e instanceof ProviderError) throw new Error(e.message)
    throw e
  }
}

/** Salvage JSON from a truncated or fenced response. */
export function repairJson(raw: string): string {
  const start = raw.indexOf('{')
  if (start === -1) throw new Error('No JSON object in AI response')
  let s = raw.slice(start)
  try { JSON.parse(s); return s } catch { /* needs repair */ }
  const stack: string[] = []
  let inStr = false, esc = false, lastClose = -1
  for (let i = 0; i < s.length; i++) {
    const c = s[i]
    if (esc) { esc = false; continue }
    if (c === '\\' && inStr) { esc = true; continue }
    if (c === '"') { inStr = !inStr; continue }
    if (inStr) continue
    if (c === '{' || c === '[') stack.push(c === '{' ? '}' : ']')
    else if (c === '}' || c === ']') {
      if (stack.length && stack[stack.length - 1] === c) stack.pop()
      if (!stack.length) { lastClose = i; break }
    }
  }
  if (lastClose > 0) {
    const cand = s.slice(0, lastClose + 1)
    try { JSON.parse(cand); return cand } catch { /* keep going */ }
  }
  s = s.trimEnd().replace(/,\s*$/, '')
  const repaired = s + [...stack].reverse().join('')
  JSON.parse(repaired)
  return repaired
}

// ── Security triage ─────────────────────────────────────────────────────────

const TRIAGE_PROMPT = `You are a security and compliance expert analyzing code scan results from Semgrep (code vulnerabilities), Gitleaks (secrets), and OSV (dependency CVEs). Produce a structured security analysis.

Return ONLY valid JSON (no markdown, no extra text):
{
  "securityScore": <integer 0-100, 100 is perfectly secure>,
  "summary": "<2-3 sentence executive summary>",
  "criticalCount": <int>, "highCount": <int>, "mediumCount": <int>, "lowCount": <int>,
  "findings": [
    {
      "id": "<unique short string>",
      "title": "<concise descriptive title>",
      "severity": "<critical|high|medium|low>",
      "explanation": "<what this is and why it is dangerous>",
      "fixSuggestion": "<specific actionable remediation>",
      "file": "<path or empty string>",
      "line": <int or null>,
      "cwe": ["<CWE-79 etc, max 3, or []>"],
      "owasp": ["<A03:2021 Injection etc, max 2, or []>"]
    }
  ],
  "complianceIssues": [
    { "regulation": "<GDPR|HIPAA|PCI-DSS|SOC2|CCPA>", "article": "<specific rule>", "description": "<what violates it>", "recommendation": "<what to change>" }
  ]
}

Severity: critical for secrets/RCE/auth bypass; high for injection/data exposure; medium for misconfig; low for best practices. For dependency CVEs use CVSS: >=9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, else low; title should name package and CVE, and fixSuggestion the exact upgrade.
For cwe/owasp: copy provided metadata when present, else infer the standard mapping (hardcoded secrets CWE-798 / A07:2021; vulnerable deps CWE-1395 / A06:2021). Empty arrays if unmappable.
Each finding includes a "code" excerpt showing the actual source (the flagged line is marked with >). USE IT:
- Judge real exploitability from the code, not from the rule name. If the code shows the input is already validated, sanitized, parameterized, or is a hardcoded constant, downgrade severity or drop the finding and say why in the explanation.
- Write explanations that reference the specific variables, functions, and control flow you can see — never generic rule descriptions.
- Make fixSuggestion a concrete change to THIS code (name the variable/function and the exact replacement), not boilerplate advice.

Only report issues evidenced by the findings — never speculate. Sort by severity. Limit 50.
Score: start 100, deduct critical -20, high -10, medium -5, low -2, min 0.
complianceIssues: only clearly-evidenced violations, else [].`

/** Read ±context lines around a finding so the model can judge real exploitability
 *  instead of guessing from a rule id. Cached per file to avoid re-reading. */
const fileCache = new Map<string, string[] | null>()

function readLines(path: string): string[] | null {
  if (fileCache.has(path)) return fileCache.get(path) ?? null
  let lines: string[] | null = null
  try {
    const st = statSync(path)
    if (st.isFile() && st.size <= 2_000_000) lines = readFileSync(path, 'utf-8').split('\n')
  } catch { lines = null }
  fileCache.set(path, lines)
  return lines
}

export function codeContext(path: string, line: number | null | undefined, before = 8, after = 8): string {
  const lines = readLines(path)
  if (!lines || !line || line < 1) return ''
  const start = Math.max(0, line - 1 - before)
  const end = Math.min(lines.length, line + after)
  return lines.slice(start, end)
    .map((text, i) => {
      const n = start + i + 1
      return `${n === line ? '>' : ' '} ${String(n).padStart(4)} | ${text}`
    })
    .join('\n')
    .slice(0, 2400)
}

function slimSemgrep(f: SemgrepFinding): Record<string, unknown> {
  const line = f.start?.line
  return {
    check_id: f.check_id,
    path: f.path,
    line,
    message: (f.extra?.message ?? '').slice(0, 180),
    severity: f.extra?.severity,
    cwe: f.extra?.metadata?.cwe?.slice(0, 3),
    owasp: f.extra?.metadata?.owasp?.slice(0, 2),
    code: codeContext(f.path, line)
  }
}

function slimGitleaks(f: GitleaksFinding): Record<string, unknown> {
  // Send surrounding code for context, but never the secret value itself
  const ctx = codeContext(f.File, f.StartLine, 4, 4).replace(f.Secret ?? '', '[REDACTED]')
  return { RuleID: f.RuleID, Description: f.Description, File: f.File, StartLine: f.StartLine, code: ctx }
}

function slimOsv(f: OsvFinding): Record<string, unknown> {
  return {
    package: f.package, version: f.version, ecosystem: f.ecosystem,
    cve: f.aliases.find(a => a.startsWith('CVE-')) ?? f.ids[0],
    cvss: f.cvss, summary: f.summary.slice(0, 150), fixedVersion: f.fixedVersion, file: f.file
  }
}

function mergeAnalyses(parts: AnalysisResult[]): AnalysisResult {
  const findings = parts.flatMap(p => p.findings)
  const seen = new Set<string>()
  const compliance = parts.flatMap(p => p.complianceIssues ?? []).filter(c => {
    const k = `${c.regulation}:${c.article}`
    if (seen.has(k)) return false
    seen.add(k); return true
  })
  const count = (s: string): number => findings.filter(f => f.severity === s).length
  const deduction = findings.reduce((a, f) => a + ({ critical: 20, high: 10, medium: 5, low: 2 }[f.severity] ?? 2), 0)
  return {
    securityScore: Math.max(0, 100 - deduction),
    summary: parts.map(p => p.summary).filter(Boolean)[0] ?? 'Scan complete.',
    criticalCount: count('critical'), highCount: count('high'),
    mediumCount: count('medium'), lowCount: count('low'),
    findings, complianceIssues: compliance
  }
}

function normalizeAnalysis(raw: unknown): AnalysisResult {
  const a = raw as Partial<AnalysisResult>
  const findings = (Array.isArray(a.findings) ? a.findings : []).map((f, i) => ({
    id: String((f as AIFinding).id ?? `f${i}`),
    title: String((f as AIFinding).title ?? 'Finding'),
    severity: (['critical', 'high', 'medium', 'low'].includes((f as AIFinding).severity) ? (f as AIFinding).severity : 'low') as AIFinding['severity'],
    explanation: String((f as AIFinding).explanation ?? ''),
    fixSuggestion: String((f as AIFinding).fixSuggestion ?? ''),
    file: typeof (f as AIFinding).file === 'string' ? (f as AIFinding).file : '',
    line: typeof (f as AIFinding).line === 'number' ? (f as AIFinding).line : null,
    cwe: Array.isArray((f as AIFinding).cwe) ? (f as AIFinding).cwe : [],
    owasp: Array.isArray((f as AIFinding).owasp) ? (f as AIFinding).owasp : []
  }))
  const count = (s: string): number => findings.filter(f => f.severity === s).length
  const score = Number(a.securityScore)
  return {
    securityScore: Number.isFinite(score) ? Math.max(0, Math.min(100, Math.round(score))) : 50,
    summary: String(a.summary ?? ''),
    criticalCount: count('critical'), highCount: count('high'),
    mediumCount: count('medium'), lowCount: count('low'),
    findings,
    complianceIssues: Array.isArray(a.complianceIssues) ? a.complianceIssues : []
  }
}

export async function analyzeFindings(
  code: SemgrepFinding[], secrets: GitleaksFinding[], deps: OsvFinding[],
  onProgress?: (msg: string) => void
): Promise<AnalysisResult> {
  const S = 10, G = 5, O = 12
  const batches = Math.max(Math.ceil(code.length / S), Math.ceil(secrets.length / G), Math.ceil(deps.length / O), 1)
  const results: AnalysisResult[] = []
  for (let i = 0; i < batches; i++) {
    if (batches > 1) onProgress?.(`AI triage — batch ${i + 1}/${batches}`)
    const user = `Analyze these security scan results${batches > 1 ? ` (batch ${i + 1} of ${batches})` : ''}:

Semgrep findings:
${JSON.stringify(code.slice(i * S, (i + 1) * S).map(slimSemgrep))}

Gitleaks findings:
${JSON.stringify(secrets.slice(i * G, (i + 1) * G).map(slimGitleaks))}

OSV dependency vulnerabilities:
${JSON.stringify(deps.slice(i * O, (i + 1) * O).map(slimOsv))}`
    const text = await callClaude(TRIAGE_PROMPT, user, 8000)
    results.push(normalizeAnalysis(JSON.parse(repairJson(text))))
  }
  return results.length === 1 ? results[0] : mergeAnalyses(results)
}


// ── Deep review: read the code directly ─────────────────────────────────────
//
// Semgrep matches patterns, so it structurally cannot see missing authorization,
// broken business logic, or flaws that span functions. This pass reads the source
// and reasons about it — that is where findings no rule-based scanner has come from.

const DEEP_PROMPT = `You are a senior application security engineer doing a manual code review. You are reading real source files. Find vulnerabilities that automated pattern scanners CANNOT find, because they require understanding intent, control flow, and what is missing.

Return ONLY valid JSON:
{
  "findings": [
    {
      "id": "<short unique id>",
      "title": "<specific problem naming the actual function/route/variable>",
      "severity": "<critical|high|medium|low>",
      "explanation": "<the concrete flaw: which function, which variable, what an attacker does step by step>",
      "fixSuggestion": "<the specific change to make in this code>",
      "file": "<file path as given>",
      "line": <int or null>,
      "cwe": ["<CWE-xxx>"],
      "owasp": ["<Axx:2021 ...>"]
    }
  ]
}

Hunt specifically for what pattern scanners miss:
- MISSING authorization: an endpoint/handler that reads or mutates a resource without checking the caller owns it (IDOR/BOLA). Compare handlers: if some check ownership and one does not, that one is a finding.
- Broken authentication/session logic: tokens never expiring, secrets compared non-constant-time, password reset tokens that are guessable or reusable, missing rate limits on auth endpoints.
- Business-logic flaws: negative or fractional quantities, price/total computed from client input, race conditions on balance/inventory (check-then-act without a lock or transaction), workflow steps that can be skipped.
- Trust-boundary mistakes: client-supplied ids, roles, prices, or flags used without server-side verification; mass assignment of a whole request body into a model.
- Unsafe defaults and dead controls: a security check behind a flag that defaults off, a validation function defined but never called, an error path that returns early before the check.
- Data exposure: endpoints returning entire records (password hashes, tokens, internal ids), verbose errors leaking stack traces or queries, secrets written to logs.
- Cryptographic misuse: weak hashing for passwords, static IVs, predictable randomness for tokens.

Rules:
- Only report what the provided code actually shows. Never invent files or functions you were not given. If you cannot see the auth middleware, do not assume it is missing — say what you would need to confirm.
- Each explanation must reference concrete identifiers from the code and describe a realistic attack path.
- Prefer a few high-confidence findings over many speculative ones. Return an empty array if the code is genuinely sound.
- Limit 15, sorted by severity.`

/** Independent review of the source itself, complementing rule-based scanners. */
export async function deepReview(rootPath: string, onProgress?: (m: string) => void): Promise<AIFinding[]> {
  const picked = await pickLoadBearingFiles(rootPath, 14)
  if (!picked.length) return []

  // Chunk files so each request stays well under rate limits
  const chunks: Array<Array<{ rel: string; content: string }>> = []
  let current: Array<{ rel: string; content: string }> = []
  let size = 0
  for (const f of picked) {
    let content: string
    try { content = readFileSync(f, 'utf-8') } catch { continue }
    if (content.length > 24_000) content = content.slice(0, 24_000) + '\n… (truncated)'
    if (size + content.length > 38_000 && current.length) { chunks.push(current); current = []; size = 0 }
    current.push({ rel: f.slice(rootPath.length + 1), content })
    size += content.length
  }
  if (current.length) chunks.push(current)

  const all: AIFinding[] = []
  for (let i = 0; i < chunks.length; i++) {
    onProgress?.(chunks.length > 1 ? `Deep code review — part ${i + 1}/${chunks.length}` : 'Deep code review…')
    const body = chunks[i].map(c => {
      const numbered = c.content.split('\n').map((l, n) => `${String(n + 1).padStart(4)} | ${l}`).join('\n')
      return `--- ${c.rel} ---\n${numbered}`
    }).join('\n\n')
    try {
      const text = await callClaude(DEEP_PROMPT, `Review these source files for security flaws:\n\n${body}`, 6000)
      const parsed = JSON.parse(repairJson(text)) as { findings?: unknown[] }
      for (const f of parsed.findings ?? []) {
        const x = f as Partial<AIFinding>
        if (!x.title) continue
        all.push({
          id: String(x.id ?? `deep-${all.length}`),
          title: String(x.title),
          severity: (['critical', 'high', 'medium', 'low'].includes(x.severity as string) ? x.severity : 'medium') as AIFinding['severity'],
          explanation: String(x.explanation ?? ''),
          fixSuggestion: String(x.fixSuggestion ?? ''),
          file: typeof x.file === 'string' ? x.file : '',
          line: typeof x.line === 'number' ? x.line : null,
          cwe: Array.isArray(x.cwe) ? x.cwe : [],
          owasp: Array.isArray(x.owasp) ? x.owasp : []
        })
      }
    } catch (e) {
      onProgress?.(`Deep review part ${i + 1} failed: ${String(e).slice(0, 80)}`)
    }
  }
  return all
}


/** "CWE-639: Authorization Bypass…" and "CWE-639" are the same identifier. */
function normalizeStdIds(list: string[] | undefined): string[] {
  if (!Array.isArray(list)) return []
  const seen = new Set<string>()
  const out: string[] = []
  for (const raw of list) {
    const m = String(raw).match(/(CWE-\d+|A\d{2}:\d{4})/i)
    const id = (m ? m[1] : String(raw)).toUpperCase()
    if (!seen.has(id)) { seen.add(id); out.push(id) }
  }
  return out
}

/** Make every finding's file project-relative and its standards ids canonical.
 *  Triage findings arrive with absolute paths (from Semgrep) while deep-review
 *  findings are relative — inconsistent paths break dedup and suppressions. */
export function normalizeFindings(rootPath: string, findings: AIFinding[]): AIFinding[] {
  return findings.map(f => {
    let file = f.file ?? ''
    if (file.startsWith(rootPath)) file = file.slice(rootPath.length).replace(/^[/\\]/, '')
    return { ...f, file, cwe: normalizeStdIds(f.cwe), owasp: normalizeStdIds(f.owasp) }
  })
}

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 }

/** Two findings describe the same defect when they sit in the same file, share a
 *  CWE, and point at nearby lines. Requiring the shared CWE keeps genuinely
 *  distinct issues on adjacent lines apart. */
function isSameDefect(a: AIFinding, b: AIFinding): boolean {
  if (a.file !== b.file) return false
  const shared = (a.cwe ?? []).some(c => (b.cwe ?? []).includes(c))
  if (!shared) return false
  if (a.line === null || b.line === null) return true
  return Math.abs(a.line - b.line) <= 5
}

/** Collapse duplicates, keeping the most severe and best-explained version. */
export function dedupeFindings(findings: AIFinding[]): AIFinding[] {
  const kept: AIFinding[] = []
  for (const f of findings) {
    const idx = kept.findIndex(k => isSameDefect(k, f))
    if (idx === -1) { kept.push(f); continue }
    const existing = kept[idx]
    const better = (SEVERITY_RANK[f.severity] ?? 3) < (SEVERITY_RANK[existing.severity] ?? 3) ? f : existing
    const other = better === f ? existing : f
    // Keep the richer explanation and the union of standards ids
    kept[idx] = {
      ...better,
      explanation: better.explanation.length >= other.explanation.length ? better.explanation : other.explanation,
      fixSuggestion: better.fixSuggestion.length >= other.fixSuggestion.length ? better.fixSuggestion : other.fixSuggestion,
      cwe: normalizeStdIds([...(better.cwe ?? []), ...(other.cwe ?? [])]),
      owasp: normalizeStdIds([...(better.owasp ?? []), ...(other.owasp ?? [])])
    }
  }
  return kept.sort((a, b) => (SEVERITY_RANK[a.severity] ?? 3) - (SEVERITY_RANK[b.severity] ?? 3))
}

/** Recompute counts and score from a findings list. */
export function rescore(analysis: AnalysisResult, findings: AIFinding[]): AnalysisResult {
  const count = (sev: string): number => findings.filter(f => f.severity === sev).length
  const deduction = findings.reduce((a, f) => a + ({ critical: 20, high: 10, medium: 5, low: 2 }[f.severity] ?? 2), 0)
  return {
    ...analysis,
    findings,
    securityScore: Math.max(0, 100 - deduction),
    criticalCount: count('critical'), highCount: count('high'),
    mediumCount: count('medium'), lowCount: count('low')
  }
}

/** Merge deep-review findings into an analysis, collapsing duplicates. */
export function mergeDeepFindings(analysis: AnalysisResult, deep: AIFinding[]): AnalysisResult {
  if (!deep.length) return analysis
  return rescore(analysis, dedupeFindings([...analysis.findings, ...deep]))
}

// ── Scalability ─────────────────────────────────────────────────────────────

const SCALE_PROMPT = `You are a scalability and reliability engineer reviewing application source code. Identify concrete bottlenecks — things that break, degrade, or cost excessively when usage grows 10x-100x.

Return ONLY valid JSON:
{
  "scalabilityScore": <integer 0-100, 100 scales cleanly>,
  "summary": "<2-3 sentences on how this behaves as usage grows>",
  "bottlenecks": [
    {
      "title": "<specific problem>",
      "risk": "<critical|high|medium|low>",
      "area": "<database|api|memory|storage|concurrency|architecture>",
      "explanation": "<what the code does>",
      "impact": "<what happens under load, e.g. 'At ~10k rows this loads the whole table per request'>",
      "recommendation": "<specific fix>",
      "file": "<path or empty>", "line": <int or null>
    }
  ]
}

Look for: unpaginated queries over growing tables; N+1 patterns; in-memory state (sessions, caches, rate limits, queues) that breaks across instances or restarts; synchronous/blocking work in request handlers; sequential awaits that could be parallel; loading whole files/datasets into memory; local-disk storage that fails on multiple instances; missing connection pooling; missing rate limits on expensive endpoints; per-request external calls without caching; single-process assumptions; unbounded array growth.

Report ONLY issues evidenced in the provided code — never speculate about code you cannot see. If it scales well, return a high score and few bottlenecks. Sort by risk. Limit 12.
Score: start 100, deduct critical -20, high -12, medium -6, low -2, min 0.`

const MANIFESTS = ['package.json', 'requirements.txt', 'go.mod', 'Cargo.toml', 'pom.xml', 'composer.json', 'Gemfile']

export async function analyzeScalability(rootPath: string): Promise<ScalabilityAssessment> {
  const picked = await pickLoadBearingFiles(rootPath)
  if (!picked.length) throw new Error('No source files found to assess')

  const parts: string[] = []
  let budget = 42_000
  for (const m of MANIFESTS) {
    const p = rootPath + sep + m
    if (existsSync(p)) {
      try {
        const c = readFileSync(p, 'utf-8').slice(0, 2000)
        parts.push(`--- ${m} ---\n${c}`); budget -= c.length
      } catch { /* skip */ }
      break
    }
  }
  for (const f of picked) {
    if (budget <= 3000) break
    let content: string
    try { content = readFileSync(f, 'utf-8') } catch { continue }
    const slice = content.slice(0, Math.min(6000, budget))
    parts.push(`--- ${f.slice(rootPath.length + 1)} ---\n${slice}`)
    budget -= slice.length
  }

  const text = await callClaude(SCALE_PROMPT, `Assess the scalability of this codebase:\n\n${parts.join('\n\n')}`, 4000)
  const parsed = JSON.parse(repairJson(text)) as Partial<ScalabilityAssessment>
  const score = Number(parsed.scalabilityScore)
  return {
    scalabilityScore: Number.isFinite(score) ? Math.max(0, Math.min(100, Math.round(score))) : 50,
    summary: String(parsed.summary ?? ''),
    bottlenecks: (Array.isArray(parsed.bottlenecks) ? parsed.bottlenecks : []).slice(0, 12).map((b: Partial<ScalabilityBottleneck>) => ({
      title: String(b.title ?? 'Bottleneck'),
      risk: (['critical', 'high', 'medium', 'low'].includes(b.risk as string) ? b.risk : 'medium') as ScalabilityBottleneck['risk'],
      area: (['database', 'api', 'memory', 'storage', 'concurrency', 'architecture'].includes(b.area as string) ? b.area : 'architecture') as ScalabilityBottleneck['area'],
      explanation: String(b.explanation ?? ''),
      impact: String(b.impact ?? ''),
      recommendation: String(b.recommendation ?? ''),
      file: typeof b.file === 'string' ? b.file : '',
      line: typeof b.line === 'number' ? b.line : null
    }))
  }
}

// ── Fix generation ──────────────────────────────────────────────────────────

const FIX_PROMPT = `You are a security engineer producing a minimal, safe patch for a single finding.

Return ONLY valid JSON:
{
  "search": "<contiguous snippet copied CHARACTER-FOR-CHARACTER from the file, including exact whitespace. 1-15 lines. Must appear exactly once.>",
  "replace": "<the fixed version of that snippet, matching existing style and indentation>",
  "explanation": "<1-2 sentences: what changed and why it fixes the issue>"
}

Rules: "search" MUST be an exact verbatim substring of the provided file content — no reformatting, no ellipses. Choose a snippet long enough to be unique. Change only what is needed; do not refactor unrelated code. Never remove functionality.`

/** Resolve a finding's file inside the project root, refusing escapes. */
export function resolveFindingFile(rootPath: string, file: string): string {
  // Canonicalize the root too: a symlink anywhere in the path (macOS /var, /tmp,
  // network mounts) would otherwise make a project's own files look external.
  let root: string
  try { root = realpathSync(rootPath) } catch { root = rootPath }
  const candidate = isAbsolute(file) ? file : root + sep + file
  let real: string
  try { real = realpathSync(candidate) } catch { throw new Error(`File not found: ${file}`) }
  if (real !== root && !real.startsWith(root + sep)) throw new Error('File is outside the scanned project')
  if (!statSync(real).isFile()) throw new Error(`Not a file: ${file}`)
  return real
}

export async function generateFix(rootPath: string, finding: AIFinding): Promise<FixPatch> {
  if (!finding.file) throw new Error('Finding has no associated file')
  const target = resolveFindingFile(rootPath, finding.file)
  const content = readFileSync(target, 'utf-8')

  const MAX = 28_000
  let excerpt = content, note = 'Full file content:'
  if (content.length > MAX) {
    const lines = content.split('\n')
    const center = finding.line && finding.line > 0 ? finding.line - 1 : 0
    const start = Math.max(0, center - 80), end = Math.min(lines.length, center + 80)
    excerpt = lines.slice(start, end).join('\n')
    note = `File excerpt (lines ${start + 1}-${end} of ${lines.length}):`
  }
  const rel = target.slice(rootPath.length + 1)
  const base = `Security finding to fix:
Title: ${finding.title}
Severity: ${finding.severity}
File: ${rel}${finding.line !== null ? ` (line ${finding.line})` : ''}
Issue: ${finding.explanation}
Suggested remediation: ${finding.fixSuggestion}

${note}
${excerpt}`

  let feedback = ''
  for (let attempt = 0; attempt < 2; attempt++) {
    const text = await callClaude(FIX_PROMPT, base + feedback, 3000)
    const p = JSON.parse(repairJson(text)) as Partial<FixPatch>
    if (typeof p.search !== 'string' || !p.search || typeof p.replace !== 'string') {
      throw new Error('AI returned an incomplete patch')
    }
    // Only usable if it matches the real file byte-for-byte
    if (content.includes(p.search)) {
      return { file: rel, search: p.search, replace: p.replace, explanation: p.explanation ?? '' }
    }
    feedback = `\n\nYour previous "search" did not match the file exactly. Copy it character-for-character from the content above, including all whitespace.`
  }
  throw new Error('Could not produce an exact patch — the file may have changed since the scan')
}
