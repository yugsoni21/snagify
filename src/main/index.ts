import { app, shell, BrowserWindow, ipcMain, dialog, safeStorage, Menu } from 'electron'
import { join, extname, basename, sep, isAbsolute } from 'path'
import { statSync, existsSync, realpathSync, writeFileSync, readFileSync, unlinkSync, mkdirSync } from 'fs'
import { readdir, stat, realpath } from 'fs/promises'
import type { Dirent } from 'fs'
import { spawn } from 'child_process'
import type { ChildProcess } from 'child_process'
import { createHash, randomUUID } from 'crypto'
import { networkInterfaces, homedir, tmpdir } from 'os'
import Store from 'electron-store'
import { complete, detectProvider, PROVIDERS, testProvider, type ProviderConfig, type ProviderId } from './providers'
import { SUPABASE_URL, SUPABASE_ANON_KEY, supabaseConfigured } from './supabase-config'
import { electronApp, optimizer, is } from '@electron-toolkit/utils'
import { autoUpdater } from 'electron-updater'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const IGNORED_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '.next',
  '.nuxt', '.turbo', '.cache', 'coverage', '__pycache__',
  '.venv', 'venv', '.expo', 'out', '.output', 'Pods', '.gradle'
])

const LANGUAGE_MAP: Record<string, string> = {
  '.ts': 'TypeScript', '.tsx': 'TypeScript',
  '.js': 'JavaScript', '.jsx': 'JavaScript', '.mjs': 'JavaScript', '.cjs': 'JavaScript',
  '.py': 'Python', '.go': 'Go', '.rs': 'Rust',
  '.java': 'Java', '.kt': 'Kotlin', '.kts': 'Kotlin',
  '.swift': 'Swift', '.c': 'C', '.cpp': 'C++', '.cc': 'C++', '.cxx': 'C++',
  '.h': 'C/C++', '.hpp': 'C++', '.cs': 'C#', '.rb': 'Ruby', '.php': 'PHP',
  '.sol': 'Solidity', '.yaml': 'YAML', '.yml': 'YAML', '.json': 'JSON',
  '.toml': 'TOML', '.tf': 'Terraform', '.tfvars': 'Terraform',
  '.sh': 'Shell', '.bash': 'Shell', '.zsh': 'Shell', '.fish': 'Shell',
  '.html': 'HTML', '.htm': 'HTML', '.css': 'CSS', '.scss': 'SCSS',
  '.sass': 'Sass', '.less': 'Less', '.vue': 'Vue', '.svelte': 'Svelte',
  '.dart': 'Dart', '.r': 'R', '.R': 'R', '.lua': 'Lua',
  '.ex': 'Elixir', '.exs': 'Elixir', '.clj': 'Clojure',
  '.scala': 'Scala', '.hs': 'Haskell', '.ml': 'OCaml', '.dockerfile': 'Docker'
}

const LS_STORE_SLUG = 'snagify'

// ---------------------------------------------------------------------------
// Types shared with preload
// ---------------------------------------------------------------------------

export interface TreeNode {
  name: string
  type: 'file' | 'dir'
  children?: TreeNode[]
}

export interface FolderStats {
  fileCount: number
  totalSizeMB: number
  languages: string[]
  filePaths: string[]
  tree: TreeNode[]
}

export interface AIFinding {
  id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  explanation: string
  fixSuggestion: string
  file: string
  line: number | null
  cwe?: string[]
  owasp?: string[]
}

export interface ComplianceIssue {
  regulation: string
  article: string
  description: string
  recommendation: string
}

export interface ScalabilityBottleneck {
  title: string
  risk: 'critical' | 'high' | 'medium' | 'low'
  area: 'database' | 'api' | 'memory' | 'storage' | 'concurrency' | 'architecture'
  explanation: string
  impact: string
  recommendation: string
  file: string
  line: number | null
}

export interface ScalabilityAssessment {
  scalabilityScore: number
  summary: string
  bottlenecks: ScalabilityBottleneck[]
}

export interface AnalysisResult {
  securityScore: number
  summary: string
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: AIFinding[]
  complianceIssues?: ComplianceIssue[]
  suppressedCount?: number
  scalability?: ScalabilityAssessment
}

export interface SuppressedFinding {
  key: string
  title: string
  file: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  date: string
}

export interface OsvFinding {
  package: string
  version: string
  ecosystem: string
  ids: string[]
  aliases: string[]
  cvss: number | null
  summary: string
  fixedVersion: string | null
  file: string
}

export interface ScanComparison {
  fixedCount: number
  newCount: number
  unchangedCount: number
  scoreDelta: number
  prevScore: number
  prevDate: string
}

export interface ScanResult {
  semgrepFindings: unknown[]
  gitleaksFindings: unknown[]
  osvFindings: OsvFinding[]
  error: string | null
  cancelled?: boolean
  analysis?: AnalysisResult
  analysisError?: string
  comparison?: ScanComparison
}

export interface FixPatch {
  file: string
  search: string
  replace: string
  explanation: string
}

export interface ApplyFixResult {
  backupId: string
}

export interface ScanHistoryEntry {
  id: string
  date: string
  folderPath: string
  folderName: string
  securityScore: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: AIFinding[]
  summary: string
  scalability?: ScalabilityAssessment
}

export interface LicenseValidateResult {
  valid: boolean
  customerEmail: string
  error: string | null
}

export interface LicenseStatus {
  activated: boolean
  email: string | null
  keyMasked: string | null
}

export interface AuthSessionInfo {
  signedIn: boolean
  email: string | null
  licensed: boolean
  plan: string | null
}

// ---------------------------------------------------------------------------
// Scan process tracking
// ---------------------------------------------------------------------------

let activeScanProcs: ChildProcess[] = []
let scanAborted = false

// ---------------------------------------------------------------------------
// electron-store (initialized in whenReady)
// ---------------------------------------------------------------------------

type AppStore = { scanHistory: ScanHistoryEntry[]; suppressions: Record<string, SuppressedFinding[]> }
let store: Store<AppStore>

// ---------------------------------------------------------------------------
// Helpers — folder walking
// ---------------------------------------------------------------------------

// Async so a monorepo-sized walk yields to the event loop instead of freezing
// the main process (and every IPC message) until it finishes
async function walkDir(
  dirPath: string, files: string[], sizeAcc: { bytes: number }, limit: number, rootPath: string
): Promise<void> {
  if (files.length >= limit) return
  let safeDir: string
  try { safeDir = await realpath(dirPath) } catch { return }
  // Bounds check — verify we are still inside rootPath before reading
  if (safeDir !== rootPath && !safeDir.startsWith(rootPath + sep)) return
  let entries: Dirent[]
  try { entries = await readdir(safeDir, { withFileTypes: true }) } catch { return }
  for (const entry of entries) {
    if (files.length >= limit) return
    if (IGNORED_DIRS.has(entry.name)) continue
    const safeName = basename(entry.name)
    if (!safeName || safeName === '.' || safeName === '..') continue
    // Use string concat instead of path.join — safeDir is already a canonical absolute path
    const fullPath = safeDir + sep + safeName
    if (entry.isDirectory()) {
      await walkDir(fullPath, files, sizeAcc, limit, rootPath)
    } else if (entry.isFile()) {
      files.push(fullPath)
      try { sizeAcc.bytes += (await stat(fullPath)).size } catch { /* skip */ }
    }
  }
}

async function buildTree(dirPath: string, currentDepth: number, maxDepth: number, rootPath: string): Promise<TreeNode[]> {
  if (currentDepth >= maxDepth) return []
  let safeDir: string
  try { safeDir = await realpath(dirPath) } catch { return [] }
  // Bounds check — stay within rootPath
  if (safeDir !== rootPath && !safeDir.startsWith(rootPath + sep)) return []
  let entries: Dirent[]
  try { entries = await readdir(safeDir, { withFileTypes: true }) } catch { return [] }

  const dirs: TreeNode[] = []
  const files: TreeNode[] = []
  for (const entry of entries) {
    if (IGNORED_DIRS.has(entry.name)) continue
    const safeName = basename(entry.name)
    if (!safeName || safeName === '.' || safeName === '..') continue
    if (entry.isDirectory()) {
      // String concat instead of path.join — safeDir is already a canonical absolute path
      dirs.push({ name: safeName, type: 'dir', children: await buildTree(safeDir + sep + safeName, currentDepth + 1, maxDepth, rootPath) })
    } else if (entry.isFile()) {
      files.push({ name: safeName, type: 'file' })
    }
  }
  dirs.sort((a, b) => a.name.localeCompare(b.name))
  files.sort((a, b) => a.name.localeCompare(b.name))
  return [...dirs, ...files].slice(0, 100)
}

// ---------------------------------------------------------------------------
// Helpers — binary paths (parameter-free — no user input flows into join)
// ---------------------------------------------------------------------------

function getSemgrepPath(): string {
  const plat = process.platform === 'win32' ? 'win' : 'mac'
  const arch = process.arch === 'arm64' ? 'arm64' : 'x64'
  const ext = process.platform === 'win32' ? '.exe' : ''
  const bundled = is.dev
    ? join(__dirname, '../../resources/binaries', plat, arch, 'semgrep' + ext)
    : join(process.resourcesPath, 'binaries', plat, arch, 'semgrep' + ext)
  // Fall back to system semgrep in both dev and production
  if (!existsSync(bundled)) {
    const home = homedir()
    const searchPaths = [
      `${home}/.local/bin/semgrep`,
      '/opt/homebrew/bin/semgrep',
      '/usr/local/bin/semgrep',
      '/usr/bin/semgrep',
      `${home}/.local/pipx/venvs/semgrep/bin/semgrep`,
    ]
    for (const p of searchPaths) {
      if (existsSync(p)) return p
    }
    const { execFileSync } = require('child_process')
    try {
      const found = execFileSync('/usr/bin/which', ['semgrep'], { encoding: 'utf-8' }).trim()
      if (found && existsSync(found)) return found
    } catch { /* not found */ }
    return bundled
  }
  return bundled
}

function getGitleaksPath(): string {
  const plat = process.platform === 'win32' ? 'win' : 'mac'
  const arch = process.arch === 'arm64' ? 'arm64' : 'x64'
  const ext = process.platform === 'win32' ? '.exe' : ''
  const bundled = is.dev
    ? join(__dirname, '../../resources/binaries', plat, arch, 'gitleaks' + ext)
    : join(process.resourcesPath, 'binaries', plat, arch, 'gitleaks' + ext)
  if (is.dev && !existsSync(bundled)) {
    const { execFileSync } = require('child_process')
    try { return execFileSync('which', ['gitleaks'], { encoding: 'utf-8' }).trim() } catch { /* not found */ }
  }
  return bundled
}

function getOsvScannerPath(): string {
  const plat = process.platform === 'win32' ? 'win' : 'mac'
  const arch = process.arch === 'arm64' ? 'arm64' : 'x64'
  const ext = process.platform === 'win32' ? '.exe' : ''
  const bundled = is.dev
    ? join(__dirname, '../../resources/binaries', plat, arch, 'osv-scanner' + ext)
    : join(process.resourcesPath, 'binaries', plat, arch, 'osv-scanner' + ext)
  if (!existsSync(bundled)) {
    const searchPaths = ['/opt/homebrew/bin/osv-scanner', '/usr/local/bin/osv-scanner', '/usr/bin/osv-scanner']
    for (const p of searchPaths) {
      if (existsSync(p)) return p
    }
    const { execFileSync } = require('child_process')
    try {
      const found = execFileSync('/usr/bin/which', ['osv-scanner'], { encoding: 'utf-8' }).trim()
      if (found && existsSync(found)) return found
    } catch { /* not found */ }
  }
  return bundled
}

// ---------------------------------------------------------------------------
// Input validation / sanitization helpers
// ---------------------------------------------------------------------------

function validateFolderPath(p: unknown): string {
  if (typeof p !== 'string' || !p.trim()) throw new Error('Invalid folder path')
  let real: string
  try { real = realpathSync(p.trim()) } catch { throw new Error(`Path not accessible: ${p.trim()}`) }
  if (!statSync(real).isDirectory()) throw new Error(`Not a directory: ${real}`)
  return real
}

function sanitizeFilename(name: unknown): string {
  if (typeof name !== 'string' || !name.trim()) throw new Error('Invalid filename')
  // Strip path separators and only allow safe filename characters
  return name.trim().replace(/[/\\:*?"<>|]/g, '-').replace(/^\.+/, '').slice(0, 255) || 'report.pdf'
}

function validateString(val: unknown, field: string): string {
  if (typeof val !== 'string' || !val.trim()) throw new Error(`Invalid ${field}`)
  return val.trim()
}

// ---------------------------------------------------------------------------
// Helpers — spawn wrapper
// ---------------------------------------------------------------------------

// Spawn a known binary — binary path comes from a parameter-free resolver, never from user input.
function runTool(tool: 'semgrep' | 'gitleaks' | 'osv', args: string[]): Promise<string> {
  // Paths come from getSemgrepPath()/getGitleaksPath()/getOsvScannerPath() — no user input reaches spawn
  const semgrepBin = getSemgrepPath()
  const gitleaksBin = getGitleaksPath()
  const osvBin = getOsvScannerPath()
  const bin = tool === 'semgrep' ? semgrepBin : tool === 'gitleaks' ? gitleaksBin : osvBin
  return new Promise((resolve, reject) => {
    let stdout = ''
    let stderr = ''
    // shell:false + absolute path — no shell expansion, no injection surface
    const proc = tool === 'semgrep'
      ? spawn(semgrepBin, args, { env: process.env, shell: false })
      : tool === 'gitleaks'
        ? spawn(gitleaksBin, args, { env: process.env, shell: false })
        : spawn(osvBin, args, { env: process.env, shell: false })
    activeScanProcs.push(proc)

    proc.stdout?.on('data', (d: Buffer) => { stdout += d.toString() })
    proc.stderr?.on('data', (d: Buffer) => { stderr += d.toString() })

    proc.on('error', (err: NodeJS.ErrnoException) => {
      activeScanProcs = activeScanProcs.filter((p) => p !== proc)
      reject(err.code === 'ENOENT' ? new Error(`BINARY_NOT_FOUND: ${bin}`) : err)
    })

    proc.on('close', (code) => {
      activeScanProcs = activeScanProcs.filter((p) => p !== proc)
      if (code === null) reject(new Error('CANCELLED'))
      else if (code === 0 || code === 1) resolve(stdout)
      // osv-scanner exits 128 when no dependency manifests exist — that's "nothing to scan", not an error
      else if (tool === 'osv' && code === 128) resolve('')
      else reject(new Error(`Process exited with code ${code}${stderr ? `: ${stderr.slice(0, 300)}` : ''}`))
    })
  })
}


// gitleaks `--report-path=-` silently writes nothing on 8.21.x, which makes every
// scan look secret-free. Always report to a temp file and read it back.
async function runGitleaksJson(folderPath: string): Promise<string> {
  const reportPath = join(tmpdir(), `snagify-gitleaks-${randomUUID()}.json`)
  try {
    await runTool('gitleaks', ['detect', '--source', folderPath, '--report-format=json', `--report-path=${reportPath}`, '--no-git', '--exit-code', '0']) // nosemgrep: path-traversal
    try { return readFileSync(reportPath, 'utf-8') } catch { return '' }
  } finally {
    try { if (existsSync(reportPath)) unlinkSync(reportPath) } catch { /* nothing to clean */ }
  }
}

// Flatten osv-scanner's nested JSON into one finding per package+vulnerability group
function flattenOsvResults(raw: string, rootPath: string): OsvFinding[] {
  if (!raw.trim()) return []
  const parsed = JSON.parse(raw) as {
    results?: Array<{
      source?: { path?: string }
      packages?: Array<{
        package?: { name?: string; version?: string; ecosystem?: string }
        groups?: Array<{ ids?: string[]; aliases?: string[]; max_severity?: string }>
        vulnerabilities?: Array<{
          id: string
          summary?: string
          affected?: Array<{ ranges?: Array<{ events?: Array<{ fixed?: string }> }> }>
        }>
      }>
    }>
  }
  const findings: OsvFinding[] = []
  const seen = new Set<string>()
  for (const r of parsed.results ?? []) {
    const sourcePath = r.source?.path ?? ''
    const relFile = sourcePath.startsWith(rootPath) ? sourcePath.slice(rootPath.length).replace(/^[/\\]/, '') : sourcePath
    for (const p of r.packages ?? []) {
      const pkg = p.package?.name ?? 'unknown'
      const version = p.package?.version ?? ''
      for (const g of p.groups ?? []) {
        const ids = g.ids ?? []
        const key = `${pkg}:${version}:${ids.join(',')}`
        if (seen.has(key)) continue
        seen.add(key)
        const vulns = (p.vulnerabilities ?? []).filter(v => ids.includes(v.id))
        const summary = vulns.map(v => v.summary).find(Boolean) ?? 'Known vulnerability'
        let fixedVersion: string | null = null
        for (const v of vulns) for (const a of v.affected ?? []) for (const rg of a.ranges ?? []) for (const e of rg.events ?? []) if (e.fixed) fixedVersion = e.fixed
        const cvssNum = g.max_severity ? Number(g.max_severity) : NaN
        findings.push({
          package: pkg,
          version,
          ecosystem: p.package?.ecosystem ?? '',
          ids,
          aliases: g.aliases ?? ids,
          cvss: Number.isFinite(cvssNum) ? cvssNum : null,
          summary: summary.slice(0, 200),
          fixedVersion,
          file: relFile
        })
      }
    }
  }
  // Highest CVSS first so the most urgent upgrades surface at the top
  findings.sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0))
  return findings
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))

// ---------------------------------------------------------------------------
// Machine ID
// ---------------------------------------------------------------------------

function getMachineId(): string {
  const idPath = join(app.getPath('userData'), 'machine-id.txt')
  if (existsSync(idPath)) {
    const stored = readFileSync(idPath, 'utf-8').trim()
    if (stored) return stored
  }
  let id: string | null = null
  const nets = networkInterfaces()
  for (const ifaces of Object.values(nets)) {
    for (const iface of ifaces ?? []) {
      if (!iface.internal && iface.mac && iface.mac !== '00:00:00:00:00:00') {
        id = createHash('sha256').update(iface.mac).digest('hex').slice(0, 32)
        break
      }
    }
    if (id) break
  }
  if (!id) id = randomUUID().replace(/-/g, '')
  writeFileSync(idPath, id, 'utf-8')
  return id
}

// ---------------------------------------------------------------------------
// License storage
// ---------------------------------------------------------------------------

function getLicensePaths(): { key: string; email: string; instance: string } {
  const base = app.getPath('userData')
  return { key: join(base, 'license-key.bin'), email: join(base, 'license-email.txt'), instance: join(base, 'license-instance.txt') }
}

function maskKey(key: string): string {
  if (key.length <= 8) return '••••••••'
  return key.slice(0, 4) + '-••••-••••-' + key.slice(-4)
}

function saveLicense(key: string, email: string, instanceId: string): void {
  const paths = getLicensePaths()
  writeFileSync(paths.key, safeStorage.encryptString(key))
  writeFileSync(paths.email, email, 'utf-8')
  if (instanceId) writeFileSync(paths.instance, instanceId, 'utf-8')
}

function loadLicense(): { key: string; email: string; instanceId: string } | null {
  const paths = getLicensePaths()
  if (!existsSync(paths.key)) return null
  try {
    const key = safeStorage.decryptString(readFileSync(paths.key))
    const email = existsSync(paths.email) ? readFileSync(paths.email, 'utf-8').trim() : ''
    const instanceId = existsSync(paths.instance) ? readFileSync(paths.instance, 'utf-8').trim() : ''
    return { key, email, instanceId }
  } catch { return null }
}

function deleteLicense(): void {
  for (const p of Object.values(getLicensePaths())) {
    try { if (existsSync(p)) unlinkSync(p) } catch { /* ignore */ }
  }
}

// ---------------------------------------------------------------------------
// Lemon Squeezy API
// ---------------------------------------------------------------------------

async function callLemonSqueezy(endpoint: 'validate' | 'deactivate', body: Record<string, string>): Promise<Response> {
  return fetch(`https://api.lemonsqueezy.com/v1/licenses/${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify(body)
  })
}

async function validateLicenseKey(licenseKey: string): Promise<LicenseValidateResult> {
  const machineId = getMachineId()
  let response: Response
  try {
    response = await callLemonSqueezy('validate', { license_key: licenseKey, instance_name: `Snagify-${machineId}` })
  } catch (err) {
    return { valid: false, customerEmail: '', error: `Network error: ${String(err)}` }
  }

  const data = await response.json() as {
    valid: boolean
    error?: string
    instance?: { id: string; name: string }
    meta?: { customer_email: string }
  }

  if (!data.valid) return { valid: false, customerEmail: '', error: data.error ?? 'License key is not valid.' }

  saveLicense(licenseKey, data.meta?.customer_email ?? '', data.instance?.id ?? '')
  return { valid: true, customerEmail: data.meta?.customer_email ?? '', error: null }
}

// ---------------------------------------------------------------------------
// API key storage
// ---------------------------------------------------------------------------

function getApiKeyPath(): string { return join(app.getPath('userData'), 'api-key.bin') }
function getProviderPath(): string { return join(app.getPath('userData'), 'ai-provider.json') }

export interface ProviderSettings {
  provider: ProviderId
  model?: string
  baseUrl?: string
}

function saveProviderSettings(s: ProviderSettings): void {
  writeFileSync(getProviderPath(), JSON.stringify(s), 'utf-8')
}

function loadProviderSettings(): ProviderSettings {
  try { return JSON.parse(readFileSync(getProviderPath(), 'utf-8')) as ProviderSettings } catch { return { provider: 'anthropic' } }
}

/** Resolve the active provider: stored settings + the encrypted key. */
function resolveProviderConfig(): ProviderConfig | null {
  const settings = loadProviderSettings()
  const key = loadApiKey()
  if (PROVIDERS[settings.provider]?.needsKey && !key) return null
  return { provider: settings.provider, apiKey: key ?? undefined, model: settings.model, baseUrl: settings.baseUrl }
}

function hasAiProvider(): boolean { return resolveProviderConfig() !== null }

function saveApiKeyToStorage(key: string): void {
  writeFileSync(getApiKeyPath(), safeStorage.encryptString(key))
}

function loadApiKey(): string | null {
  const keyPath = getApiKeyPath()
  if (!existsSync(keyPath)) return null
  try { return safeStorage.decryptString(readFileSync(keyPath)) } catch { return null }
}

// ---------------------------------------------------------------------------
// Claude AI analysis
// ---------------------------------------------------------------------------

const SYSTEM_PROMPT = `You are a security and compliance expert analyzing code scan results. Review findings from Semgrep (vulnerability scanner), Gitleaks (secret detector), and OSV (dependency CVE scanner) and produce a structured security analysis.

Return ONLY valid JSON (no markdown, no extra text) in this exact format:
{
  "securityScore": <integer 0-100 where 100 is perfectly secure>,
  "summary": "<2-3 sentence executive summary of the overall security posture>",
  "criticalCount": <integer>,
  "highCount": <integer>,
  "mediumCount": <integer>,
  "lowCount": <integer>,
  "findings": [
    {
      "id": "<unique alphanumeric string>",
      "title": "<concise descriptive title>",
      "severity": "<critical|high|medium|low>",
      "explanation": "<what this issue is and why it is dangerous>",
      "fixSuggestion": "<specific actionable remediation step>",
      "file": "<file path or empty string if unknown>",
      "line": <line number as integer, or null>,
      "cwe": ["<CWE identifiers like CWE-89, max 3, or empty array>"],
      "owasp": ["<OWASP Top 10 category like A03:2021 Injection, max 2, or empty array>"]
    }
  ],
  "complianceIssues": [
    {
      "regulation": "<e.g. GDPR, HIPAA, CCPA, PCI-DSS, SOC2>",
      "article": "<specific article/rule violated, e.g. GDPR Art. 32>",
      "description": "<what the code does that violates this regulation>",
      "recommendation": "<what must be changed to comply>"
    }
  ]
}

For cwe/owasp: when a Semgrep finding includes cwe/owasp metadata, copy those identifiers (normalized, e.g. "CWE-89", "A03:2021 Injection"). Otherwise infer the standard mapping: hardcoded secrets are CWE-798 / A07:2021 Identification and Authentication Failures; vulnerable dependencies are CWE-1395 / A06:2021 Vulnerable and Outdated Components. Use empty arrays if genuinely unmappable.

Severity: critical for secrets/RCE/auth bypass; high for injection/data exposure; medium for misconfig; low for best practices. For dependency CVEs use the CVSS score: critical for CVSS >= 9.0, high for 7.0-8.9, medium for 4.0-6.9, low below 4.0. For dependency findings the title should name the package and CVE (e.g. "tar 6.2.1 — CVE-2026-24842 path traversal") and the fixSuggestion should state the exact upgrade (e.g. "Upgrade tar to >= 7.5.7"). Sort findings by severity. Limit 50. Score: start 100, deduct critical:-20, high:-10, medium:-5, low:-2, min 0.

For complianceIssues: scan findings for patterns that violate data protection and privacy regulations. Flag issues such as: logging or storing PII/personal data without encryption (GDPR Art. 32, HIPAA), missing data deletion mechanisms (GDPR Art. 17), transmitting personal data to third parties without disclosure (GDPR Art. 13/14), storing payment card data insecurely (PCI-DSS), hardcoded credentials or API keys (SOC2 CC6), missing access controls on sensitive data (GDPR Art. 25). Only include complianceIssues that are clearly evidenced by the findings — do not speculate. Return empty array if none found.`

function slimFinding(f: Record<string, unknown>): Record<string, unknown> {
  if (f.RuleID !== undefined) {
    return { RuleID: f.RuleID, Description: f.Description, File: f.File,
      Secret: typeof f.Secret === 'string' ? f.Secret.slice(0, 60) + '…' : f.Secret }
  }
  const extra = f.extra && typeof f.extra === 'object' ? f.extra as Record<string, unknown> : {}
  const metadata = extra.metadata && typeof extra.metadata === 'object' ? extra.metadata as Record<string, unknown> : {}
  return { check_id: f.check_id, path: f.path, line: (f.start as Record<string, unknown>)?.line,
    message: typeof (extra.message ?? f.message) === 'string'
      ? String(extra.message ?? f.message).slice(0, 180)
      : extra.message ?? f.message,
    severity: extra.severity ?? f.severity,
    // Standards metadata — lets the AI map findings to CWE/OWASP accurately
    cwe: Array.isArray(metadata.cwe) ? (metadata.cwe as string[]).slice(0, 3) : undefined,
    owasp: Array.isArray(metadata.owasp) ? (metadata.owasp as string[]).slice(0, 2) : undefined }
}

// Remove duplicate findings — same rule hitting the same file+line
function deduplicateFindings(semgrep: unknown[], gitleaks: unknown[]): { semgrep: unknown[], gitleaks: unknown[] } {
  const sSeen = new Set<string>()
  const gSeen = new Set<string>()
  return {
    semgrep: semgrep.filter(f => {
      const ff = f as Record<string, unknown>
      const key = `${ff.check_id}:${ff.path}:${(ff.start as Record<string, unknown>)?.line}`
      if (sSeen.has(key)) return false
      sSeen.add(key); return true
    }),
    gitleaks: gitleaks.filter(f => {
      const ff = f as Record<string, unknown>
      const key = `${ff.RuleID}:${ff.File}:${ff.StartLine}`
      if (gSeen.has(key)) return false
      gSeen.add(key); return true
    })
  }
}

// Attempt to salvage a truncated JSON response by closing open structures
function repairJson(raw: string): string {
  const start = raw.indexOf('{')
  if (start === -1) throw new Error('No JSON object in response')
  let s = raw.slice(start)
  try { JSON.parse(s); return s } catch { /* needs repair */ }

  // Walk the string tracking depth; stop at last valid closing brace
  const stack: string[] = []
  let inStr = false, esc = false, lastDepthZero = -1
  for (let i = 0; i < s.length; i++) {
    const c = s[i]
    if (esc) { esc = false; continue }
    if (c === '\\' && inStr) { esc = true; continue }
    if (c === '"') { inStr = !inStr; continue }
    if (inStr) continue
    if (c === '{' || c === '[') stack.push(c === '{' ? '}' : ']')
    else if (c === '}' || c === ']') {
      if (stack.length && stack[stack.length - 1] === c) stack.pop()
      if (stack.length === 0) { lastDepthZero = i; break }
    }
  }
  if (lastDepthZero > 0) {
    const candidate = s.slice(0, lastDepthZero + 1)
    try { JSON.parse(candidate); return candidate } catch { /* still broken */ }
  }

  // Close any open structures (truncated response)
  s = s.trimEnd().replace(/,\s*$/, '')  // remove trailing comma
  const closing = [...stack].reverse().join('')
  const repaired = s + closing
  JSON.parse(repaired)  // throws if still broken
  return repaired
}


/** Single entry point for all AI calls in the app — routes to the chosen provider. */
async function aiComplete(system: string, user: string, maxTokens: number): Promise<string> {
  const cfg = resolveProviderConfig()
  if (!cfg) throw new Error('NO_API_KEY')
  return complete(cfg, { system, user, maxTokens, json: true })
}

async function callClaudeOnce(_apiKey: string, semgrep: unknown[], gitleaks: unknown[], osv: OsvFinding[], batchLabel: string): Promise<AnalysisResult> {
  const slimOsv = osv.map(f => ({
    package: f.package, version: f.version, ecosystem: f.ecosystem,
    cve: f.aliases.find(a => a.startsWith('CVE-')) ?? f.ids[0],
    cvss: f.cvss, summary: f.summary.slice(0, 150), fixedVersion: f.fixedVersion, file: f.file
  }))
  const userPrompt = `Analyze these security scan results${batchLabel}:\n\nSemgrep findings:\n${JSON.stringify(semgrep.map(f => slimFinding(f as Record<string, unknown>)))}\n\nGitleaks findings:\n${JSON.stringify(gitleaks.map(f => slimFinding(f as Record<string, unknown>)))}\n\nOSV dependency vulnerabilities:\n${JSON.stringify(slimOsv)}`
  const rawText = await aiComplete(SYSTEM_PROMPT, userPrompt, 8000)
  try {
    return JSON.parse(repairJson(rawText)) as AnalysisResult
  } catch {
    throw new Error(`Could not parse the AI response as JSON: ${rawText.slice(0, 120)}`)
  }
}

function mergeAnalysisResults(results: AnalysisResult[]): AnalysisResult {
  const allFindings = results.flatMap(r => r.findings)
  const seenCompliance = new Set<string>()
  const complianceIssues = results.flatMap(r => r.complianceIssues ?? []).filter(c => {
    const key = `${c.regulation}:${c.article}`
    if (seenCompliance.has(key)) return false
    seenCompliance.add(key); return true
  })
  const criticalCount = allFindings.filter(f => f.severity === 'critical').length
  const highCount     = allFindings.filter(f => f.severity === 'high').length
  const mediumCount   = allFindings.filter(f => f.severity === 'medium').length
  const lowCount      = allFindings.filter(f => f.severity === 'low').length
  // Use first batch score for single-batch; recalculated by summary pass for multi-batch
  const securityScore = results.length === 1
    ? results[0].securityScore
    : Math.max(0, 100 - criticalCount * 20 - highCount * 10 - mediumCount * 5 - lowCount * 2)
  return { securityScore, summary: results[0].summary, criticalCount, highCount, mediumCount, lowCount, findings: allFindings, complianceIssues }
}

async function refineSummaryAndScore(apiKey: string, merged: AnalysisResult): Promise<AnalysisResult> {
  const sample = merged.findings.slice(0, 12).map(f => `[${f.severity.toUpperCase()}] ${f.title}`).join('\n')
  const prompt = `Security scan results for a codebase:
Critical: ${merged.criticalCount} | High: ${merged.highCount} | Medium: ${merged.mediumCount} | Low: ${merged.lowCount}

Most severe findings:
${sample}

Give a realistic security score (0–100, where 100 = no issues, 0 = completely compromised) and a 2-3 sentence executive summary. Use professional judgment — don't mechanically deduct per finding, consider exploitability and real-world impact.

Return ONLY valid JSON: {"securityScore":<int>,"summary":"<text>"}`

  try {
    const text = await aiComplete('You are a security expert. Return only valid JSON, no markdown.', prompt, 512)
    const parsed = JSON.parse(repairJson(text)) as { securityScore: number; summary: string }
    return { ...merged, securityScore: parsed.securityScore, summary: parsed.summary }
  } catch { /* keep the merged result */ }
  return merged  // fall back to merged result if summary pass fails
}

// Run up to `concurrency` async tasks at a time, preserving result order
async function runWithConcurrency<T>(tasks: (() => Promise<T>)[], concurrency: number): Promise<T[]> {
  const results: T[] = new Array(tasks.length)
  let next = 0
  async function worker() {
    while (next < tasks.length) {
      const i = next++
      results[i] = await tasks[i]()
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, tasks.length) }, worker))
  return results
}

async function analyzeWithClaude(semgrepFindings: unknown[], gitleaksFindings: unknown[], osvFindings: OsvFinding[] = []): Promise<AnalysisResult> {
  if (!hasAiProvider()) throw new Error('NO_API_KEY')

  // 1. Deduplicate — removes same rule hitting the same line twice
  const { semgrep: dedupSemgrep, gitleaks: dedupGitleaks } = deduplicateFindings(semgrepFindings, gitleaksFindings)

  // 2. Split into batches — smaller batches = shorter outputs = no truncation
  const S_BATCH = 10
  const G_BATCH = 5
  const O_BATCH = 12
  const totalBatches = Math.max(
    Math.ceil(dedupSemgrep.length / S_BATCH),
    Math.ceil(dedupGitleaks.length / G_BATCH),
    Math.ceil(osvFindings.length / O_BATCH),
    1
  )

  const tasks = Array.from({ length: totalBatches }, (_, i) => () => {
    const sBatch = dedupSemgrep.slice(i * S_BATCH, (i + 1) * S_BATCH)
    const gBatch = dedupGitleaks.slice(i * G_BATCH, (i + 1) * G_BATCH)
    const oBatch = osvFindings.slice(i * O_BATCH, (i + 1) * O_BATCH)
    const label = totalBatches > 1 ? ` (batch ${i + 1} of ${totalBatches})` : ''
    return callClaudeOnce(apiKey, sBatch, gBatch, oBatch, label)
  })

  // 3. Run 2 batches at a time — faster than sequential, safe under 30K TPM limit
  const results = await runWithConcurrency(tasks, 2)
  const merged = mergeAnalysisResults(results)

  // 4. Single fast summary pass to get a holistic score and executive summary
  if (totalBatches > 1) return refineSummaryAndScore(apiKey, merged)
  return merged
}

// ---------------------------------------------------------------------------
// AI patch generation + apply/revert
// ---------------------------------------------------------------------------

const FIX_SYSTEM_PROMPT = `You are a security engineer producing a minimal, safe code patch for a single security finding.

Return ONLY valid JSON (no markdown, no extra text) in this exact format:
{
  "search": "<a contiguous snippet copied CHARACTER-FOR-CHARACTER from the provided file content, including exact whitespace and indentation. 1-15 lines. Must appear exactly once in the file.>",
  "replace": "<the fixed version of that snippet, matching the file's existing style and indentation>",
  "explanation": "<1-2 sentences: what the patch changes and why it fixes the issue>"
}

Rules:
- "search" MUST be an exact verbatim substring of the file content you were given. Do not reformat, do not add or remove whitespace, do not abbreviate with ellipses.
- Choose a snippet long enough to be unique in the file.
- Keep the patch minimal — change only what is needed to fix the finding. Do not refactor unrelated code.
- Never remove functionality; prefer the smallest secure equivalent.
- If the vulnerable code cannot be safely patched without more context, still produce your best minimal patch.`

// Resolve a finding's file path against the scanned root, enforcing bounds
function resolveFindingFile(rootPath: string, file: string): string {
  // Canonicalize the root too: a symlink anywhere in the path (macOS /var, /tmp,
  // network mounts) would otherwise make a project's own files look external.
  let root: string
  try { root = realpathSync(rootPath) } catch { root = rootPath }
  const candidate = isAbsolute(file) ? file : root + sep + file
  let real: string
  try { real = realpathSync(candidate) } catch { throw new Error(`File not found: ${file}`) }
  if (real !== root && !real.startsWith(root + sep)) throw new Error('File is outside the scanned folder')
  if (!statSync(real).isFile()) throw new Error(`Not a file: ${file}`)
  return real
}

// If the file is large, send only a window around the finding line
function buildFileExcerpt(content: string, line: number | null): { excerpt: string; note: string } {
  const MAX_CHARS = 28000
  if (content.length <= MAX_CHARS) return { excerpt: content, note: 'Full file content:' }
  const lines = content.split('\n')
  const center = line && line > 0 ? line - 1 : 0
  const start = Math.max(0, center - 80)
  const end = Math.min(lines.length, center + 80)
  return {
    excerpt: lines.slice(start, end).join('\n'),
    note: `File excerpt (lines ${start + 1}-${end} of ${lines.length}):`
  }
}

async function generateFixWithClaude(rootPath: string, finding: AIFinding): Promise<FixPatch> {
  if (!hasAiProvider()) throw new Error('NO_API_KEY')
  if (!finding.file) throw new Error('This finding has no file associated with it')

  const targetPath = resolveFindingFile(rootPath, finding.file)
  const content = readFileSync(targetPath, 'utf-8')
  const { excerpt, note } = buildFileExcerpt(content, finding.line)
  const relFile = targetPath.startsWith(rootPath) ? targetPath.slice(rootPath.length).replace(/^[/\\]/, '') : targetPath

  const basePrompt = `Security finding to fix:
Title: ${finding.title}
Severity: ${finding.severity}
File: ${relFile}${finding.line !== null ? ` (line ${finding.line})` : ''}
Issue: ${finding.explanation}
Suggested remediation: ${finding.fixSuggestion}

${note}
${excerpt}`

  let feedback = ''
  for (let attempt = 0; attempt < 2; attempt++) {
    const text = await aiComplete(FIX_SYSTEM_PROMPT, basePrompt + feedback, 3000)
    const parsed = JSON.parse(repairJson(text)) as { search?: string; replace?: string; explanation?: string }
    if (typeof parsed.search !== 'string' || typeof parsed.replace !== 'string' || !parsed.search) {
      throw new Error('AI returned an incomplete patch')
    }
    // Only usable if "search" matches the real file verbatim
    if (content.includes(parsed.search)) {
      return { file: relFile, search: parsed.search, replace: parsed.replace, explanation: parsed.explanation ?? '' }
    }
    feedback = `\n\nYour previous "search" snippet did not match the file content exactly. Copy the snippet character-for-character from the file content above, including all whitespace.`
  }
  throw new Error('AI could not produce an exact patch for this file — the code may have changed since the scan')
}

function getFixBackupDir(): string {
  const dir = join(app.getPath('userData'), 'fix-backups')
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
  return dir
}

function applyFixToFile(rootPath: string, patch: FixPatch): ApplyFixResult {
  const targetPath = resolveFindingFile(rootPath, patch.file)
  const content = readFileSync(targetPath, 'utf-8')
  const idx = content.indexOf(patch.search)
  if (idx === -1) throw new Error('Patch no longer matches the file — it may have been edited since the patch was generated')

  const backupId = randomUUID()
  writeFileSync(join(getFixBackupDir(), `${backupId}.json`), JSON.stringify({ filePath: targetPath, original: content }), 'utf-8')

  const newContent = content.slice(0, idx) + patch.replace + content.slice(idx + patch.search.length)
  writeFileSync(targetPath, newContent, 'utf-8')
  return { backupId }
}

function revertFix(backupId: string): void {
  // Strict UUID shape — hex and hyphens only, so no dots or separators can reach the path
  if (!/^[0-9a-f-]{36}$/i.test(backupId)) throw new Error('Invalid backup id')
  const backupPath = getFixBackupDir() + sep + backupId + '.json'
  if (!existsSync(backupPath)) throw new Error('Backup not found — cannot undo')
  const { filePath, original } = JSON.parse(readFileSync(backupPath, 'utf-8')) as { filePath: string; original: string }
  writeFileSync(filePath, original, 'utf-8')
  unlinkSync(backupPath)
}

// ---------------------------------------------------------------------------
// Scalability analysis — reads load-bearing source files and asks Claude
// what breaks under 10x-100x usage growth
// ---------------------------------------------------------------------------

const SCALABILITY_PROMPT = `You are a scalability and reliability engineer reviewing application source code. Identify concrete bottlenecks — things that will break, degrade, or cost excessively when usage grows 10x-100x (more users, more traffic, more data).

Return ONLY valid JSON (no markdown, no extra text) in this exact format:
{
  "scalabilityScore": <integer 0-100 where 100 means the code scales cleanly>,
  "summary": "<2-3 sentence assessment of how this codebase behaves as usage grows>",
  "bottlenecks": [
    {
      "title": "<concise title naming the specific problem>",
      "risk": "<critical|high|medium|low>",
      "area": "<database|api|memory|storage|concurrency|architecture>",
      "explanation": "<what the code currently does>",
      "impact": "<what concretely happens under load, e.g. 'At ~10k rows this query loads the entire table into memory per request'>",
      "recommendation": "<specific fix, e.g. 'Add pagination with LIMIT/OFFSET or cursor-based paging'>",
      "file": "<file path from the provided sources, or empty string>",
      "line": <integer or null>
    }
  ]
}

Look for evidence of: unpaginated queries or findAll over growing tables; N+1 query patterns; in-memory state (sessions, caches, rate limits, queues) that breaks with multiple instances or restarts; synchronous/blocking work inside request handlers; sequential awaits that could run in parallel; loading entire files or datasets into memory; local-disk file storage that fails on multiple instances; missing connection pooling; missing rate limiting on expensive endpoints; per-request external API calls without caching or batching; single-process assumptions (SQLite writes, in-process cron); unbounded array growth.

Rules: report ONLY issues evidenced in the provided code — never speculate about code you cannot see. If the code genuinely scales well, return a high score and few or no bottlenecks. Risk reflects how soon and how hard it fails as usage grows. Sort by risk. Limit 12. Score: start 100, deduct critical:-20, high:-12, medium:-6, low:-2, min 0.`

const SCALE_EXTS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.go', '.rb', '.php', '.java', '.cs', '.rs'])
const SCALE_HINTS = /(server|api|route|controller|service|handler|middleware|db|database|model|schema|query|repo|dao|queue|worker|job|cache|store|socket|index|app|main)/i
const SCALE_MANIFESTS = ['package.json', 'requirements.txt', 'go.mod', 'Cargo.toml', 'pom.xml', 'composer.json', 'Gemfile']

// Rank source files by how likely they are to contain load-bearing logic
async function pickScalabilityFiles(rootPath: string): Promise<string[]> {
  const files: string[] = []
  const sizeAcc = { bytes: 0 }
  await walkDir(rootPath, files, sizeAcc, 20_000, rootPath)
  const scored: Array<{ path: string; score: number }> = []
  for (const f of files) {
    if (!SCALE_EXTS.has(extname(f).toLowerCase())) continue
    const rel = f.slice(rootPath.length + 1)
    const depth = rel.split(sep).length
    let score = 0
    if (SCALE_HINTS.test(basename(f))) score += 3
    else if (SCALE_HINTS.test(rel)) score += 1
    score += Math.max(0, 3 - depth)  // shallow files are usually entry points
    try { if ((await stat(f)).size > 200_000) score -= 5 } catch { score -= 5 }  // skip bundles/generated
    scored.push({ path: f, score })
  }
  scored.sort((a, b) => b.score - a.score)
  return scored.slice(0, 12).map(s => s.path)
}

async function analyzeScalability(rootPath: string): Promise<ScalabilityAssessment> {
  if (!hasAiProvider()) throw new Error('NO_API_KEY')

  const picked = await pickScalabilityFiles(rootPath)
  if (picked.length === 0) throw new Error('No source files found for scalability analysis')

  const parts: string[] = []
  let budget = 42_000  // chars — keeps the request well under rate limits

  // Manifests give the AI framework/runtime context cheaply
  for (const m of SCALE_MANIFESTS) {
    const p = rootPath + sep + m
    if (existsSync(p)) {
      try { parts.push(`--- ${m} ---\n${readFileSync(p, 'utf-8').slice(0, 2000)}`) ; budget -= 2000 } catch { /* skip */ }
      break
    }
  }

  for (const f of picked) {
    if (budget <= 3000) break
    let content: string
    try { content = readFileSync(f, 'utf-8') } catch { continue }
    const slice = content.slice(0, Math.min(6000, budget))
    const rel = f.slice(rootPath.length + 1)
    parts.push(`--- ${rel} ---\n${slice}`)
    budget -= slice.length
  }

  const text = await aiComplete(SCALABILITY_PROMPT, `Assess the scalability of this codebase:\n\n${parts.join('\n\n')}`, 4000)
  const parsed = JSON.parse(repairJson(text)) as ScalabilityAssessment
  const score = Number(parsed.scalabilityScore)
  return {
    scalabilityScore: Number.isFinite(score) ? Math.max(0, Math.min(100, Math.round(score))) : 50,
    summary: typeof parsed.summary === 'string' ? parsed.summary : '',
    bottlenecks: (Array.isArray(parsed.bottlenecks) ? parsed.bottlenecks : []).slice(0, 12).map(b => ({
      title: String(b.title ?? 'Bottleneck'),
      risk: (['critical', 'high', 'medium', 'low'].includes(b.risk) ? b.risk : 'medium') as ScalabilityBottleneck['risk'],
      area: (['database', 'api', 'memory', 'storage', 'concurrency', 'architecture'].includes(b.area) ? b.area : 'architecture') as ScalabilityBottleneck['area'],
      explanation: String(b.explanation ?? ''),
      impact: String(b.impact ?? ''),
      recommendation: String(b.recommendation ?? ''),
      file: typeof b.file === 'string' ? b.file : '',
      line: typeof b.line === 'number' ? b.line : null
    }))
  }
}

// ---------------------------------------------------------------------------
// History helpers
// ---------------------------------------------------------------------------

// History is split: a lightweight index lives in electron-store (loaded often),
// while the heavy per-scan payload (findings + scalability) lives in its own
// JSON file read only when a specific scan is opened. Keeps history reads O(1)
// in scan size instead of deserializing every finding of every scan.

function getScanPayloadDir(): string {
  const dir = join(app.getPath('userData'), 'scan-payloads')
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
  return dir
}

// id is always a randomUUID we generated — never renderer input directly
function scanPayloadPath(id: string): string {
  return getScanPayloadDir() + sep + id + '.json'
}

function loadFullHistoryEntry(meta: ScanHistoryEntry): ScanHistoryEntry {
  try {
    const payload = JSON.parse(readFileSync(scanPayloadPath(meta.id), 'utf-8')) as {
      findings?: AIFinding[]; scalability?: ScalabilityAssessment
    }
    return { ...meta, findings: payload.findings ?? [], scalability: payload.scalability }
  } catch {
    return meta  // payload missing (pre-migration entry or deleted file) — metadata still renders
  }
}

function saveToHistory(entry: ScanHistoryEntry): void {
  try {
    writeFileSync(scanPayloadPath(entry.id), JSON.stringify({ findings: entry.findings, scalability: entry.scalability }), 'utf-8')
  } catch { /* payload write failed — index entry still saved below */ }
  const meta: ScanHistoryEntry = { ...entry, findings: [], scalability: undefined }
  const all = [meta, ...store.get('scanHistory')]
  // Delete payload files of entries falling off the 50-entry cap
  for (const dropped of all.slice(50)) {
    try { unlinkSync(scanPayloadPath(dropped.id)) } catch { /* already gone */ }
  }
  store.set('scanHistory', all.slice(0, 50))
}

// One-time migration: strip inline findings from pre-split history entries
function migrateHistoryStorage(): void {
  try {
    const list = store.get('scanHistory')
    let changed = false
    for (const e of list) {
      if ((e.findings?.length ?? 0) > 0 || e.scalability) {
        writeFileSync(scanPayloadPath(e.id), JSON.stringify({ findings: e.findings, scalability: e.scalability }), 'utf-8')
        e.findings = []
        delete e.scalability
        changed = true
      }
    }
    if (changed) store.set('scanHistory', list)
  } catch { /* leave legacy storage as-is */ }
}

// Stable identity for a finding across scans — line numbers shift, so key on file + title
function findingKey(f: AIFinding): string {
  return `${f.file}|${f.title.toLowerCase().trim()}`
}

// ---------------------------------------------------------------------------
// Suppressions (per-project ignored findings)
// ---------------------------------------------------------------------------

function getSuppressions(folderPath: string): SuppressedFinding[] {
  return store.get('suppressions')[folderPath] ?? []
}

function setSuppressions(folderPath: string, list: SuppressedFinding[]): void {
  const all = { ...store.get('suppressions') }
  if (list.length === 0) delete all[folderPath]
  else all[folderPath] = list
  store.set('suppressions', all)
}

const SEVERITY_DEDUCTION: Record<AIFinding['severity'], number> = { critical: 20, high: 10, medium: 5, low: 2 }

// Remove suppressed findings from an analysis and recompute counts + score
function applySuppressions(folderPath: string, analysis: AnalysisResult): AnalysisResult {
  const suppressed = getSuppressions(folderPath)
  if (suppressed.length === 0) return analysis
  const suppressedKeys = new Set(suppressed.map(s => s.key))
  const kept = analysis.findings.filter(f => !suppressedKeys.has(findingKey(f)))
  const removedCount = analysis.findings.length - kept.length
  if (removedCount === 0) return analysis
  // Same scoring formula the AI is instructed to use: start 100, deduct per severity
  const score = Math.max(0, 100 - kept.reduce((acc, f) => acc + (SEVERITY_DEDUCTION[f.severity] ?? 2), 0))
  return {
    ...analysis,
    findings: kept,
    securityScore: score,
    criticalCount: kept.filter(f => f.severity === 'critical').length,
    highCount: kept.filter(f => f.severity === 'high').length,
    mediumCount: kept.filter(f => f.severity === 'medium').length,
    lowCount: kept.filter(f => f.severity === 'low').length,
    suppressedCount: removedCount
  }
}

function compareWithPreviousScan(folderPath: string, analysis: AnalysisResult): ScanComparison | undefined {
  // History is newest-first, so the first match is the most recent scan of this folder
  const prevMeta = store.get('scanHistory').find(e => e.folderPath === folderPath)
  if (!prevMeta) return undefined
  // Index rows carry no findings — pull the payload file to diff against
  const prev = loadFullHistoryEntry(prevMeta)
  const prevKeys = new Set(prev.findings.map(findingKey))
  const currKeys = new Set(analysis.findings.map(findingKey))
  let fixedCount = 0
  for (const k of prevKeys) if (!currKeys.has(k)) fixedCount++
  let newCount = 0
  let unchangedCount = 0
  for (const k of currKeys) {
    if (prevKeys.has(k)) unchangedCount++
    else newCount++
  }
  return {
    fixedCount,
    newCount,
    unchangedCount,
    scoreDelta: analysis.securityScore - prev.securityScore,
    prevScore: prev.securityScore,
    prevDate: prev.date
  }
}

// ---------------------------------------------------------------------------
// App menu (keyboard shortcuts → renderer navigation)
// ---------------------------------------------------------------------------

function buildAppMenu(mainWindow: BrowserWindow): void {
  const send = (page: string) => (): void => {
    if (!mainWindow.isDestroyed()) mainWindow.webContents.send('navigate-to', page)
  }
  const isMac = process.platform === 'darwin'
  const template: Electron.MenuItemConstructorOptions[] = [
    ...(isMac ? [{
      label: app.name,
      submenu: [
        { role: 'about' as const },
        { type: 'separator' as const },
        { role: 'services' as const },
        { type: 'separator' as const },
        { role: 'hide' as const },
        { role: 'hideOthers' as const },
        { role: 'unhide' as const },
        { type: 'separator' as const },
        { role: 'quit' as const }
      ]
    }] : []),
    {
      label: 'Go',
      submenu: [
        { label: 'Dashboard',  accelerator: 'CmdOrCtrl+D', click: send('dashboard') },
        { label: 'New Scan',   accelerator: 'CmdOrCtrl+N', click: send('new-scan') },
        { label: 'History',    accelerator: 'CmdOrCtrl+H', click: send('history') },
        { label: 'Settings',   accelerator: 'CmdOrCtrl+,', click: send('settings') }
      ]
    },
    { role: 'editMenu' as const },
    { role: 'viewMenu' as const },
    ...(isMac ? [{ role: 'windowMenu' as const }] : [])
  ]
  Menu.setApplicationMenu(Menu.buildFromTemplate(template))
}

// ---------------------------------------------------------------------------
// Window
// ---------------------------------------------------------------------------

function createWindow(): void {
  const iconPath = is.dev
    ? join(__dirname, '../../resources/icon.png')
    : join(process.resourcesPath, 'icon.png')

  const mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    show: false,
    autoHideMenuBar: true,
    backgroundColor: '#0a0a0a',
    icon: existsSync(iconPath) ? iconPath : undefined,
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'hidden',
    trafficLightPosition: { x: 16, y: 14 },
    webPreferences: {
      preload: join(__dirname, '../preload/index.js'),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: false   // required for preload Node.js access; renderer is still isolated
    }
  })

  buildAppMenu(mainWindow)

  mainWindow.on('ready-to-show', () => mainWindow.show())
  mainWindow.webContents.setWindowOpenHandler((details) => {
    shell.openExternal(details.url)
    return { action: 'deny' }
  })

  if (is.dev && process.env['ELECTRON_RENDERER_URL']) {
    mainWindow.loadURL(process.env['ELECTRON_RENDERER_URL'])
  } else {
    mainWindow.loadFile(join(__dirname, '../renderer/index.html'))
  }
}

// ---------------------------------------------------------------------------
// Shared scanner post-processing
// ---------------------------------------------------------------------------

// Drop gitleaks hits inside compiled/vendored paths — build artifacts, not source
function filterGitleaksFindings(all: unknown[]): unknown[] {
  const BUILD_DIRS = ['dist-electron', 'dist/', '/dist\\', 'node_modules', '/out/', '\\out\\']
  const BUILD_EXTS = ['.asar', '.pak', '.map', '.min.js']
  return all.filter(f => {
    const filePath: string = ((f as Record<string, unknown>).File as string) ?? ''
    if (BUILD_DIRS.some(d => filePath.includes(d))) return false
    if (BUILD_EXTS.some(e => filePath.endsWith(e))) return false
    return true
  })
}

// Deterministic score when AI analysis is unavailable — same deduction scale as the AI prompt
function heuristicScore(semgrep: unknown[], gitleaks: unknown[], osv: OsvFinding[]): number {
  let deduction = 0
  for (const f of semgrep) {
    const extra = (f as Record<string, unknown>).extra as Record<string, unknown> | undefined
    const sev = String(extra?.severity ?? '').toUpperCase()
    deduction += sev === 'ERROR' ? 10 : sev === 'WARNING' ? 5 : 2
  }
  deduction += gitleaks.length * 20
  for (const f of osv) {
    const c = f.cvss ?? 0
    deduction += c >= 9 ? 20 : c >= 7 ? 10 : c >= 4 ? 5 : 2
  }
  return Math.max(0, 100 - deduction)
}

// ---------------------------------------------------------------------------
// Supabase auth (account login) — REST API, no SDK needed
// ---------------------------------------------------------------------------

interface StoredSession {
  accessToken: string
  refreshToken: string
  email: string
  userId: string
  expiresAt: number  // unix seconds
}

function getSessionPath(): string { return join(app.getPath('userData'), 'supabase-session.bin') }

function saveSession(s: StoredSession): void {
  writeFileSync(getSessionPath(), safeStorage.encryptString(JSON.stringify(s)))
}

function loadSession(): StoredSession | null {
  const p = getSessionPath()
  if (!existsSync(p)) return null
  try { return JSON.parse(safeStorage.decryptString(readFileSync(p))) as StoredSession } catch { return null }
}

function clearSession(): void {
  try { if (existsSync(getSessionPath())) unlinkSync(getSessionPath()) } catch { /* already gone */ }
}

async function supabaseAuthRequest(path: string, body: Record<string, unknown>): Promise<Record<string, unknown>> {
  const res = await fetch(`${SUPABASE_URL}/auth/v1/${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', apikey: SUPABASE_ANON_KEY },
    body: JSON.stringify(body)
  })
  const data = await res.json() as Record<string, unknown>
  if (!res.ok) {
    const msg = (data.msg ?? data.error_description ?? data.message ?? `Auth request failed (${res.status})`) as string
    throw new Error(msg)
  }
  return data
}

function sessionFromAuthResponse(data: Record<string, unknown>): StoredSession {
  const user = data.user as Record<string, unknown> | undefined
  return {
    accessToken: String(data.access_token ?? ''),
    refreshToken: String(data.refresh_token ?? ''),
    email: String(user?.email ?? ''),
    userId: String(user?.id ?? ''),
    expiresAt: typeof data.expires_at === 'number' ? data.expires_at : Math.floor(Date.now() / 1000) + Number(data.expires_in ?? 3600)
  }
}

async function ensureFreshSession(): Promise<StoredSession | null> {
  let session = loadSession()
  if (!session) return null
  // Refresh if the token expires within the next minute
  if (session.expiresAt - Math.floor(Date.now() / 1000) < 60) {
    try {
      const data = await supabaseAuthRequest('token?grant_type=refresh_token', { refresh_token: session.refreshToken })
      session = sessionFromAuthResponse(data)
      saveSession(session)
    } catch {
      clearSession()
      return null
    }
  }
  return session
}

// A user is licensed when they have an active row in the licenses table (RLS scopes rows to the user)
async function fetchLicenseRow(session: StoredSession): Promise<{ licensed: boolean; plan: string | null }> {
  try {
    const res = await fetch(`${SUPABASE_URL}/rest/v1/licenses?select=status,plan&status=eq.active&limit=1`, {
      headers: { apikey: SUPABASE_ANON_KEY, Authorization: `Bearer ${session.accessToken}` }
    })
    if (!res.ok) return { licensed: false, plan: null }
    const rows = await res.json() as Array<{ status: string; plan: string | null }>
    return rows.length > 0 ? { licensed: true, plan: rows[0].plan ?? 'pro' } : { licensed: false, plan: null }
  } catch {
    // Offline — fall back to last-known state stored alongside the session
    return { licensed: false, plan: null }
  }
}

async function getAuthSessionInfo(): Promise<AuthSessionInfo> {
  const session = await ensureFreshSession()
  if (!session) return { signedIn: false, email: null, licensed: false, plan: null }
  const { licensed, plan } = await fetchLicenseRow(session)
  return { signedIn: true, email: session.email, licensed, plan }
}

// ---------------------------------------------------------------------------
// Pre-commit hook install / uninstall
// ---------------------------------------------------------------------------

const HOOK_MARKER = '# snagify-pre-commit-guard'

function hookPathFor(repoPath: string): string {
  const gitDir = repoPath + sep + '.git'
  if (!existsSync(gitDir) || !statSync(gitDir).isDirectory()) {
    throw new Error('Not a git repository — run "git init" first or pick the repo root')
  }
  const hooksDir = gitDir + sep + 'hooks'
  if (!existsSync(hooksDir)) mkdirSync(hooksDir, { recursive: true })
  return hooksDir + sep + 'pre-commit'
}

function isSnagifyHookInstalled(repoPath: string): boolean {
  try {
    const p = hookPathFor(repoPath)
    return existsSync(p) && readFileSync(p, 'utf-8').includes(HOOK_MARKER)
  } catch { return false }
}

function installPreCommitHook(repoPath: string, minScore: number): string {
  const hookPath = hookPathFor(repoPath)
  if (existsSync(hookPath) && !readFileSync(hookPath, 'utf-8').includes(HOOK_MARKER)) {
    throw new Error('A pre-commit hook from another tool already exists — remove it first or chain manually')
  }
  // Packaged builds launch the app from execPath directly; dev needs the app dir argument
  const appArg = app.isPackaged ? '' : ` "${app.getAppPath()}"`
  const script = `#!/bin/sh
${HOOK_MARKER}
# Blocks commits when the Snagify security score falls below ${minScore}.
# Bypass once with: git commit --no-verify
REPO_ROOT="$(git rev-parse --show-toplevel)"
"${process.execPath}"${appArg} --scan "$REPO_ROOT" --no-ai --min-score ${minScore}
STATUS=$?
if [ $STATUS -ne 0 ]; then
  echo ""
  echo "Commit blocked by Snagify security gate (exit $STATUS)."
  echo "Fix the findings, or bypass once with: git commit --no-verify"
  exit 1
fi
exit 0
`
  writeFileSync(hookPath, script, { encoding: 'utf-8', mode: 0o755 })
  return hookPath
}

function uninstallPreCommitHook(repoPath: string): void {
  const hookPath = hookPathFor(repoPath)
  if (!existsSync(hookPath)) return
  if (!readFileSync(hookPath, 'utf-8').includes(HOOK_MARKER)) {
    throw new Error('The existing pre-commit hook was not installed by Snagify — refusing to delete it')
  }
  unlinkSync(hookPath)
}

// ---------------------------------------------------------------------------
// Headless CLI mode — snagify --scan <path> [--json] [--no-ai] [--min-score N]
// ---------------------------------------------------------------------------

function cliArg(flag: string): string | null {
  const idx = process.argv.indexOf(flag)
  return idx !== -1 && idx + 1 < process.argv.length ? process.argv[idx + 1] : null
}

async function runCliScan(): Promise<number> {
  // Progress goes to stderr so --json output on stdout stays machine-readable
  const info = (m: string): void => { process.stderr.write(m + '\n') }
  const out = (m: string): void => { process.stdout.write(m + '\n') }

  const target = cliArg('--scan')
  if (!target) {
    info('Usage: snagify --scan <path> [--json] [--no-ai] [--min-score N]')
    return 2
  }
  if (!loadLicense()) {
    info('Snagify CLI requires an activated license. Open the Snagify app and activate it first.')
    return 3
  }

  let folderPath: string
  try { folderPath = validateFolderPath(target) } catch (e) { info(String(e)); return 2 }

  const wantJson = process.argv.includes('--json')
  const noAi = process.argv.includes('--no-ai')
  const minScoreRaw = cliArg('--min-score')
  const minScore = minScoreRaw !== null ? Number(minScoreRaw) : null
  if (minScore !== null && (!Number.isFinite(minScore) || minScore < 0 || minScore > 100)) {
    info('--min-score must be a number between 0 and 100')
    return 2
  }

  scanAborted = false
  activeScanProcs = []
  const errors: string[] = []

  info(`Scanning ${folderPath}`)

  // Semgrep
  let semgrepFindings: unknown[] = []
  if (existsSync(getSemgrepPath())) {
    info('→ Semgrep (code vulnerabilities)…')
    try {
      const o = await runTool('semgrep', ['--config=auto', '--json', folderPath]) // nosemgrep: path-traversal
      if (o.trim()) semgrepFindings = (JSON.parse(o) as { results?: unknown[] }).results ?? []
    } catch (e) { errors.push('semgrep: ' + String(e)) }
  } else { errors.push('semgrep binary not found — skipped') }

  // Gitleaks
  let gitleaksFindings: unknown[] = []
  if (existsSync(getGitleaksPath())) {
    info('→ Gitleaks (secrets)…')
    try {
      const o = await runGitleaksJson(folderPath)
      if (o.trim()) {
        const parsed = JSON.parse(o) as unknown
        gitleaksFindings = filterGitleaksFindings(Array.isArray(parsed) ? parsed : [])
      }
    } catch (e) { errors.push('gitleaks: ' + String(e)) }
  } else { errors.push('gitleaks binary not found — skipped') }

  // OSV
  let osvFindings: OsvFinding[] = []
  if (existsSync(getOsvScannerPath())) {
    info('→ OSV (dependency CVEs)…')
    try {
      const o = await runTool('osv', ['scan', 'source', '-r', '--format', 'json', folderPath]) // nosemgrep: path-traversal
      osvFindings = flattenOsvResults(o, folderPath)
    } catch (e) { errors.push('osv-scanner: ' + String(e)) }
  } else { errors.push('osv-scanner binary not found — skipped') }

  // AI analysis (optional)
  let analysis: AnalysisResult | undefined
  if (!noAi && loadApiKey()) {
    info('→ AI analysis…')
    try {
      analysis = applySuppressions(folderPath, await analyzeWithClaude(semgrepFindings, gitleaksFindings, osvFindings))
    } catch (e) { errors.push('ai: ' + String(e).replace('Error: ', '')) }
  }

  const score = analysis?.securityScore ?? heuristicScore(semgrepFindings, gitleaksFindings, osvFindings)
  const scoreSource = analysis ? 'ai' : 'heuristic'

  if (wantJson) {
    out(JSON.stringify({
      folderPath,
      score,
      scoreSource,
      codeFindings: semgrepFindings.length,
      secrets: gitleaksFindings.length,
      vulnerableDependencies: osvFindings.length,
      semgrepFindings,
      gitleaksFindings,
      osvFindings,
      analysis: analysis ?? null,
      errors
    }, null, 2))
  } else {
    out('')
    out('Snagify Security Scan')
    out(`Project: ${folderPath}`)
    out('')
    out(`  Code findings           ${semgrepFindings.length}`)
    out(`  Secrets                 ${gitleaksFindings.length}`)
    out(`  Vulnerable dependencies ${osvFindings.length}`)
    out('')
    out(`  Security score          ${score}/100  (${scoreSource === 'ai' ? 'AI analysis' : 'heuristic — run with an API key for AI scoring'})`)
    if (analysis && analysis.findings.length > 0) {
      out('')
      out('  Top findings:')
      for (const f of analysis.findings.slice(0, 10)) {
        out(`   [${f.severity.toUpperCase().padEnd(8)}] ${f.title}${f.file ? `  (${f.file}${f.line !== null ? ':' + f.line : ''})` : ''}`)
      }
      if (analysis.findings.length > 10) out(`   … and ${analysis.findings.length - 10} more`)
    }
    if (errors.length > 0) {
      out('')
      out('  Warnings:')
      for (const e of errors) out(`   - ${e.slice(0, 120)}`)
    }
    out('')
  }

  if (minScore !== null && score < minScore) {
    info(`FAIL: score ${score} is below required minimum ${minScore}`)
    return 1
  }
  if (minScore !== null) info(`PASS: score ${score} meets minimum ${minScore}`)
  return 0
}

// ---------------------------------------------------------------------------
// App lifecycle & IPC handlers
// ---------------------------------------------------------------------------

app.whenReady().then(async () => {
  electronApp.setAppUserModelId('ca.snagify.app')
  app.on('browser-window-created', (_, window) => optimizer.watchWindowShortcuts(window))

  // Initialise store after app is ready
  store = new Store<AppStore>({ name: 'snagify-data', defaults: { scanHistory: [], suppressions: {} } })
  migrateHistoryStorage()

  // Headless CLI mode — no window, results to stdout, exit code for CI gates
  if (process.argv.includes('--scan')) {
    if (process.platform === 'darwin') app.dock?.hide()
    const code = await runCliScan()
    app.exit(code)
    return
  }

  // Hook installer CLI — snagify --install-hook <repo> [--min-score N] / --uninstall-hook <repo>
  if (process.argv.includes('--install-hook') || process.argv.includes('--uninstall-hook')) {
    if (process.platform === 'darwin') app.dock?.hide()
    try {
      if (process.argv.includes('--install-hook')) {
        const repo = validateFolderPath(cliArg('--install-hook'))
        const minRaw = cliArg('--min-score')
        const min = minRaw !== null ? Number(minRaw) : 60
        if (!Number.isFinite(min) || min < 0 || min > 100) throw new Error('--min-score must be 0-100')
        const p = installPreCommitHook(repo, min)
        process.stdout.write(`Pre-commit guard installed: ${p} (min score ${min})\n`)
      } else {
        const repo = validateFolderPath(cliArg('--uninstall-hook'))
        uninstallPreCommitHook(repo)
        process.stdout.write('Pre-commit guard removed.\n')
      }
      app.exit(0)
    } catch (e) {
      process.stderr.write(String(e) + '\n')
      app.exit(2)
    }
    return
  }

  // ── App version ────────────────────────────────────────────────────────────
  ipcMain.handle('get-app-version', (): string => app.getVersion())

  // ── Folder picker ──────────────────────────────────────────────────────────
  ipcMain.handle('select-folder', async () => {
    try {
      const result = await dialog.showOpenDialog({ properties: ['openDirectory'], title: 'Select Project Folder' })
      return !result.canceled && result.filePaths.length > 0 ? result.filePaths[0] : null
    } catch { return null }
  })

  // ── Folder stats ───────────────────────────────────────────────────────────
  ipcMain.handle('get-folder-stats', async (_event, rawPath: unknown): Promise<FolderStats> => {
    const folderPath = validateFolderPath(rawPath)
    const files: string[] = []
    const sizeAcc = { bytes: 0 }
    const rootPath = realpathSync(folderPath)
    await walkDir(rootPath, files, sizeAcc, 50_000, rootPath)
    const langSet = new Set<string>()
    for (const f of files) {
      const lang = LANGUAGE_MAP[extname(f).toLowerCase()]
      if (lang) langSet.add(lang)
    }
    return {
      fileCount: files.length,
      totalSizeMB: Math.round((sizeAcc.bytes / (1024 * 1024)) * 100) / 100,
      languages: Array.from(langSet).sort(),
      filePaths: files,
      tree: await buildTree(rootPath, 0, 2, rootPath)
    }
  })

  // ── License management ─────────────────────────────────────────────────────
  ipcMain.handle('validate-license', async (_event, licenseKey: unknown): Promise<LicenseValidateResult> => {
    try {
      const key = validateString(licenseKey, 'license key')
      return validateLicenseKey(key)
    } catch (err) {
      return { valid: false, customerEmail: '', error: String(err) }
    }
  })

  ipcMain.handle('get-license-status', (): LicenseStatus => {
    try {
      if (is.dev) return { activated: true, email: 'dev@snagify.ca', keyMasked: 'DEV-MODE' }
      const license = loadLicense()
      if (!license) return { activated: false, email: null, keyMasked: null }
      return { activated: true, email: license.email, keyMasked: maskKey(license.key) }
    } catch { return { activated: false, email: null, keyMasked: null } }
  })

  ipcMain.handle('get-machine-id', (): string => {
    try { return getMachineId() } catch { return randomUUID().replace(/-/g, '') }
  })

  ipcMain.handle('deactivate-license', async (): Promise<void> => {
    try {
      const license = loadLicense()
      if (license?.key && license.instanceId) {
        callLemonSqueezy('deactivate', { license_key: license.key, instance_id: license.instanceId }).catch(() => { /* best-effort */ })
      }
      deleteLicense()
    } catch { /* always succeed from user's perspective */ }
  })

  // ── API key management ─────────────────────────────────────────────────────
  ipcMain.handle('save-api-key', (_event, key: unknown) => {
    const trimmed = validateString(key, 'API key')
    saveApiKeyToStorage(trimmed)
  })
  // ── AI provider settings ───────────────────────────────────────────────────
  ipcMain.handle('get-ai-provider', () => {
    const settings = loadProviderSettings()
    const cfg = resolveProviderConfig()
    return {
      provider: settings.provider,
      model: settings.model ?? PROVIDERS[settings.provider].defaultModel,
      baseUrl: settings.baseUrl ?? '',
      configured: cfg !== null,
      needsKey: PROVIDERS[settings.provider].needsKey,
      providers: Object.entries(PROVIDERS).map(([id, spec]) => ({
        id, label: spec.label, needsKey: spec.needsKey, defaultModel: spec.defaultModel, keyUrl: spec.keyUrl ?? ''
      }))
    }
  })

  ipcMain.handle('set-ai-provider', (_e, raw: unknown) => {
    const v = raw as Partial<ProviderSettings>
    const provider = (v?.provider && PROVIDERS[v.provider as ProviderId]) ? v.provider as ProviderId : 'anthropic'
    saveProviderSettings({
      provider,
      model: typeof v?.model === 'string' && v.model.trim() ? v.model.trim() : undefined,
      baseUrl: typeof v?.baseUrl === 'string' && v.baseUrl.trim() ? v.baseUrl.trim() : undefined
    })
  })

  ipcMain.handle('test-ai-provider', async () => {
    const cfg = resolveProviderConfig()
    if (!cfg) return { ok: false, detail: 'No provider configured' }
    return testProvider(cfg)
  })

  ipcMain.handle('detect-provider-from-key', (_e, key: unknown) =>
    typeof key === 'string' ? detectProvider(key) : null)

  ipcMain.handle('get-api-key-status', () => {
    try { return !!loadApiKey() } catch { return false }
  })

  // ── Analyze findings ───────────────────────────────────────────────────────
  ipcMain.handle('analyze-findings', async (_event, semgrepFindings: unknown[], gitleaksFindings: unknown[], osvFindings?: unknown[]) => {
    if (!Array.isArray(semgrepFindings)) semgrepFindings = []
    if (!Array.isArray(gitleaksFindings)) gitleaksFindings = []
    const osv = Array.isArray(osvFindings) ? osvFindings as OsvFinding[] : []
    return analyzeWithClaude(semgrepFindings, gitleaksFindings, osv)
  })

  // ── AI patch generation / apply / revert ───────────────────────────────────
  ipcMain.handle('generate-fix', async (_event, rawFolder: unknown, rawFinding: unknown): Promise<FixPatch> => {
    const rootPath = validateFolderPath(rawFolder)
    const f = rawFinding as Record<string, unknown>
    if (!f || typeof f !== 'object') throw new Error('Invalid finding')
    const finding: AIFinding = {
      id: validateString(f.id, 'finding id'),
      title: validateString(f.title, 'finding title'),
      severity: (['critical', 'high', 'medium', 'low'].includes(f.severity as string) ? f.severity : 'low') as AIFinding['severity'],
      explanation: typeof f.explanation === 'string' ? f.explanation : '',
      fixSuggestion: typeof f.fixSuggestion === 'string' ? f.fixSuggestion : '',
      file: validateString(f.file, 'finding file'),
      line: typeof f.line === 'number' ? f.line : null
    }
    return generateFixWithClaude(rootPath, finding)
  })

  ipcMain.handle('apply-fix', (_event, rawFolder: unknown, rawPatch: unknown): ApplyFixResult => {
    const rootPath = validateFolderPath(rawFolder)
    const p = rawPatch as Record<string, unknown>
    if (!p || typeof p !== 'object') throw new Error('Invalid patch')
    const patch: FixPatch = {
      file: validateString(p.file, 'patch file'),
      search: typeof p.search === 'string' && p.search ? p.search : (() => { throw new Error('Invalid patch search') })(),
      replace: typeof p.replace === 'string' ? p.replace : '',
      explanation: typeof p.explanation === 'string' ? p.explanation : ''
    }
    return applyFixToFile(rootPath, patch)
  })

  ipcMain.handle('revert-fix', (_event, rawBackupId: unknown): void => {
    revertFix(validateString(rawBackupId, 'backup id'))
  })

  // ── Finding suppressions ───────────────────────────────────────────────────
  ipcMain.handle('suppress-finding', (_event, rawFolder: unknown, rawFinding: unknown): SuppressedFinding[] => {
    const folderPath = validateFolderPath(rawFolder)
    const f = rawFinding as Record<string, unknown>
    if (!f || typeof f !== 'object') throw new Error('Invalid finding')
    const finding: AIFinding = {
      id: typeof f.id === 'string' ? f.id : '',
      title: validateString(f.title, 'finding title'),
      severity: (['critical', 'high', 'medium', 'low'].includes(f.severity as string) ? f.severity : 'low') as AIFinding['severity'],
      explanation: '',
      fixSuggestion: '',
      file: typeof f.file === 'string' ? f.file : '',
      line: null
    }
    const key = findingKey(finding)
    const current = getSuppressions(folderPath)
    if (!current.some(s => s.key === key)) {
      setSuppressions(folderPath, [...current, {
        key, title: finding.title, file: finding.file, severity: finding.severity, date: new Date().toISOString()
      }])
    }
    return getSuppressions(folderPath)
  })

  ipcMain.handle('unsuppress-finding', (_event, rawFolder: unknown, rawKey: unknown): SuppressedFinding[] => {
    const folderPath = validateFolderPath(rawFolder)
    const key = validateString(rawKey, 'suppression key')
    setSuppressions(folderPath, getSuppressions(folderPath).filter(s => s.key !== key))
    return getSuppressions(folderPath)
  })

  ipcMain.handle('get-suppressions', (_event, rawFolder: unknown): SuppressedFinding[] => {
    return getSuppressions(validateFolderPath(rawFolder))
  })

  // ── Account auth (Supabase) ────────────────────────────────────────────────
  ipcMain.handle('auth-available', (): boolean => supabaseConfigured())

  ipcMain.handle('auth-sign-up', async (_event, rawEmail: unknown, rawPassword: unknown): Promise<AuthSessionInfo> => {
    if (!supabaseConfigured()) throw new Error('Account login is not configured')
    const email = validateString(rawEmail, 'email')
    const password = validateString(rawPassword, 'password')
    if (password.length < 8) throw new Error('Password must be at least 8 characters')
    const data = await supabaseAuthRequest('signup', { email, password })
    // If email confirmation is enabled there is no session yet
    if (!data.access_token) return { signedIn: false, email, licensed: false, plan: null }
    saveSession(sessionFromAuthResponse(data))
    return getAuthSessionInfo()
  })

  ipcMain.handle('auth-sign-in', async (_event, rawEmail: unknown, rawPassword: unknown): Promise<AuthSessionInfo> => {
    if (!supabaseConfigured()) throw new Error('Account login is not configured')
    const email = validateString(rawEmail, 'email')
    const password = validateString(rawPassword, 'password')
    const data = await supabaseAuthRequest('token?grant_type=password', { email, password })
    saveSession(sessionFromAuthResponse(data))
    return getAuthSessionInfo()
  })

  ipcMain.handle('auth-sign-out', (): void => { clearSession() })

  ipcMain.handle('auth-get-session', async (): Promise<AuthSessionInfo> => {
    if (!supabaseConfigured()) return { signedIn: false, email: null, licensed: false, plan: null }
    return getAuthSessionInfo()
  })

  // ── Pre-commit hook ────────────────────────────────────────────────────────
  ipcMain.handle('get-hook-status', (_event, rawFolder: unknown): boolean => {
    return isSnagifyHookInstalled(validateFolderPath(rawFolder))
  })

  ipcMain.handle('install-hook', (_event, rawFolder: unknown, rawMinScore: unknown): void => {
    const folderPath = validateFolderPath(rawFolder)
    const min = typeof rawMinScore === 'number' && Number.isFinite(rawMinScore) && rawMinScore >= 0 && rawMinScore <= 100 ? rawMinScore : 60
    installPreCommitHook(folderPath, min)
  })

  ipcMain.handle('uninstall-hook', (_event, rawFolder: unknown): void => {
    uninstallPreCommitHook(validateFolderPath(rawFolder))
  })

  // ── Scan history ───────────────────────────────────────────────────────────
  ipcMain.handle('get-scan-history', (): ScanHistoryEntry[] => {
    try { return store.get('scanHistory').slice(0, 20) } catch { return [] }
  })

  ipcMain.handle('get-scan-by-id', (_event, id: unknown): ScanHistoryEntry | null => {
    try {
      const scanId = validateString(id, 'scan id')
      const meta = store.get('scanHistory').find((e) => e.id === scanId)
      // Findings/scalability live in a payload file — loaded only for the opened scan
      return meta ? loadFullHistoryEntry(meta) : null
    } catch { return null }
  })

  ipcMain.handle('delete-scan', (_event, id: unknown): void => {
    try {
      const scanId = validateString(id, 'scan id')
      const meta = store.get('scanHistory').find((e) => e.id === scanId)
      if (meta) { try { unlinkSync(scanPayloadPath(meta.id)) } catch { /* already gone */ } }
      store.set('scanHistory', store.get('scanHistory').filter((e) => e.id !== scanId))
    } catch { /* ignore */ }
  })

  // ── Save PDF report to Downloads ────────────────────────────────────────────
  ipcMain.handle('save-pdf-report', (_event, rawFilename: unknown, data: unknown): string => {
    const filename = sanitizeFilename(rawFilename)
    if (typeof data !== 'object' || data === null) throw new Error('Invalid PDF data')
    const downloadsPath = app.getPath('downloads')
    const filePath = join(downloadsPath, filename)
    writeFileSync(filePath, Buffer.from(data as ArrayBuffer))
    return filePath
  })

  // ── Cancel active scan ─────────────────────────────────────────────────────
  ipcMain.handle('cancel-scan', () => {
    scanAborted = true
    for (const p of activeScanProcs) { try { p.kill('SIGTERM') } catch { /* already dead */ } }
    activeScanProcs = []
  })

  // ── Run scan ───────────────────────────────────────────────────────────────
  ipcMain.handle('run-scan', async (event, rawPath: unknown): Promise<ScanResult> => {
    let folderPath: string
    try { folderPath = validateFolderPath(rawPath) }
    catch (err) { return { semgrepFindings: [], gitleaksFindings: [], osvFindings: [], error: String(err) } }

    scanAborted = false
    activeScanProcs = []

    const sender = event.sender
    const progress = (step: string, message: string): void => {
      if (!sender.isDestroyed()) sender.send('scan-progress', { step, message })
    }

    progress('init', 'Preparing scan environment…')
    await sleep(400)
    if (scanAborted) { progress('cancelled', 'Scan cancelled'); return { semgrepFindings: [], gitleaksFindings: [], osvFindings: [], error: null, cancelled: true } }

    // Semgrep
    progress('semgrep', 'Running security scan…')
    let semgrepFindings: unknown[] = []
    let semgrepError: string | null = null

    const semgrepBin = getSemgrepPath()
    if (!existsSync(semgrepBin)) {
      semgrepError = `Semgrep binary not found at:\n${semgrepBin}\n\nAdd it to resources/binaries/`
      progress('semgrep-skip', 'Semgrep not installed — skipping')
      await sleep(300)
    } else {
      try {
        const out = await runTool('semgrep', ['--config=auto', '--json', folderPath]) // nosemgrep: path-traversal
        if (out.trim()) {
          const parsed = JSON.parse(out) as { results?: unknown[] }
          semgrepFindings = parsed.results ?? []
        }
        progress('semgrep', `Found ${semgrepFindings.length} finding${semgrepFindings.length !== 1 ? 's' : ''}`)
      } catch (err) {
        const msg = String(err)
        if (msg.includes('CANCELLED')) { progress('cancelled', 'Scan cancelled'); return { semgrepFindings: [], gitleaksFindings: [], osvFindings: [], error: null, cancelled: true } }
        semgrepError = msg.replace('Error: ', '')
        progress('semgrep-error', `Semgrep error: ${semgrepError.slice(0, 80)}`)
        await sleep(300)
      }
    }

    if (scanAborted) { progress('cancelled', 'Scan cancelled'); return { semgrepFindings: [], gitleaksFindings: [], osvFindings: [], error: null, cancelled: true } }

    // Gitleaks
    progress('gitleaks', 'Detecting secrets and credentials…')
    let gitleaksFindings: unknown[] = []
    let gitleaksError: string | null = null

    const gitleaksBin = getGitleaksPath()
    if (!existsSync(gitleaksBin)) {
      gitleaksError = `Gitleaks binary not found at:\n${gitleaksBin}\n\nAdd it to resources/binaries/`
      progress('gitleaks-skip', 'Gitleaks not installed — skipping')
      await sleep(300)
    } else {
      try {
        const out = await runGitleaksJson(folderPath)
        if (out.trim()) {
          const parsed = JSON.parse(out) as unknown
          gitleaksFindings = filterGitleaksFindings(Array.isArray(parsed) ? parsed : [])
        }
        progress('gitleaks', `Found ${gitleaksFindings.length} secret${gitleaksFindings.length !== 1 ? 's' : ''}`)
      } catch (err) {
        const msg = String(err)
        if (msg.includes('CANCELLED')) { progress('cancelled', 'Scan cancelled'); return { semgrepFindings: [], gitleaksFindings: [], osvFindings: [], error: null, cancelled: true } }
        gitleaksError = msg.replace('Error: ', '')
        progress('gitleaks-error', `Gitleaks error: ${gitleaksError.slice(0, 80)}`)
        await sleep(300)
      }
    }

    if (scanAborted) { progress('cancelled', 'Scan cancelled'); return { semgrepFindings: [], gitleaksFindings: [], osvFindings: [], error: null, cancelled: true } }

    // OSV dependency vulnerability scan
    progress('osv', 'Checking dependencies for known CVEs…')
    let osvFindings: OsvFinding[] = []
    let osvError: string | null = null

    const osvBin = getOsvScannerPath()
    if (!existsSync(osvBin)) {
      osvError = `osv-scanner binary not found at:\n${osvBin}\n\nAdd it to resources/binaries/`
      progress('osv-skip', 'osv-scanner not installed — skipping dependency check')
      await sleep(300)
    } else {
      try {
        const out = await runTool('osv', ['scan', 'source', '-r', '--format', 'json', folderPath]) // nosemgrep: path-traversal
        osvFindings = flattenOsvResults(out, folderPath)
        progress('osv', `Found ${osvFindings.length} vulnerable dependenc${osvFindings.length !== 1 ? 'ies' : 'y'}`)
      } catch (err) {
        const msg = String(err)
        if (msg.includes('CANCELLED')) { progress('cancelled', 'Scan cancelled'); return { semgrepFindings: [], gitleaksFindings: [], osvFindings: [], error: null, cancelled: true } }
        osvError = msg.replace('Error: ', '')
        progress('osv-error', `Dependency scan error: ${osvError.slice(0, 80)}`)
        await sleep(300)
      }
    }

    if (scanAborted) { progress('cancelled', 'Scan cancelled'); return { semgrepFindings: [], gitleaksFindings: [], osvFindings: [], error: null, cancelled: true } }

    // AI analysis
    let analysis: AnalysisResult | undefined
    let analysisError: string | undefined

    if (!hasAiProvider()) {
      progress('ai-skip', 'No API key configured — skipping AI analysis')
      await sleep(300)
    } else {
      progress('ai', 'Analyzing findings with AI…')
      try {
        analysis = await analyzeWithClaude(semgrepFindings, gitleaksFindings, osvFindings)
        analysis = applySuppressions(folderPath, analysis)
        progress('ai', `AI analysis complete — security score: ${analysis.securityScore}/100`)
      } catch (err) {
        const msg = String(err)
        if (msg.includes('CANCELLED')) { progress('cancelled', 'Scan cancelled'); return { semgrepFindings: [], gitleaksFindings: [], osvFindings: [], error: null, cancelled: true } }
        analysisError = msg.replace('Error: ', '')
        progress('ai-error', `AI analysis failed: ${analysisError.slice(0, 80)}`)
        await sleep(300)
      }
    }

    if (scanAborted) { progress('cancelled', 'Scan cancelled'); return { semgrepFindings: [], gitleaksFindings: [], osvFindings: [], error: null, cancelled: true } }

    // Scalability analysis — needs the AI key; non-fatal if it fails
    if (analysis) {
      progress('scaling', 'Analyzing scalability under load…')
      try {
        analysis.scalability = await analyzeScalability(folderPath)
        progress('scaling', `Scalability score: ${analysis.scalability.scalabilityScore}/100 — ${analysis.scalability.bottlenecks.length} bottleneck${analysis.scalability.bottlenecks.length !== 1 ? 's' : ''}`)
      } catch (err) {
        const msg = String(err)
        if (msg.includes('CANCELLED')) { progress('cancelled', 'Scan cancelled'); return { semgrepFindings: [], gitleaksFindings: [], osvFindings: [], error: null, cancelled: true } }
        progress('scaling-error', `Scalability analysis failed: ${msg.replace('Error: ', '').slice(0, 80)}`)
        await sleep(300)
      }
    } else {
      progress('scaling-skip', 'Scalability analysis needs an API key — skipping')
      await sleep(300)
    }

    if (scanAborted) { progress('cancelled', 'Scan cancelled'); return { semgrepFindings: [], gitleaksFindings: [], osvFindings: [], error: null, cancelled: true } }

    // Compare against the previous scan of this folder, then save to history
    let comparison: ScanComparison | undefined
    if (analysis) {
      comparison = compareWithPreviousScan(folderPath, analysis)
      const folderName = folderPath.replace(/\\/g, '/').split('/').filter(Boolean).pop() ?? folderPath
      saveToHistory({
        id: randomUUID(),
        date: new Date().toISOString(),
        folderPath,
        folderName,
        securityScore: analysis.securityScore,
        criticalCount: analysis.criticalCount,
        highCount: analysis.highCount,
        mediumCount: analysis.mediumCount,
        lowCount: analysis.lowCount,
        findings: analysis.findings,
        summary: analysis.summary,
        scalability: analysis.scalability
      })
    }

    const totalFindings = semgrepFindings.length + gitleaksFindings.length + osvFindings.length
    progress('done', `Scan complete — ${totalFindings} total finding${totalFindings !== 1 ? 's' : ''}`)

    const combinedError = [semgrepError, gitleaksError, osvError].filter(Boolean).join('\n\n') || null
    return { semgrepFindings, gitleaksFindings, osvFindings, error: combinedError, analysis, analysisError, comparison }
  })

  createWindow()
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow() })

  // ── Auto-updater ────────────────────────────────────────────────────────────
  if (!is.dev) {
    autoUpdater.logger = null // silence logs in production; swap for electron-log if desired
    autoUpdater.autoDownload = true
    autoUpdater.autoInstallOnAppQuit = true
    autoUpdater.checkForUpdatesAndNotify().catch(() => { /* no network / no release yet */ })
  }
})

app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit() })

void LS_STORE_SLUG
