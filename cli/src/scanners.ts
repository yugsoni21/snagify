import { spawn } from 'child_process'
import { existsSync, statSync, realpathSync, readFileSync, unlinkSync } from 'fs'
import { tmpdir } from 'os'
import { randomUUID } from 'crypto'
import { readdir, stat, realpath } from 'fs/promises'
import { join, sep, basename, extname, isAbsolute, resolve } from 'path'
import { homedir } from 'os'
import type { Dirent } from 'fs'
import type { GitleaksFinding, OsvFinding, ScannerOutcome, SemgrepFinding } from './types.js'

export type Tool = 'semgrep' | 'gitleaks' | 'osv-scanner'

const SEARCH_PATHS: Record<Tool, string[]> = {
  semgrep: [`${homedir()}/.local/bin/semgrep`, '/opt/homebrew/bin/semgrep', '/usr/local/bin/semgrep', '/usr/bin/semgrep'],
  gitleaks: ['/opt/homebrew/bin/gitleaks', '/usr/local/bin/gitleaks', '/usr/bin/gitleaks'],
  'osv-scanner': ['/opt/homebrew/bin/osv-scanner', '/usr/local/bin/osv-scanner', '/usr/bin/osv-scanner']
}

export const INSTALL_HINT: Record<Tool, string> = {
  semgrep: 'pip install semgrep   (or: brew install semgrep)',
  gitleaks: 'brew install gitleaks   (or: https://github.com/gitleaks/gitleaks/releases)',
  'osv-scanner': 'brew install osv-scanner   (or: https://github.com/google/osv-scanner/releases)'
}

/** Resolve a tool from PATH or well-known locations. Never takes user input. */
export function findTool(tool: Tool): string | null {
  const override = process.env[`SNAGIFY_${tool.toUpperCase().replace(/-/g, '_')}_PATH`]
  if (override && existsSync(override)) return override
  for (const p of SEARCH_PATHS[tool]) if (existsSync(p)) return p
  // Fall back to PATH lookup
  const dirs = (process.env.PATH ?? '').split(sep === '\\' ? ';' : ':')
  const exe = process.platform === 'win32' ? `${tool}.exe` : tool
  for (const d of dirs) {
    if (!d) continue
    const candidate = join(d, exe)
    try { if (existsSync(candidate) && statSync(candidate).isFile()) return candidate } catch { /* skip */ }
  }
  return null
}

let active: ReturnType<typeof spawn>[] = []

export function killActiveScans(): void {
  for (const p of active) { try { p.kill('SIGTERM') } catch { /* already dead */ } }
  active = []
}

interface RunResult { stdout: string; stderr: string; code: number | null }

/** shell:false + absolute binary path — no shell expansion, no injection surface. */
function run(bin: string, args: string[]): Promise<RunResult> {
  return new Promise((resolvePromise, reject) => {
    let stdout = '', stderr = ''
    const proc = spawn(bin, args, { env: process.env, shell: false })
    active.push(proc)
    proc.stdout?.on('data', (d: Buffer) => { stdout += d.toString() })
    proc.stderr?.on('data', (d: Buffer) => { stderr += d.toString() })
    proc.on('error', err => {
      active = active.filter(p => p !== proc)
      reject(err)
    })
    proc.on('close', code => {
      active = active.filter(p => p !== proc)
      resolvePromise({ stdout, stderr, code })
    })
  })
}

function fail<T>(error: string): ScannerOutcome<T> {
  return { ok: false, findings: [], error, skipped: false }
}
function skipped<T>(error: string): ScannerOutcome<T> {
  return { ok: false, findings: [], error, skipped: true }
}

// ── Semgrep ─────────────────────────────────────────────────────────────────

export async function runSemgrep(target: string): Promise<ScannerOutcome<SemgrepFinding>> {
  const bin = findTool('semgrep')
  if (!bin) return skipped(`semgrep not found — install with: ${INSTALL_HINT.semgrep}`)
  try {
    const { stdout, stderr, code } = await run(bin, ['--config=auto', '--json', '--quiet', target])
    if (!stdout.trim()) return fail(`semgrep produced no output (exit ${code}): ${stderr.slice(0, 200)}`)
    const parsed = JSON.parse(stdout) as { results?: SemgrepFinding[] }
    if (!Array.isArray(parsed.results)) return fail('semgrep returned unexpected JSON')
    return { ok: true, findings: parsed.results, error: null, skipped: false }
  } catch (e) {
    return fail(`semgrep failed: ${String(e).slice(0, 200)}`)
  }
}

// ── Gitleaks ────────────────────────────────────────────────────────────────

const BUILD_DIRS = ['node_modules', 'dist/', '/dist\\', '/out/', '\\out\\', 'dist-electron', '.venv', 'vendor/']
const BUILD_EXTS = ['.asar', '.pak', '.map', '.min.js', '.lock']

export async function runGitleaks(target: string): Promise<ScannerOutcome<GitleaksFinding>> {
  const bin = findTool('gitleaks')
  if (!bin) return skipped(`gitleaks not found — install with: ${INSTALL_HINT.gitleaks}`)
  // Report to a temp file, not stdout: `--report-path=-` silently emits nothing
  // on gitleaks 8.21.x, which would make every scan look secret-free.
  const reportPath = join(tmpdir(), `snagify-gitleaks-${randomUUID()}.json`)
  try {
    const { stderr, code } = await run(bin, [
      'detect', '--source', target, '--report-format=json', `--report-path=${reportPath}`, '--no-git', '--exit-code', '0'
    ])
    let raw = ''
    try { raw = readFileSync(reportPath, 'utf-8') } catch { /* no report written */ }
    if (!raw.trim()) {
      // gitleaks omits the report file entirely when it finds nothing
      if (code === 0) return { ok: true, findings: [], error: null, skipped: false }
      return fail(`gitleaks failed (exit ${code}): ${stderr.slice(0, 200)}`)
    }
    const parsed = JSON.parse(raw) as unknown
    const all = Array.isArray(parsed) ? (parsed as GitleaksFinding[]) : []
    // Build artifacts and vendored code are not the user's secrets to fix
    const findings = all.filter(f => {
      const p = f.File ?? ''
      if (BUILD_DIRS.some(d => p.includes(d))) return false
      if (BUILD_EXTS.some(e => p.endsWith(e))) return false
      return true
    })
    return { ok: true, findings, error: null, skipped: false }
  } catch (e) {
    return fail(`gitleaks failed: ${String(e).slice(0, 200)}`)
  } finally {
    try { unlinkSync(reportPath) } catch { /* nothing to clean */ }
  }
}

// ── OSV-Scanner ─────────────────────────────────────────────────────────────

export function flattenOsv(raw: string, rootPath: string): OsvFinding[] {
  if (!raw.trim()) return []
  const parsed = JSON.parse(raw) as {
    results?: Array<{
      source?: { path?: string }
      packages?: Array<{
        package?: { name?: string; version?: string; ecosystem?: string }
        groups?: Array<{ ids?: string[]; aliases?: string[]; max_severity?: string }>
        vulnerabilities?: Array<{ id: string; summary?: string; affected?: Array<{ ranges?: Array<{ events?: Array<{ fixed?: string }> }> }> }>
      }>
    }>
  }
  const out: OsvFinding[] = []
  const seen = new Set<string>()
  for (const r of parsed.results ?? []) {
    const src = r.source?.path ?? ''
    const relFile = src.startsWith(rootPath) ? src.slice(rootPath.length).replace(/^[/\\]/, '') : src
    for (const p of r.packages ?? []) {
      const pkg = p.package?.name ?? 'unknown'
      const version = p.package?.version ?? ''
      for (const g of p.groups ?? []) {
        const ids = g.ids ?? []
        const key = `${pkg}:${version}:${ids.join(',')}`
        if (seen.has(key)) continue
        seen.add(key)
        const vulns = (p.vulnerabilities ?? []).filter(v => ids.includes(v.id))
        let fixedVersion: string | null = null
        for (const v of vulns) for (const a of v.affected ?? []) for (const rg of a.ranges ?? []) for (const e of rg.events ?? []) if (e.fixed) fixedVersion = e.fixed
        const cvss = g.max_severity ? Number(g.max_severity) : NaN
        out.push({
          package: pkg, version, ecosystem: p.package?.ecosystem ?? '',
          ids, aliases: g.aliases ?? ids,
          cvss: Number.isFinite(cvss) ? cvss : null,
          summary: (vulns.map(v => v.summary).find(Boolean) ?? 'Known vulnerability').slice(0, 200),
          fixedVersion, file: relFile
        })
      }
    }
  }
  out.sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0))
  return out
}

export async function runOsv(target: string): Promise<ScannerOutcome<OsvFinding>> {
  const bin = findTool('osv-scanner')
  if (!bin) return skipped(`osv-scanner not found — install with: ${INSTALL_HINT['osv-scanner']}`)
  try {
    const { stdout, stderr, code } = await run(bin, ['scan', 'source', '-r', '--format', 'json', target])
    // Exit 128 = no dependency manifests found: nothing to scan, not a failure.
    // Non-zero otherwise usually means "vulns found", so validate JSON not exit code.
    if (code === 128) return { ok: true, findings: [], error: null, skipped: false }
    if (!stdout.trim()) return fail(`osv-scanner produced no output (exit ${code}): ${stderr.slice(0, 200)}`)
    return { ok: true, findings: flattenOsv(stdout, target), error: null, skipped: false }
  } catch (e) {
    return fail(`osv-scanner failed: ${String(e).slice(0, 200)}`)
  }
}

// ── Project file walking (async: never block on huge repos) ──────────────────

export const IGNORED_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '.next', '.nuxt', '.turbo', '.cache',
  'coverage', '__pycache__', '.venv', 'venv', '.expo', 'out', '.output', 'Pods', '.gradle', 'target'
])

export async function walkFiles(rootPath: string, limit = 20_000): Promise<string[]> {
  const files: string[] = []
  async function walk(dir: string): Promise<void> {
    if (files.length >= limit) return
    let safeDir: string
    try { safeDir = await realpath(dir) } catch { return }
    // Stay inside the project root even across symlinks
    if (safeDir !== rootPath && !safeDir.startsWith(rootPath + sep)) return
    let entries: Dirent[]
    try { entries = await readdir(safeDir, { withFileTypes: true }) } catch { return }
    for (const e of entries) {
      if (files.length >= limit) return
      if (IGNORED_DIRS.has(e.name) || e.name.startsWith('.') && e.isDirectory()) continue
      const name = basename(e.name)
      if (!name || name === '.' || name === '..') continue
      const full = safeDir + sep + name
      if (e.isDirectory()) await walk(full)
      else if (e.isFile()) files.push(full)
    }
  }
  await walk(rootPath)
  return files
}

const SCALE_EXTS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.go', '.rb', '.php', '.java', '.cs', '.rs'])
const SCALE_HINTS = /(server|api|route|controller|service|handler|middleware|db|database|model|schema|query|repo|dao|queue|worker|job|cache|store|socket|index|app|main)/i

/** Rank files by how likely they carry load-bearing logic. */
export async function pickLoadBearingFiles(rootPath: string, max = 12): Promise<string[]> {
  const files = await walkFiles(rootPath)
  const scored: Array<{ path: string; score: number }> = []
  for (const f of files) {
    if (!SCALE_EXTS.has(extname(f).toLowerCase())) continue
    const rel = f.slice(rootPath.length + 1)
    const depth = rel.split(sep).length
    let score = 0
    if (SCALE_HINTS.test(basename(f))) score += 3
    else if (SCALE_HINTS.test(rel)) score += 1
    score += Math.max(0, 3 - depth)
    try { if ((await stat(f)).size > 200_000) score -= 5 } catch { score -= 5 }
    scored.push({ path: f, score })
  }
  scored.sort((a, b) => b.score - a.score)
  return scored.slice(0, max).map(s => s.path)
}

/** Validate a user-supplied path and canonicalize it. */
export function resolveTarget(input: string): string {
  const abs = isAbsolute(input) ? input : resolve(process.cwd(), input)
  let real: string
  try { real = realpathSync(abs) } catch { throw new Error(`Path not accessible: ${input}`) }
  if (!statSync(real).isDirectory()) throw new Error(`Not a directory: ${real}`)
  return real
}
