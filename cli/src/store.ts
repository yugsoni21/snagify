import { join, sep } from 'path'
import { existsSync, mkdirSync, readFileSync, writeFileSync, unlinkSync, readdirSync } from 'fs'
import { createHash, randomUUID } from 'crypto'
import { configDir } from './config.js'
import type { AIFinding, AnalysisResult, HistoryEntry, ScanComparison, SuppressedFinding } from './types.js'

const HISTORY_LIMIT = 50

function historyDir(): string {
  const d = join(configDir(), 'history')
  if (!existsSync(d)) mkdirSync(d, { recursive: true })
  return d
}

function indexPath(): string { return historyDir() + sep + 'index.json' }
// id is always a randomUUID we generated ourselves (see saveScan) — every caller
// reads it back from our own index file, never from raw external input.
function payloadPath(id: string): string { return historyDir() + sep + `${id}.json` }
function suppressionsPath(): string { return configDir() + sep + 'suppressions.json' }

// ── History (split: light index + per-scan payload, loaded on demand) ────────

export function readIndex(): HistoryEntry[] {
  try { return JSON.parse(readFileSync(indexPath(), 'utf-8')) as HistoryEntry[] } catch { return [] }
}

function writeIndex(list: HistoryEntry[]): void {
  writeFileSync(indexPath(), JSON.stringify(list, null, 2), 'utf-8')
}

export function saveScan(folderPath: string, analysis: AnalysisResult): string {
  const id = randomUUID()
  const folderName = folderPath.replace(/\\/g, '/').split('/').filter(Boolean).pop() ?? folderPath
  const entry: HistoryEntry = {
    id,
    date: new Date().toISOString(),
    folderPath,
    folderName,
    securityScore: analysis.securityScore,
    criticalCount: analysis.criticalCount,
    highCount: analysis.highCount,
    mediumCount: analysis.mediumCount,
    lowCount: analysis.lowCount,
    summary: analysis.summary
  }
  try {
    writeFileSync(payloadPath(id), JSON.stringify({ findings: analysis.findings, scalability: analysis.scalability }), 'utf-8')
  } catch { /* index entry still useful without the payload */ }

  const all = [entry, ...readIndex()]
  for (const dropped of all.slice(HISTORY_LIMIT)) {
    try { unlinkSync(payloadPath(dropped.id)) } catch { /* already gone */ }
  }
  writeIndex(all.slice(0, HISTORY_LIMIT))
  return id
}

export function loadPayload(id: string): { findings: AIFinding[]; scalability?: AnalysisResult['scalability'] } {
  try {
    return JSON.parse(readFileSync(payloadPath(id), 'utf-8'))
  } catch { return { findings: [] } }
}

export function deleteScan(id: string): boolean {
  const list = readIndex()
  const next = list.filter(e => e.id !== id)
  if (next.length === list.length) return false
  try { unlinkSync(payloadPath(id)) } catch { /* already gone */ }
  writeIndex(next)
  return true
}

/** Resolve a full or short id prefix to an entry. */
export function findEntry(idOrPrefix: string): HistoryEntry | null {
  const list = readIndex()
  return list.find(e => e.id === idOrPrefix) ?? list.find(e => e.id.startsWith(idOrPrefix)) ?? null
}

export function pruneHistory(): number {
  const dir = historyDir()
  const ids = new Set(readIndex().map(e => e.id))
  let removed = 0
  for (const f of readdirSync(dir)) {
    if (f === 'index.json' || !f.endsWith('.json')) continue
    if (!ids.has(f.replace(/\.json$/, ''))) { try { unlinkSync(join(dir, f)); removed++ } catch { /* skip */ } }
  }
  return removed
}

// ── Comparison ──────────────────────────────────────────────────────────────

/** Stable across scans: line numbers move, file+title does not. */
export function findingKey(f: { file: string; title: string }): string {
  return `${f.file}|${f.title.toLowerCase().trim()}`
}

export function compareWithPrevious(folderPath: string, analysis: AnalysisResult): ScanComparison | undefined {
  const prev = readIndex().find(e => e.folderPath === folderPath)
  if (!prev) return undefined
  const prevFindings = loadPayload(prev.id).findings ?? []
  const prevKeys = new Set(prevFindings.map(findingKey))
  const currKeys = new Set(analysis.findings.map(findingKey))
  let fixedCount = 0
  for (const k of prevKeys) if (!currKeys.has(k)) fixedCount++
  let newCount = 0, unchangedCount = 0
  for (const k of currKeys) { if (prevKeys.has(k)) unchangedCount++; else newCount++ }
  return {
    fixedCount, newCount, unchangedCount,
    scoreDelta: analysis.securityScore - prev.securityScore,
    prevScore: prev.securityScore,
    prevDate: prev.date
  }
}

// ── Suppressions (per project) ──────────────────────────────────────────────

type SuppressionMap = Record<string, SuppressedFinding[]>

function projectKey(folderPath: string): string {
  return createHash('sha256').update(folderPath).digest('hex').slice(0, 16)
}

function readSuppressions(): SuppressionMap {
  try { return JSON.parse(readFileSync(suppressionsPath(), 'utf-8')) as SuppressionMap } catch { return {} }
}

function writeSuppressions(map: SuppressionMap): void {
  writeFileSync(suppressionsPath(), JSON.stringify(map, null, 2), 'utf-8')
}

export function getSuppressions(folderPath: string): SuppressedFinding[] {
  return readSuppressions()[projectKey(folderPath)] ?? []
}

export function addSuppression(folderPath: string, f: AIFinding): SuppressedFinding[] {
  const map = readSuppressions()
  const key = projectKey(folderPath)
  const list = map[key] ?? []
  const fk = findingKey(f)
  if (!list.some(s => s.key === fk)) {
    list.push({ key: fk, title: f.title, file: f.file, severity: f.severity, date: new Date().toISOString() })
  }
  map[key] = list
  writeSuppressions(map)
  return list
}

export function removeSuppression(folderPath: string, key: string): SuppressedFinding[] {
  const map = readSuppressions()
  const pk = projectKey(folderPath)
  map[pk] = (map[pk] ?? []).filter(s => s.key !== key)
  if (map[pk].length === 0) delete map[pk]
  writeSuppressions(map)
  return map[pk] ?? []
}

const DEDUCTION: Record<string, number> = { critical: 20, high: 10, medium: 5, low: 2 }

/** Drop suppressed findings and recompute score/counts so the number stays honest. */
export function applySuppressions(folderPath: string, analysis: AnalysisResult): AnalysisResult {
  const suppressed = getSuppressions(folderPath)
  if (!suppressed.length) return analysis
  const keys = new Set(suppressed.map(s => s.key))
  const kept = analysis.findings.filter(f => !keys.has(findingKey(f)))
  const removed = analysis.findings.length - kept.length
  if (!removed) return analysis
  return {
    ...analysis,
    findings: kept,
    securityScore: Math.max(0, 100 - kept.reduce((a, f) => a + (DEDUCTION[f.severity] ?? 2), 0)),
    criticalCount: kept.filter(f => f.severity === 'critical').length,
    highCount: kept.filter(f => f.severity === 'high').length,
    mediumCount: kept.filter(f => f.severity === 'medium').length,
    lowCount: kept.filter(f => f.severity === 'low').length,
    suppressedCount: removed
  }
}
