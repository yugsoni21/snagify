import { runGitleaks, runOsv, runSemgrep } from './scanners.js'
import { analyzeFindings, analyzeScalability, deepReview, mergeDeepFindings, normalizeFindings, dedupeFindings, rescore, MissingApiKeyError } from './ai.js'
import { applySuppressions, compareWithPrevious, saveScan } from './store.js'
import { hasProvider } from './config.js'
import { rawAsFindings } from './report.js'
import type { AnalysisResult, ScanResult } from './types.js'

export interface ScanOptions {
  code?: boolean
  secrets?: boolean
  deps?: boolean
  ai?: boolean
  deep?: boolean
  scalability?: boolean
  save?: boolean
  onProgress?: (phase: string, msg: string) => void
}

/** Deterministic fallback score using the same weights the AI is told to use. */
export function heuristicScore(r: Pick<ScanResult, 'code' | 'secrets' | 'deps'>): number {
  let deduction = 0
  for (const f of r.code.findings) {
    const sev = String(f.extra?.severity ?? '').toUpperCase()
    deduction += sev === 'ERROR' ? 10 : sev === 'WARNING' ? 5 : 2
  }
  deduction += r.secrets.findings.length * 20
  for (const d of r.deps.findings) {
    const c = d.cvss ?? 0
    deduction += c >= 9 ? 20 : c >= 7 ? 10 : c >= 4 ? 5 : 2
  }
  return Math.max(0, 100 - deduction)
}

export async function runScan(target: string, opts: ScanOptions = {}): Promise<ScanResult> {
  const {
    code = true, secrets = true, deps = true,
    ai = true, deep = true, scalability = false, save = true, onProgress
  } = opts
  const p = (phase: string, msg: string): void => onProgress?.(phase, msg)

  const empty = { ok: true, findings: [], error: null, skipped: true } as const

  p('code', 'Scanning code for vulnerabilities…')
  const codeOut = code ? await runSemgrep(target) : { ...empty, findings: [] as never[] }
  p('code-done', codeOut.ok ? `${codeOut.findings.length} code finding${codeOut.findings.length === 1 ? '' : 's'}` : codeOut.error ?? 'failed')

  p('secrets', 'Detecting secrets…')
  const secretsOut = secrets ? await runGitleaks(target) : { ...empty, findings: [] as never[] }
  p('secrets-done', secretsOut.ok ? `${secretsOut.findings.length} secret${secretsOut.findings.length === 1 ? '' : 's'}` : secretsOut.error ?? 'failed')

  p('deps', 'Checking dependencies for CVEs…')
  const depsOut = deps ? await runOsv(target) : { ...empty, findings: [] as never[] }
  p('deps-done', depsOut.ok ? `${depsOut.findings.length} vulnerable dependenc${depsOut.findings.length === 1 ? 'y' : 'ies'}` : depsOut.error ?? 'failed')

  let analysis: AnalysisResult | null = null
  let analysisError: string | null = null

  const wantAi = ai && hasProvider()
  if (ai && !hasProvider()) analysisError = 'no AI provider configured — run: snagify config --key <key>'

  if (wantAi) {
    p('ai', 'Analyzing findings with AI…')
    try {
      analysis = await analyzeFindings(codeOut.findings, secretsOut.findings, depsOut.findings, m => p('ai', m))
      // Canonicalize paths/ids and collapse duplicates before scoring
      analysis = rescore(analysis, dedupeFindings(normalizeFindings(target, analysis.findings)))
      analysis = applySuppressions(target, analysis)
      p('ai-done', `AI analysis complete — score ${analysis.securityScore}/100`)
    } catch (e) {
      analysisError = e instanceof MissingApiKeyError ? e.message : String(e).replace(/^Error: /, '')
      p('ai-error', analysisError)
    }
  }

  // Deep review reads the source directly, catching what pattern scanners cannot
  if (deep && analysis) {
    p('deep', 'Deep code review — hunting logic and authorization flaws…')
    try {
      const extra = normalizeFindings(target, await deepReview(target, m => p('deep', m)))
      if (extra.length) {
        analysis = mergeDeepFindings(analysis, extra)
        analysis = applySuppressions(target, analysis)
        p('deep-done', `Deep review found ${extra.length} additional issue${extra.length === 1 ? '' : 's'}`)
      } else {
        p('deep-done', 'Deep review found no additional issues')
      }
    } catch (e) {
      p('deep-error', `Deep review failed: ${String(e).replace(/^Error: /, '').slice(0, 90)}`)
    }
  }

  if (scalability && analysis) {
    p('scale', 'Assessing scalability under load…')
    try {
      analysis.scalability = await analyzeScalability(target)
      p('scale-done', `Load readiness ${analysis.scalability.scalabilityScore}/100 — ${analysis.scalability.bottlenecks.length} bottleneck${analysis.scalability.bottlenecks.length === 1 ? '' : 's'}`)
    } catch (e) {
      p('scale-error', String(e).replace(/^Error: /, ''))
    }
  } else if (scalability && !analysis) {
    p('scale-skip', 'Scalability analysis needs AI — skipped')
  }

  const result: ScanResult = {
    folderPath: target,
    date: new Date().toISOString(),
    code: codeOut,
    secrets: secretsOut,
    deps: depsOut,
    score: analysis ? analysis.securityScore : heuristicScore({ code: codeOut, secrets: secretsOut, deps: depsOut }),
    scoreSource: analysis ? 'ai' : 'heuristic',
    analysis,
    analysisError
  }

  // Record every scan, AI or not — otherwise history, `show`, and the
  // fixed/new comparison silently do nothing for users without an API key.
  const recordable: AnalysisResult = analysis ?? (() => {
    const findings = rawAsFindings(result)
    const count = (sev: string): number => findings.filter(f => f.severity === sev).length
    return {
      securityScore: result.score,
      summary: `Heuristic scan: ${result.code.findings.length} code, ${result.secrets.findings.length} secret, ${result.deps.findings.length} dependency findings.`,
      criticalCount: count('critical'), highCount: count('high'),
      mediumCount: count('medium'), lowCount: count('low'),
      findings
    }
  })()

  result.comparison = compareWithPrevious(target, recordable)
  if (save) saveScan(target, recordable)
  return result
}

/** True when any enabled scanner failed outright (skipped-but-absent is not a failure). */
export function hasScannerFailure(r: ScanResult): boolean {
  return [r.code, r.secrets, r.deps].some(o => !o.ok && !o.skipped)
}
