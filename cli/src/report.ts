import { bold, cyan, gray, green, hr, red, scoreColor, sevColor, wrapText, yellow } from './ui.js'
import type { AnalysisResult, ScanResult } from './types.js'

const AREA_LABEL: Record<string, string> = {
  database: 'DATABASE', api: 'API', memory: 'MEMORY',
  storage: 'STORAGE', concurrency: 'CONCURRENCY', architecture: 'ARCHITECTURE'
}

function statusWord(score: number): string {
  return score >= 71 ? 'Good' : score >= 41 ? 'Fair' : 'At risk'
}

export function renderTerminal(r: ScanResult, opts: { verbose?: boolean } = {}): string {
  const out: string[] = []
  const push = (s = ''): void => { out.push(s) }

  push()
  push(bold('  Snagify Security Scan'))
  push(gray(`  ${r.folderPath}`))
  push()

  const cell = (o: { ok: boolean; skipped: boolean; findings: unknown[] }, color: (s: string) => string): string =>
    o.ok ? (o.findings.length ? color(bold(String(o.findings.length))) : bold('0')) : yellow('—')

  push(`  ${gray('Code findings'.padEnd(24))}${cell(r.code, red)}`)
  push(`  ${gray('Secrets'.padEnd(24))}${cell(r.secrets, yellow)}`)
  push(`  ${gray('Vulnerable dependencies'.padEnd(24))}${cell(r.deps, cyan)}`)
  push()
  push(`  ${gray('Security score'.padEnd(24))}${scoreColor(r.score, bold(`${r.score}/100`))}  ${gray(`(${statusWord(r.score)}, ${r.scoreSource === 'ai' ? 'AI analysis' : 'heuristic'})`)}`)

  if (r.comparison) {
    const c = r.comparison
    const parts: string[] = []
    if (c.fixedCount) parts.push(green(`${c.fixedCount} fixed`))
    if (c.newCount) parts.push(red(`${c.newCount} new`))
    if (!parts.length) parts.push(gray('no change'))
    const delta = c.scoreDelta > 0 ? green(`+${c.scoreDelta}`) : c.scoreDelta < 0 ? red(String(c.scoreDelta)) : gray('±0')
    push(`  ${gray('vs last scan'.padEnd(24))}${parts.join(gray(' · '))}  ${delta} ${gray('pts')}`)
  }

  const a = r.analysis
  // Without AI there is no analysis — still show every finding rather than bare counts
  if (!a) {
    const raw = rawAsFindings(r)
    if (raw.length) {
      push()
      push(`  ${hr(66)}`)
      push()
      const shown = opts.verbose ? raw : raw.slice(0, 15)
      for (const f of shown) {
        push(`  ${sevColor(f.severity, f.severity.toUpperCase().padEnd(8))} ${bold(f.title.slice(0, 62))}`)
        if (f.file) push(gray(`           ${f.file}${f.line !== null ? `:${f.line}` : ''}`))
        if (opts.verbose && f.fixSuggestion) push(`           ${green('fix:')} ${wrapText(f.fixSuggestion, 56, '                ')}`)
      }
      push()
      if (raw.length > shown.length) { push(gray(`  … and ${raw.length - shown.length} more (--verbose to see all)`)); push() }
      push(gray('  Set an API key for ranked severity, real explanations, fixes,'))
      push(gray('  and a deep code review:  snagify config --key sk-ant-…'))
      push()
    }
  }
  if (a) {
    if (a.summary) {
      push()
      push(`  ${wrapText(a.summary, 68, '  ')}`)
    }
    if (a.suppressedCount) {
      push()
      push(gray(`  ${a.suppressedCount} ignored finding${a.suppressedCount === 1 ? '' : 's'} excluded from this score`))
    }
    if (a.findings.length) {
      push()
      push(`  ${hr(66)}`)
      push()
      const shown = opts.verbose ? a.findings : a.findings.slice(0, 12)
      for (const f of shown) {
        const tag = sevColor(f.severity, f.severity.toUpperCase().padEnd(8))
        const loc = f.file ? gray(`  ${f.file}${f.line !== null ? `:${f.line}` : ''}`) : ''
        push(`  ${tag} ${bold(f.title)}`)
        if (loc) push(`           ${loc.trim()}`)
        const std = [...(f.cwe ?? []), ...(f.owasp ?? [])]
        if (std.length) push(`           ${cyan(std.join(' · '))}`)
        if (opts.verbose) {
          if (f.explanation) push(`           ${wrapText(f.explanation, 60, '           ')}`)
          if (f.fixSuggestion) push(`           ${green('fix:')} ${wrapText(f.fixSuggestion, 56, '                ')}`)
        }
        push()
      }
      if (a.findings.length > shown.length) {
        push(gray(`  … and ${a.findings.length - shown.length} more (use --verbose to see all)`))
        push()
      }
    }

    if (a.complianceIssues?.length) {
      push(`  ${bold(yellow('Compliance'))}`)
      for (const c of a.complianceIssues) {
        push(`    ${yellow(c.regulation)} ${gray(c.article)}`)
        push(`      ${wrapText(c.description, 62, '      ')}`)
      }
      push()
    }

    if (a.scalability) {
      const s = a.scalability
      push(`  ${hr(66)}`)
      push()
      push(`  ${bold('Load readiness')}  ${scoreColor(s.scalabilityScore, bold(`${s.scalabilityScore}/100`))}`)
      if (s.summary) push(`  ${wrapText(s.summary, 68, '  ')}`)
      push()
      for (const b of s.bottlenecks) {
        push(`  ${sevColor(b.risk, b.risk.toUpperCase().padEnd(8))} ${gray((AREA_LABEL[b.area] ?? 'ARCH').padEnd(13))} ${bold(b.title)}`)
        if (b.impact) push(`           ${cyan('under load:')} ${wrapText(b.impact, 54, '           ')}`)
        if (opts.verbose && b.recommendation) push(`           ${green('fix:')} ${wrapText(b.recommendation, 56, '                ')}`)
        push()
      }
    }
  }

  const warnings = [r.code, r.secrets, r.deps].filter(o => !o.ok)
  if (warnings.length) {
    push(`  ${yellow('Warnings')} ${gray('— this score is incomplete')}`)
    for (const w of warnings) push(`    ${w.skipped ? gray('skipped:') : red('failed:')} ${w.error}`)
    push()
  }

  if (r.analysisError) {
    push(`  ${yellow('AI analysis unavailable')} ${gray('— ' + r.analysisError)}`)
    push()
  }

  return out.join('\n')
}

/** Gitleaks echoes the credential in several fields (Secret, Match, and the
 *  matched line). Scrub every occurrence — a leaked secret in a CI artifact is
 *  worse than the finding itself. */
function redactSecret(f: ScanResult['secrets']['findings'][number]): Record<string, unknown> {
  const raw = f as unknown as Record<string, unknown>
  const value = typeof raw.Secret === 'string' ? raw.Secret : ''
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(raw)) {
    if (k === 'Secret' || k === 'Match' || k === 'Line') { out[k] = '[redacted]'; continue }
    // Defensive: the value can appear in fields we do not know about
    out[k] = typeof v === 'string' && value && v.includes(value) ? v.split(value).join('[redacted]') : v
  }
  return out
}

export function renderJson(r: ScanResult): string {
  return JSON.stringify({
    folderPath: r.folderPath,
    date: r.date,
    score: r.score,
    scoreSource: r.scoreSource,
    counts: {
      code: r.code.ok ? r.code.findings.length : null,
      secrets: r.secrets.ok ? r.secrets.findings.length : null,
      vulnerableDependencies: r.deps.ok ? r.deps.findings.length : null
    },
    scanners: {
      code: { ok: r.code.ok, skipped: r.code.skipped, error: r.code.error },
      secrets: { ok: r.secrets.ok, skipped: r.secrets.skipped, error: r.secrets.error },
      deps: { ok: r.deps.ok, skipped: r.deps.skipped, error: r.deps.error }
    },
    comparison: r.comparison ?? null,
    analysis: r.analysis,
    analysisError: r.analysisError,
    findings: {
      code: r.code.findings,
      secrets: r.secrets.findings.map(redactSecret),
      deps: r.deps.findings
    }
  }, null, 2)
}

const SARIF_LEVEL: Record<string, string> = { critical: 'error', high: 'error', medium: 'warning', low: 'note' }

/** Without AI triage there are no synthesized findings — derive them from raw
 *  scanner output so `--no-ai --sarif` still produces a usable report. */
export function rawAsFindings(r: ScanResult): AnalysisResult['findings'] {
  const out: AnalysisResult['findings'] = []
  r.code.findings.forEach((f, i) => {
    const sev = String(f.extra?.severity ?? '').toUpperCase()
    out.push({
      id: f.check_id || `semgrep-${i}`,
      title: (f.extra?.message ?? f.check_id ?? 'Code finding').slice(0, 140),
      severity: sev === 'ERROR' ? 'high' : sev === 'WARNING' ? 'medium' : 'low',
      explanation: f.extra?.message ?? '',
      fixSuggestion: '',
      file: f.path ?? '',
      line: f.start?.line ?? null,
      cwe: f.extra?.metadata?.cwe ?? [],
      owasp: f.extra?.metadata?.owasp ?? []
    })
  })
  r.secrets.findings.forEach((f, i) => {
    out.push({
      id: `gitleaks-${f.RuleID || i}-${i}`,
      title: f.Description || 'Hardcoded secret detected',
      severity: 'critical',
      explanation: 'A credential appears to be committed in source.',
      fixSuggestion: 'Revoke the credential and move it to a secret manager or environment variable.',
      file: f.File ?? '',
      line: f.StartLine ?? null,
      cwe: ['CWE-798'],
      owasp: ['A07:2021 Identification and Authentication Failures']
    })
  })
  r.deps.findings.forEach((f, i) => {
    const c = f.cvss ?? 0
    out.push({
      id: (f.aliases.find(a => a.startsWith('CVE-')) ?? f.ids[0] ?? `osv-${i}`),
      title: `${f.package} ${f.version} — ${f.aliases.find(a => a.startsWith('CVE-')) ?? f.ids[0] ?? 'known vulnerability'}`,
      severity: c >= 9 ? 'critical' : c >= 7 ? 'high' : c >= 4 ? 'medium' : 'low',
      explanation: f.summary,
      fixSuggestion: f.fixedVersion ? `Upgrade ${f.package} to >= ${f.fixedVersion}` : `Upgrade ${f.package}`,
      file: f.file ?? '',
      line: null,
      cwe: ['CWE-1395'],
      owasp: ['A06:2021 Vulnerable and Outdated Components']
    })
  })
  return out
}

/** SARIF 2.1.0 so results can be uploaded to GitHub code scanning. */
export function renderSarif(r: ScanResult): string {
  const findings = r.analysis?.findings?.length ? r.analysis.findings : rawAsFindings(r)
  const rules = findings.map(f => ({
    id: f.id,
    name: f.title.slice(0, 120),
    shortDescription: { text: f.title },
    fullDescription: { text: f.explanation || f.title },
    help: { text: f.fixSuggestion || 'See finding details.' },
    properties: {
      tags: [...(f.cwe ?? []), ...(f.owasp ?? []), 'security'],
      'security-severity': String({ critical: 9.5, high: 7.5, medium: 5, low: 2 }[f.severity] ?? 2)
    }
  }))
  const results = findings.map(f => ({
    ruleId: f.id,
    level: SARIF_LEVEL[f.severity] ?? 'note',
    message: { text: `${f.title}${f.fixSuggestion ? ` — ${f.fixSuggestion}` : ''}` },
    locations: f.file ? [{
      physicalLocation: {
        artifactLocation: { uri: f.file.replace(/^\//, '') },
        region: { startLine: Math.max(1, f.line ?? 1) }
      }
    }] : []
  }))
  return JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'Snagify', informationUri: 'https://snagify.ca', rules } },
      results
    }]
  }, null, 2)
}

export function renderMarkdown(r: ScanResult): string {
  const a: AnalysisResult | null = r.analysis
  const lines: string[] = []
  lines.push(`# Snagify Security Report`)
  lines.push('')
  lines.push(`**Project:** \`${r.folderPath}\`  `)
  lines.push(`**Date:** ${new Date(r.date).toLocaleString()}  `)
  lines.push(`**Security score:** ${r.score}/100 (${statusWord(r.score)})`)
  lines.push('')
  lines.push('| Metric | Count |')
  lines.push('|---|---|')
  lines.push(`| Code findings | ${r.code.ok ? r.code.findings.length : 'unknown'} |`)
  lines.push(`| Secrets | ${r.secrets.ok ? r.secrets.findings.length : 'unknown'} |`)
  lines.push(`| Vulnerable dependencies | ${r.deps.ok ? r.deps.findings.length : 'unknown'} |`)
  lines.push('')
  if (r.comparison) {
    const c = r.comparison
    lines.push(`**Since last scan:** ${c.fixedCount} fixed, ${c.newCount} new (${c.scoreDelta >= 0 ? '+' : ''}${c.scoreDelta} pts)`)
    lines.push('')
  }
  if (a?.summary) { lines.push('## Summary'); lines.push(''); lines.push(a.summary); lines.push('') }
  const mdFindings = a?.findings.length ? a.findings : rawAsFindings(r)
  if (mdFindings.length) {
    lines.push('## Findings')
    lines.push('')
    for (const f of mdFindings) {
      lines.push(`### ${f.severity.toUpperCase()} — ${f.title}`)
      lines.push('')
      if (f.file) lines.push(`\`${f.file}${f.line !== null ? `:${f.line}` : ''}\`  `)
      const std = [...(f.cwe ?? []), ...(f.owasp ?? [])]
      if (std.length) lines.push(`${std.join(' · ')}  `)
      lines.push('')
      if (f.explanation) { lines.push(f.explanation); lines.push('') }
      if (f.fixSuggestion) { lines.push(`**Fix:** ${f.fixSuggestion}`); lines.push('') }
    }
  }
  if (a?.scalability) {
    const s = a.scalability
    lines.push('## Scalability')
    lines.push('')
    lines.push(`**Load readiness:** ${s.scalabilityScore}/100`)
    lines.push('')
    if (s.summary) { lines.push(s.summary); lines.push('') }
    for (const b of s.bottlenecks) {
      lines.push(`### ${b.risk.toUpperCase()} · ${b.area} — ${b.title}`)
      lines.push('')
      if (b.impact) { lines.push(`**Under load:** ${b.impact}`); lines.push('') }
      if (b.recommendation) { lines.push(`**Fix:** ${b.recommendation}`); lines.push('') }
    }
  }
  lines.push('---')
  lines.push('')
  lines.push('_Generated by [Snagify](https://snagify.ca)_')
  return lines.join('\n')
}
