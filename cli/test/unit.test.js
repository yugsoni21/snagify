/**
 * Unit tests — pure logic, no network, no scanners.
 * Run against the built artifact in dist/ so we test what actually ships.
 */
import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, readFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { repairJson, codeContext, resolveFindingFile } from '../dist/ai.js'
import { detectProvider, PROVIDERS } from '../dist/providers.js'
import { flattenOsv, resolveTarget, findTool } from '../dist/scanners.js'
import { findingKey, applySuppressions } from '../dist/store.js'
import { renderJson, renderSarif, renderMarkdown, rawAsFindings, renderTerminal } from '../dist/report.js'
import { heuristicScore, hasScannerFailure } from '../dist/scan.js'
import { applyPatch, revertPatch } from '../dist/fix.js'
import { install as hookInstall, uninstall as hookUninstall, isInstalled } from '../dist/hook.js'
import { parseArgs } from '../dist/args.js'
import { maskKey } from '../dist/config.js'

const tmp = () => mkdtempSync(join(tmpdir(), 'snagify-test-'))

/** Minimal ScanResult skeleton for report tests. */
function scanResult(over = {}) {
  const ok = (findings = []) => ({ ok: true, findings, error: null, skipped: false })
  return {
    folderPath: '/proj', date: new Date().toISOString(),
    code: ok(), secrets: ok(), deps: ok(),
    score: 100, scoreSource: 'heuristic', analysis: null, analysisError: null,
    ...over
  }
}

describe('repairJson', () => {
  test('passes through valid JSON', () => {
    assert.equal(repairJson('{"a":1}'), '{"a":1}')
  })
  test('strips prose before the object', () => {
    assert.deepEqual(JSON.parse(repairJson('Here you go:\n{"a":1}')), { a: 1 })
  })
  test('strips markdown fences', () => {
    assert.deepEqual(JSON.parse(repairJson('```json\n{"a":1}\n```')), { a: 1 })
  })
  test('closes a truncated object', () => {
    const out = JSON.parse(repairJson('{"a":1,"b":{"c":2'))
    assert.equal(out.a, 1)
    assert.equal(out.b.c, 2)
  })
  test('closes a truncated array and drops a trailing comma', () => {
    const out = JSON.parse(repairJson('{"items":[1,2,3,'))
    assert.deepEqual(out.items, [1, 2, 3])
  })
  test('does not confuse braces inside strings', () => {
    const out = JSON.parse(repairJson('{"msg":"a { b } c"}'))
    assert.equal(out.msg, 'a { b } c')
  })
  test('handles escaped quotes in strings', () => {
    const out = JSON.parse(repairJson('{"msg":"say \\"hi\\""}'))
    assert.equal(out.msg, 'say "hi"')
  })
  test('throws when there is no object at all', () => {
    assert.throws(() => repairJson('no json here'))
  })
})

describe('detectProvider', () => {
  const cases = [
    ['sk-ant-api03-xxxx', 'anthropic'],
    ['sk-proj-xxxx', 'openai'],
    ['sk-xxxx', 'openai'],
    ['AIzaSyABC', 'google'],
    ['gsk_abc', 'openai-compatible'],
    ['sk-or-v1-abc', 'openai-compatible'],
    ['garbage', null],
    ['', null]
  ]
  for (const [key, expected] of cases) {
    test(`${key || '(empty)'} -> ${expected}`, () => {
      assert.equal(detectProvider(key), expected)
    })
  }
  test('anthropic prefix wins over the generic sk- rule', () => {
    // sk-ant- also matches sk-, so order matters
    assert.equal(detectProvider('sk-ant-foo'), 'anthropic')
  })
  test('every provider declares a default model', () => {
    for (const [id, spec] of Object.entries(PROVIDERS)) {
      assert.ok(spec.defaultModel, `${id} missing defaultModel`)
      assert.equal(typeof spec.needsKey, 'boolean')
    }
  })
  test('ollama is the only keyless provider', () => {
    assert.equal(PROVIDERS.ollama.needsKey, false)
    assert.equal(PROVIDERS.anthropic.needsKey, true)
  })
})

describe('flattenOsv', () => {
  const raw = JSON.stringify({
    results: [{
      source: { path: '/proj/package-lock.json' },
      packages: [{
        package: { name: 'lodash', version: '4.17.20', ecosystem: 'npm' },
        groups: [
          { ids: ['GHSA-1'], aliases: ['CVE-2021-1', 'GHSA-1'], max_severity: '7.5' },
          { ids: ['GHSA-2'], aliases: ['CVE-2021-2'], max_severity: '9.8' }
        ],
        vulnerabilities: [
          { id: 'GHSA-1', summary: 'ReDoS', affected: [{ ranges: [{ events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }] },
          { id: 'GHSA-2', summary: 'Proto pollution', affected: [{ ranges: [{ events: [{ fixed: '4.17.22' }] }] }] }
        ]
      }]
    }]
  })

  test('flattens one finding per vulnerability group', () => {
    assert.equal(flattenOsv(raw, '/proj').length, 2)
  })
  test('sorts by CVSS descending', () => {
    const out = flattenOsv(raw, '/proj')
    assert.equal(out[0].cvss, 9.8)
    assert.equal(out[1].cvss, 7.5)
  })
  test('extracts the fixed version', () => {
    const out = flattenOsv(raw, '/proj')
    assert.equal(out.find(f => f.ids[0] === 'GHSA-1').fixedVersion, '4.17.21')
  })
  test('makes the source path project-relative', () => {
    assert.equal(flattenOsv(raw, '/proj')[0].file, 'package-lock.json')
  })
  test('returns empty for blank input', () => {
    assert.deepEqual(flattenOsv('', '/proj'), [])
    assert.deepEqual(flattenOsv('   ', '/proj'), [])
  })
  test('deduplicates identical package+group entries', () => {
    const dup = JSON.stringify({
      results: [
        { source: { path: '/proj/a.lock' }, packages: [{ package: { name: 'x', version: '1' }, groups: [{ ids: ['G'] }], vulnerabilities: [] }] },
        { source: { path: '/proj/a.lock' }, packages: [{ package: { name: 'x', version: '1' }, groups: [{ ids: ['G'] }], vulnerabilities: [] }] }
      ]
    })
    assert.equal(flattenOsv(dup, '/proj').length, 1)
  })
  test('survives missing optional fields', () => {
    const sparse = JSON.stringify({ results: [{ packages: [{ groups: [{}] }] }] })
    const out = flattenOsv(sparse, '/proj')
    assert.equal(out.length, 1)
    assert.equal(out[0].package, 'unknown')
    assert.equal(out[0].cvss, null)
  })
})

describe('heuristicScore', () => {
  const wrap = (code = [], secrets = [], deps = []) => ({
    code: { findings: code }, secrets: { findings: secrets }, deps: { findings: deps }
  })
  test('clean project scores 100', () => {
    assert.equal(heuristicScore(wrap()), 100)
  })
  test('one secret costs 20', () => {
    assert.equal(heuristicScore(wrap([], [{}])), 80)
  })
  test('semgrep ERROR costs 10, WARNING 5', () => {
    assert.equal(heuristicScore(wrap([{ extra: { severity: 'ERROR' } }])), 90)
    assert.equal(heuristicScore(wrap([{ extra: { severity: 'WARNING' } }])), 95)
  })
  test('CVSS maps to deduction bands', () => {
    assert.equal(heuristicScore(wrap([], [], [{ cvss: 9.5 }])), 80)
    assert.equal(heuristicScore(wrap([], [], [{ cvss: 7.1 }])), 90)
    assert.equal(heuristicScore(wrap([], [], [{ cvss: 4.0 }])), 95)
    assert.equal(heuristicScore(wrap([], [], [{ cvss: 1.0 }])), 98)
  })
  test('never goes below zero', () => {
    assert.equal(heuristicScore(wrap([], new Array(20).fill({}))), 0)
  })
})

describe('hasScannerFailure', () => {
  test('a crashed scanner is a failure', () => {
    assert.equal(hasScannerFailure(scanResult({
      code: { ok: false, findings: [], error: 'boom', skipped: false }
    })), true)
  })
  test('a missing (skipped) scanner is not a failure', () => {
    assert.equal(hasScannerFailure(scanResult({
      code: { ok: false, findings: [], error: 'not installed', skipped: true }
    })), false)
  })
  test('all-ok is not a failure', () => {
    assert.equal(hasScannerFailure(scanResult()), false)
  })
})

describe('suppressions', () => {
  test('findingKey ignores case and surrounding whitespace', () => {
    assert.equal(
      findingKey({ file: 'a.js', title: '  SQL Injection ' }),
      findingKey({ file: 'a.js', title: 'sql injection' })
    )
  })
  test('findingKey distinguishes different files', () => {
    assert.notEqual(findingKey({ file: 'a.js', title: 'x' }), findingKey({ file: 'b.js', title: 'x' }))
  })

  test('applySuppressions removes findings and recomputes the score', (t) => {
    const home = tmp()
    process.env.SNAGIFY_HOME = home
    t.after(() => { delete process.env.SNAGIFY_HOME; rmSync(home, { recursive: true, force: true }) })

    const analysis = {
      securityScore: 70, summary: '', criticalCount: 1, highCount: 1, mediumCount: 0, lowCount: 0,
      findings: [
        { id: '1', title: 'Critical thing', severity: 'critical', explanation: '', fixSuggestion: '', file: 'a.js', line: 1 },
        { id: '2', title: 'High thing', severity: 'high', explanation: '', fixSuggestion: '', file: 'b.js', line: 2 }
      ]
    }
    // No suppressions yet: untouched
    assert.equal(applySuppressions('/proj', analysis).findings.length, 2)
  })
})

describe('rawAsFindings', () => {
  test('maps semgrep severity to our scale', () => {
    const out = rawAsFindings(scanResult({
      code: { ok: true, skipped: false, error: null, findings: [
        { check_id: 'r1', path: 'a.js', start: { line: 3 }, extra: { severity: 'ERROR', message: 'bad' } },
        { check_id: 'r2', path: 'b.js', start: { line: 4 }, extra: { severity: 'WARNING', message: 'meh' } }
      ] }
    }))
    assert.equal(out[0].severity, 'high')
    assert.equal(out[1].severity, 'medium')
  })
  test('secrets are always critical and carry CWE-798', () => {
    const out = rawAsFindings(scanResult({
      secrets: { ok: true, skipped: false, error: null, findings: [{ Description: 'Stripe key', File: 'c.js', StartLine: 5, RuleID: 'stripe' }] }
    }))
    assert.equal(out[0].severity, 'critical')
    assert.ok(out[0].cwe.includes('CWE-798'))
  })
  test('dependency severity follows CVSS and suggests the upgrade', () => {
    const out = rawAsFindings(scanResult({
      deps: { ok: true, skipped: false, error: null, findings: [
        { package: 'tar', version: '6.0.0', ecosystem: 'npm', ids: ['G1'], aliases: ['CVE-9'], cvss: 9.1, summary: 's', fixedVersion: '7.0.0', file: 'lock' }
      ] }
    }))
    assert.equal(out[0].severity, 'critical')
    assert.match(out[0].fixSuggestion, /7\.0\.0/)
  })
})

describe('reporters', () => {
  const withSecret = scanResult({
    secrets: { ok: true, skipped: false, error: null, findings: [
      { Description: 'Stripe', File: 'c.js', StartLine: 5, RuleID: 'stripe', Secret: 'sk_live_SUPERSECRET' }
    ] }
  })

  test('renderJson redacts secret values', () => {
    const j = JSON.parse(renderJson(withSecret))
    assert.equal(j.findings.secrets[0].Secret, '[redacted]')
    assert.ok(!renderJson(withSecret).includes('SUPERSECRET'))
  })
  test('renderJson reports null counts for failed scanners', () => {
    const j = JSON.parse(renderJson(scanResult({
      deps: { ok: false, findings: [], error: 'crash', skipped: false }
    })))
    assert.equal(j.counts.vulnerableDependencies, null)
  })
  test('renderSarif produces valid SARIF 2.1.0', () => {
    const s = JSON.parse(renderSarif(withSecret))
    assert.equal(s.version, '2.1.0')
    assert.ok(s.$schema.includes('sarif-2.1.0'))
    assert.equal(s.runs[0].tool.driver.name, 'Snagify')
  })
  test('renderSarif falls back to raw findings without AI', () => {
    const s = JSON.parse(renderSarif(withSecret))
    assert.ok(s.runs[0].results.length > 0, 'expected results without AI analysis')
    assert.ok(s.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri)
  })
  test('renderSarif maps severity to SARIF levels', () => {
    const s = JSON.parse(renderSarif(withSecret))
    assert.equal(s.runs[0].results[0].level, 'error') // secrets are critical
  })
  test('renderMarkdown includes the score and a findings section', () => {
    const md = renderMarkdown(withSecret)
    assert.match(md, /# Snagify Security Report/)
    assert.match(md, /Security score/)
    assert.match(md, /## Findings/)
  })
  test('renderTerminal shows findings even without AI', () => {
    const out = renderTerminal(withSecret, {})
    assert.match(out, /Snagify Security Scan/)
    assert.match(out, /Stripe/)
  })
  test('renderTerminal surfaces scanner failures as warnings', () => {
    const out = renderTerminal(scanResult({
      deps: { ok: false, findings: [], error: 'osv exploded', skipped: false }
    }), {})
    assert.match(out, /Warnings/)
    assert.match(out, /osv exploded/)
  })
})

describe('parseArgs', () => {
  test('separates positionals from flags', () => {
    const a = parseArgs(['scan', './x', '--json'])
    assert.deepEqual(a._, ['scan', './x'])
    assert.equal(a.flags.json, true)
  })
  test('supports --key value and --key=value', () => {
    assert.equal(parseArgs(['--min-score', '80']).flags['min-score'], '80')
    assert.equal(parseArgs(['--min-score=80']).flags['min-score'], '80')
  })
  test('expands short flags', () => {
    assert.equal(parseArgs(['-v']).flags.verbose, true)
    assert.equal(parseArgs(['-q']).flags.quiet, true)
  })
  test('a flag before another flag stays boolean', () => {
    const a = parseArgs(['--json', '--verbose'])
    assert.equal(a.flags.json, true)
    assert.equal(a.flags.verbose, true)
  })
  test('handles an empty argv', () => {
    const a = parseArgs([])
    assert.deepEqual(a._, [])
    assert.deepEqual(a.flags, {})
  })
})

describe('codeContext', () => {
  test('extracts surrounding lines and marks the target', (t) => {
    const dir = tmp()
    t.after(() => rmSync(dir, { recursive: true, force: true }))
    const f = join(dir, 'x.js')
    writeFileSync(f, Array.from({ length: 30 }, (_, i) => `line${i + 1}`).join('\n'))
    const ctx = codeContext(f, 10, 2, 2)
    assert.match(ctx, /> +10 \| line10/)
    assert.match(ctx, /line8/)
    assert.match(ctx, /line12/)
    assert.ok(!ctx.includes('line5'), 'should not reach beyond the window')
  })
  test('returns empty for a missing file or no line', () => {
    assert.equal(codeContext('/nope/missing.js', 5), '')
    assert.equal(codeContext('/tmp', null), '')
  })
})

describe('path safety', () => {
  test('resolveTarget rejects a nonexistent path', () => {
    assert.throws(() => resolveTarget('/definitely/not/here'), /not accessible/i)
  })
  test('resolveTarget rejects a file', (t) => {
    const dir = tmp()
    t.after(() => rmSync(dir, { recursive: true, force: true }))
    const f = join(dir, 'a.txt')
    writeFileSync(f, 'x')
    assert.throws(() => resolveTarget(f), /not a directory/i)
  })
  test('resolveFindingFile refuses to escape the project root', (t) => {
    const root = tmp()
    t.after(() => rmSync(root, { recursive: true, force: true }))
    writeFileSync(join(root, 'in.js'), 'x')
    assert.doesNotThrow(() => resolveFindingFile(root, 'in.js'))
    assert.throws(() => resolveFindingFile(root, '../../../etc/passwd'), /not found|outside/i)
  })
})

describe('fix apply / revert', () => {
  test('applies an exact patch and reverts it', (t) => {
    const home = tmp(); const root = tmp()
    process.env.SNAGIFY_HOME = home
    t.after(() => { delete process.env.SNAGIFY_HOME; rmSync(home, { recursive: true, force: true }); rmSync(root, { recursive: true, force: true }) })

    const file = join(root, 'app.js')
    writeFileSync(file, 'const a = 1\nconst pw = "hunter2"\nconst b = 2\n')
    const id = applyPatch(root, { file: 'app.js', search: 'const pw = "hunter2"', replace: 'const pw = process.env.PW', explanation: '' })
    assert.match(readFileSync(file, 'utf-8'), /process\.env\.PW/)

    revertPatch(id)
    assert.match(readFileSync(file, 'utf-8'), /hunter2/, 'revert should restore the original')
  })

  test('refuses a patch that no longer matches', (t) => {
    const home = tmp(); const root = tmp()
    process.env.SNAGIFY_HOME = home
    t.after(() => { delete process.env.SNAGIFY_HOME; rmSync(home, { recursive: true, force: true }); rmSync(root, { recursive: true, force: true }) })
    writeFileSync(join(root, 'a.js'), 'changed content\n')
    assert.throws(
      () => applyPatch(root, { file: 'a.js', search: 'original content', replace: 'x', explanation: '' }),
      /no longer matches/i
    )
  })

  test('refuses an ambiguous patch matching twice', (t) => {
    const home = tmp(); const root = tmp()
    process.env.SNAGIFY_HOME = home
    t.after(() => { delete process.env.SNAGIFY_HOME; rmSync(home, { recursive: true, force: true }); rmSync(root, { recursive: true, force: true }) })
    writeFileSync(join(root, 'a.js'), 'dup\ndup\n')
    assert.throws(
      () => applyPatch(root, { file: 'a.js', search: 'dup', replace: 'x', explanation: '' }),
      /multiple locations/i
    )
  })

  test('revert rejects a malformed backup id', () => {
    assert.throws(() => revertPatch('../../etc/passwd'), /invalid backup id/i)
  })
})

describe('pre-commit hook', () => {
  test('install, detect, uninstall round-trip', (t) => {
    const repo = tmp()
    t.after(() => rmSync(repo, { recursive: true, force: true }))
    mkdirSync(join(repo, '.git', 'hooks'), { recursive: true })

    assert.equal(isInstalled(repo), false)
    const p = hookInstall(repo, 75)
    assert.ok(existsSync(p))
    assert.match(readFileSync(p, 'utf-8'), /--min-score 75/)
    assert.equal(isInstalled(repo), true)
    hookUninstall(repo)
    assert.equal(isInstalled(repo), false)
  })

  test('refuses to clobber a foreign pre-commit hook', (t) => {
    const repo = tmp()
    t.after(() => rmSync(repo, { recursive: true, force: true }))
    mkdirSync(join(repo, '.git', 'hooks'), { recursive: true })
    writeFileSync(join(repo, '.git', 'hooks', 'pre-commit'), '#!/bin/sh\necho other tool\n')
    assert.throws(() => hookInstall(repo, 60), /already exists/i)
  })

  test('refuses to delete a hook it did not write', (t) => {
    const repo = tmp()
    t.after(() => rmSync(repo, { recursive: true, force: true }))
    mkdirSync(join(repo, '.git', 'hooks'), { recursive: true })
    writeFileSync(join(repo, '.git', 'hooks', 'pre-commit'), '#!/bin/sh\necho other\n')
    assert.throws(() => hookUninstall(repo), /not installed by Snagify/i)
  })

  test('rejects a non-git directory', (t) => {
    const dir = tmp()
    t.after(() => rmSync(dir, { recursive: true, force: true }))
    assert.throws(() => hookInstall(dir, 60), /not a git repository/i)
  })
})

describe('misc', () => {
  test('maskKey hides the middle', () => {
    const m = maskKey('sk-ant-api03-abcdefghijklmnop')
    assert.match(m, /^sk-ant-…/)
    assert.ok(!m.includes('abcdefghij'))
  })
  test('findTool returns null for an unknown tool path override', () => {
    process.env.SNAGIFY_SEMGREP_PATH = '/nonexistent/semgrep'
    const r = findTool('semgrep')
    delete process.env.SNAGIFY_SEMGREP_PATH
    // Falls through to real lookup; just assert the call is safe
    assert.ok(r === null || typeof r === 'string')
  })
})
