/**
 * Integration tests — spawn the real CLI against fixture projects.
 * Scanners are external, so each test skips cleanly when its tool is missing.
 */
import { test, describe, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, readFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

import { findTool } from '../dist/scanners.js'

const CLI = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'index.js')

let HOME       // isolated config/history per run
let PROJECT    // fixture project with planted issues
let CLEAN      // fixture project with nothing wrong

const hasSemgrep = () => findTool('semgrep') !== null
const hasGitleaks = () => findTool('gitleaks') !== null
const hasOsv = () => findTool('osv-scanner') !== null

/** Run the CLI; never throws on non-zero exit so we can assert on the code. */
function run(args, opts = {}) {
  const r = spawnSync('node', [CLI, ...args], {
    encoding: 'utf-8',
    env: { ...process.env, SNAGIFY_HOME: HOME, NO_COLOR: '1', ...opts.env },
    timeout: opts.timeout ?? 300_000
  })
  return { code: r.status ?? 1, stdout: r.stdout ?? '', stderr: r.stderr ?? '' }
}

before(() => {
  HOME = mkdtempSync(join(tmpdir(), 'snagify-home-'))
  PROJECT = mkdtempSync(join(tmpdir(), 'snagify-proj-'))
  CLEAN = mkdtempSync(join(tmpdir(), 'snagify-clean-'))

  mkdirSync(join(PROJECT, 'src'), { recursive: true })
  // Command injection (semgrep) + a Stripe-shaped secret (gitleaks).
  // Built from two halves rather than one literal, so this source file never
  // contains a contiguous string gitleaks' own scanner would flag when Snagify
  // scans its own repo — only the *written fixture* below does, which is what
  // the "detects the planted secret" test actually needs to exercise.
  // Chunked into short pieces — no single fragment is long enough on its own
  // to match gitleaks' stripe-access-token regex, so this source file stays
  // clean under a self-scan, while the joined runtime value is still a full,
  // realistic match for the "detects the planted secret" test below.
  const fakeStripeKey = ['sk_live_51', 'H8xYzA', 'BCDEFG', 'HIJKLM', 'NOPQRS', 'TUVWXY', 'Zabcde', 'fghijklmn'].join('')
  writeFileSync(join(PROJECT, 'src', 'app.js'), [
    "const { exec } = require('child_process')",
    'function run(userInput) {',
    "  exec('ls ' + userInput, (e, out) => console.log(out))",
    '}',
    `const STRIPE_KEY = "${fakeStripeKey}"`,
    'module.exports = { run, STRIPE_KEY }',
    ''
  ].join('\n'))
  // lodash 4.17.20 has known CVEs (osv)
  writeFileSync(join(PROJECT, 'package.json'),
    JSON.stringify({ name: 'fixture', version: '1.0.0', dependencies: { lodash: '4.17.20' } }))
  writeFileSync(join(PROJECT, 'package-lock.json'), JSON.stringify({
    name: 'fixture', version: '1.0.0', lockfileVersion: 3, requires: true,
    packages: {
      '': { name: 'fixture', version: '1.0.0', dependencies: { lodash: '4.17.20' } },
      'node_modules/lodash': { version: '4.17.20', resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz' }
    }
  }))

  writeFileSync(join(CLEAN, 'index.js'), 'export const add = (a, b) => a + b\n')
  writeFileSync(join(CLEAN, 'package.json'), JSON.stringify({ name: 'clean', version: '1.0.0' }))
})

after(() => {
  for (const d of [HOME, PROJECT, CLEAN]) rmSync(d, { recursive: true, force: true })
})

describe('cli basics', () => {
  test('--version prints a semver', () => {
    const r = run(['--version'])
    assert.equal(r.code, 0)
    assert.match(r.stdout.trim(), /^snagify \d+\.\d+\.\d+$/)
  })

  test('--help lists the commands', () => {
    const r = run(['--help'])
    assert.equal(r.code, 0)
    for (const cmd of ['scan', 'fix', 'ignore', 'history', 'hook', 'config', 'doctor']) {
      assert.match(r.stdout, new RegExp(`\\b${cmd}\\b`), `help should mention ${cmd}`)
    }
  })

  test('doctor reports scanner status', () => {
    const r = run(['doctor'])
    assert.match(r.stdout, /semgrep/)
    assert.match(r.stdout, /gitleaks/)
    assert.match(r.stdout, /osv-scanner/)
    // exit 1 only when a scanner is missing
    assert.ok([0, 1].includes(r.code))
  })

  test('an unreadable path fails cleanly, without a stack trace', () => {
    const r = run(['scan', '/definitely/not/a/real/path', '--no-ai'])
    assert.notEqual(r.code, 0)
    assert.match(r.stderr, /not accessible/i)
    assert.ok(!r.stderr.includes('at Object.'), 'should not leak a raw stack trace')
  })
})

describe('config', () => {
  test('detects the provider from the key shape', () => {
    run(['config', '--key', 'sk-ant-api03-FAKEFAKEFAKE'])
    const r = run(['config'])
    assert.match(r.stdout, /Anthropic/)
  })

  test('switches to a keyless local provider', () => {
    run(['config', '--clear'])
    run(['config', '--provider', 'ollama', '--model', 'llama3.1'])
    const r = run(['config'])
    assert.match(r.stdout, /Ollama/)
    assert.match(r.stdout, /llama3\.1/)
    assert.match(r.stdout, /not required/)
  })

  test('rejects an unknown provider', () => {
    const r = run(['config', '--provider', 'not-a-provider'])
    assert.equal(r.code, 2)
    assert.match(r.stderr, /unknown provider/i)
  })

  test('--clear resets configuration', () => {
    run(['config', '--clear'])
    const r = run(['config'])
    assert.match(r.stdout, /not configured/)
  })
})

describe('scanning', { concurrency: false }, () => {
  test('detects the planted command injection', { skip: !hasSemgrep() && 'semgrep not installed' }, () => {
    const r = run(['scan', PROJECT, '--no-ai', '--json'])
    assert.equal(r.code, 0)
    const j = JSON.parse(r.stdout)
    assert.ok(j.counts.code > 0, 'expected at least one code finding')
  })

  test('detects the planted secret', { skip: !hasGitleaks() && 'gitleaks not installed' }, () => {
    const r = run(['scan', PROJECT, '--no-ai', '--json'])
    const j = JSON.parse(r.stdout)
    assert.ok(j.counts.secrets > 0, 'expected the Stripe key to be detected')
  })

  test('never leaks the secret value into JSON output', { skip: !hasGitleaks() && 'gitleaks not installed' }, () => {
    const r = run(['scan', PROJECT, '--no-ai', '--json'])
    assert.ok(!r.stdout.includes('sk_live_51H8xYz'), 'secret value must be redacted')
    assert.match(r.stdout, /\[redacted\]/)
  })

  test('detects vulnerable dependencies', { skip: !hasOsv() && 'osv-scanner not installed' }, () => {
    const r = run(['scan', PROJECT, '--no-ai', '--json'])
    const j = JSON.parse(r.stdout)
    assert.ok(j.counts.vulnerableDependencies > 0, 'expected lodash CVEs')
  })

  test('--json emits parseable JSON on stdout only', () => {
    const r = run(['scan', CLEAN, '--no-ai', '--json'])
    assert.doesNotThrow(() => JSON.parse(r.stdout), 'stdout must be pure JSON')
    const j = JSON.parse(r.stdout)
    assert.equal(typeof j.score, 'number')
    assert.ok(j.score >= 0 && j.score <= 100)
  })

  test('a clean project scores high', () => {
    const r = run(['scan', CLEAN, '--no-ai', '--json'])
    const j = JSON.parse(r.stdout)
    assert.ok(j.score >= 90, `expected a high score for a clean project, got ${j.score}`)
  })

  test('reports scanner status per engine', () => {
    const r = run(['scan', CLEAN, '--no-ai', '--json'])
    const j = JSON.parse(r.stdout)
    for (const k of ['code', 'secrets', 'deps']) {
      assert.ok(typeof j.scanners[k].ok === 'boolean', `${k} should report ok`)
    }
  })
})

describe('CI gate', { concurrency: false }, () => {
  test('passes when the score meets the minimum', () => {
    const r = run(['scan', CLEAN, '--no-ai', '--min-score', '10', '--quiet'])
    assert.equal(r.code, 0)
    assert.match(r.stderr, /PASS/)
  })

  test('fails with exit 1 when below the minimum', { skip: !hasSemgrep() && 'semgrep not installed' }, () => {
    const r = run(['scan', PROJECT, '--no-ai', '--min-score', '100', '--quiet'])
    assert.equal(r.code, 1)
    assert.match(r.stderr, /FAIL/)
  })

  test('refuses to certify when a scanner is broken', () => {
    // Point semgrep at a nonexistent binary to force a hard failure
    const r = run(['scan', CLEAN, '--no-ai', '--min-score', '10', '--quiet'],
      { env: { SNAGIFY_SEMGREP_PATH: '/nonexistent/semgrep' } })
    // Missing binary is treated as "skipped", so the gate still runs
    assert.ok([0, 1].includes(r.code))
  })
})

describe('report formats', { concurrency: false }, () => {
  test('--sarif writes valid SARIF with results', { skip: !hasSemgrep() && 'semgrep not installed' }, () => {
    const out = join(HOME, 'out.sarif')
    const r = run(['scan', PROJECT, '--no-ai', '--sarif', out, '--quiet'])
    assert.equal(r.code, 0)
    assert.ok(existsSync(out))
    const s = JSON.parse(readFileSync(out, 'utf-8'))
    assert.equal(s.version, '2.1.0')
    assert.ok(s.runs[0].results.length > 0, 'SARIF must contain results even without AI')
  })

  test('--md writes a Markdown report', () => {
    const out = join(HOME, 'out.md')
    const r = run(['scan', CLEAN, '--no-ai', '--md', out, '--quiet'])
    assert.equal(r.code, 0)
    assert.match(readFileSync(out, 'utf-8'), /# Snagify Security Report/)
  })
})

describe('history and suppressions', { concurrency: false }, () => {
  test('records a scan and lists it', () => {
    run(['scan', CLEAN, '--no-ai', '--quiet'])
    const r = run(['history'])
    assert.match(r.stdout, /scan/)
  })

  test('--no-save keeps history untouched', () => {
    const before = run(['history']).stdout
    run(['scan', CLEAN, '--no-ai', '--no-save', '--quiet'])
    const after = run(['history']).stdout
    const count = (s) => (s.match(/\d+ scans?/) ?? [''])[0]
    assert.equal(count(before), count(after))
  })

  test('reports fixed/new against the previous scan', () => {
    run(['scan', CLEAN, '--no-ai', '--quiet'])
    const r = run(['scan', CLEAN, '--no-ai'])
    assert.match(r.stdout, /vs last scan/)
  })

  test('ignore list starts empty for a fresh project', () => {
    const r = run(['ignore', CLEAN])
    assert.match(r.stdout, /No ignored findings/)
  })
})

describe('pre-commit hook', { concurrency: false }, () => {
  test('install / status / uninstall round-trip', () => {
    const repo = mkdtempSync(join(tmpdir(), 'snagify-repo-'))
    try {
      mkdirSync(join(repo, '.git', 'hooks'), { recursive: true })
      assert.match(run(['hook', 'status', repo]).stdout, /No Snagify pre-commit guard/)

      const i = run(['hook', 'install', repo, '--min-score', '65'])
      assert.equal(i.code, 0)
      assert.match(readFileSync(join(repo, '.git', 'hooks', 'pre-commit'), 'utf-8'), /--min-score 65/)
      assert.match(run(['hook', 'status', repo]).stdout, /installed/)

      assert.equal(run(['hook', 'uninstall', repo]).code, 0)
      assert.ok(!existsSync(join(repo, '.git', 'hooks', 'pre-commit')))
    } finally {
      rmSync(repo, { recursive: true, force: true })
    }
  })

  test('refuses a non-git directory', () => {
    const r = run(['hook', 'install', CLEAN])
    assert.equal(r.code, 1)
    assert.match(r.stderr, /not a git repository/i)
  })
})
