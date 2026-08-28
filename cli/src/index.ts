#!/usr/bin/env node
import { writeFileSync } from 'fs'
import { createInterface } from 'readline'
import { findTool, killActiveScans, resolveTarget, INSTALL_HINT, type Tool } from './scanners.js'
import { runScan, hasScannerFailure } from './scan.js'
import { renderJson, renderMarkdown, renderSarif, renderTerminal } from './report.js'
import { generateFix } from './ai.js'
import { applyPatch, renderDiff, revertPatch } from './fix.js'
import * as hook from './hook.js'
import {
  addSuppression, deleteScan, findEntry, getSuppressions, loadPayload,
  pruneHistory, readIndex, removeSuppression
} from './store.js'
import { activeModel, hasProvider, loadConfig, maskKey, resolveProvider, saveConfig } from './config.js'
import { detectProvider, PROVIDERS, testProvider, type ProviderId } from './providers.js'
import { bold, gray, green, red, scoreColor, Spinner, yellow, sevColor } from './ui.js'
import { parseArgs, str, num, type Args } from './args.js'

const VERSION = '1.0.0'

function ask(question: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stderr })
  return new Promise(res => rl.question(question, a => { rl.close(); res(a.trim()) }))
}

// ── help ────────────────────────────────────────────────────────────────────

const HELP = `
${bold('snagify')} ${gray('— one command, three scanners, one score')}

${bold('USAGE')}
  snagify [command] [path] [options]

${bold('COMMANDS')}
  scan [path]              Scan a project (default)
  fix [path]               Generate and apply AI fixes interactively
  ignore [path]            Manage suppressed findings
  history                  List past scans (--delete <id>, --clear)
  show <id>                Show a past scan in detail
  hook <install|uninstall|status> [path]
                           Manage the git pre-commit guard
  config                   Set AI provider/key/model (--test to verify)
  doctor                   Check that scanners are installed
  version                  Print version

${bold('SCAN OPTIONS')}
  --json                   Machine-readable JSON on stdout
  --sarif [file]           SARIF 2.1.0 (for GitHub code scanning)
  --md <file>              Write a Markdown report
  --min-score <n>          Exit 1 if the score is below n (CI gate)
  --scalability            Also assess what breaks under load
  --no-ai                  Skip AI entirely, use deterministic scoring
  --no-deep                Skip the deep code review pass (faster, cheaper)
  --no-code                Skip Semgrep
  --no-secrets             Skip Gitleaks
  --no-deps                Skip OSV
  --no-save                Do not record this scan in history
  -v, --verbose            Show full explanations and fixes
  -q, --quiet              Only errors and the final gate result

${bold('EXAMPLES')}
  snagify                              ${gray('# scan the current directory')}
  snagify scan ./api --scalability     ${gray('# include load-readiness analysis')}
  snagify scan . --min-score 80        ${gray('# CI gate')}
  snagify scan . --json > report.json  ${gray('# pipe results')}
  snagify scan . --sarif results.sarif ${gray('# upload to GitHub code scanning')}
  snagify fix .                        ${gray('# review and apply AI patches')}
  snagify hook install .               ${gray('# block risky commits')}

${bold('AI PROVIDERS')} ${gray('(any one enables AI features)')}
  ANTHROPIC_API_KEY        Claude
  OPENAI_API_KEY           GPT
  GOOGLE_API_KEY           Gemini ${gray('(free tier available)')}
  SNAGIFY_PROVIDER=ollama  Local models — code never leaves your machine
  SNAGIFY_API_KEY          Groq / OpenRouter / Together / any OpenAI-compatible

${bold('CONFIG')}
  SNAGIFY_MODEL            Override the model
  SNAGIFY_BASE_URL         Override the API base URL
  SNAGIFY_HOME             Override config dir (default ~/.snagify)
  NO_COLOR                 Disable colored output
`

// ── commands ────────────────────────────────────────────────────────────────


/** First run with no provider: ask, rather than silently degrading to a basic scan. */
async function ensureProvider(opts: { json: boolean; quiet: boolean; noAi: boolean }): Promise<void> {
  if (opts.noAi || hasProvider()) return
  const interactive = process.stdin.isTTY && process.stdout.isTTY && !opts.json && !opts.quiet
  if (!interactive) {
    process.stderr.write(`${yellow('!')} No AI provider configured — running a basic scan without AI analysis.\n`)
    process.stderr.write(gray(`  Set ANTHROPIC_API_KEY / OPENAI_API_KEY / GOOGLE_API_KEY, or run: snagify config\n\n`))
    return
  }
  process.stderr.write(`\n${bold('Snagify needs an AI provider for full analysis.')}\n`)
  process.stderr.write(gray('  With one: ranked findings, real explanations, fixes, deep code review.\n'))
  process.stderr.write(gray('  Without:  scanner counts and a heuristic score only.\n\n'))
  process.stderr.write(`  ${bold('1')}  Anthropic (Claude)      ${gray('sk-ant-…')}\n`)
  process.stderr.write(`  ${bold('2')}  OpenAI (GPT)            ${gray('sk-…')}\n`)
  process.stderr.write(`  ${bold('3')}  Google (Gemini)         ${gray('AIza…  free tier available')}\n`)
  process.stderr.write(`  ${bold('4')}  Ollama (local)          ${gray('no key, code never leaves your machine')}\n`)
  process.stderr.write(`  ${bold('5')}  Other OpenAI-compatible ${gray('Groq, OpenRouter, Together, LM Studio…')}\n`)
  process.stderr.write(`  ${bold('6')}  Skip\n\n`)
  const choice = (await ask('  Choose [1-6]: ')).trim()
  const map: Record<string, ProviderId> = { '1': 'anthropic', '2': 'openai', '3': 'google', '4': 'ollama', '5': 'openai-compatible' }
  const provider = map[choice]
  if (!provider) {
    process.stderr.write(gray('  Continuing without AI. Configure later with: snagify config\n\n'))
    return
  }
  const spec = PROVIDERS[provider]
  const cfg = loadConfig()
  cfg.provider = provider

  if (provider === 'ollama') {
    process.stderr.write(gray(`\n  Ollama runs locally — make sure it is installed and running (${spec.keyUrl}).\n`))
    const model = (await ask(`  Model [${spec.defaultModel}]: `)).trim()
    cfg.model = model || spec.defaultModel
    delete cfg.apiKey
  } else {
    if (provider === 'openai-compatible') {
      const base = (await ask('  Base URL (e.g. https://api.groq.com/openai/v1): ')).trim()
      if (!base) { process.stderr.write(gray('  Skipped.\n\n')); return }
      cfg.baseUrl = base
    } else if (spec.keyUrl) {
      process.stderr.write(gray(`\n  Get a key at ${spec.keyUrl}\n`))
    }
    const key = (await ask('  Paste your API key: ')).trim()
    if (!key) { process.stderr.write(gray('  Skipped.\n\n')); return }
    cfg.apiKey = key
    const model = (await ask(`  Model [${spec.defaultModel}]: `)).trim()
    cfg.model = model || spec.defaultModel
  }
  saveConfig(cfg)
  process.stderr.write(`  ${green('✓')} Saved to ~/.snagify/config.json ${gray('(owner-readable only)')}\n\n`)
}

async function cmdScan(args: Args): Promise<number> {
  const quiet = Boolean(args.flags.quiet)
  const json = Boolean(args.flags.json)
  const sarif = args.flags.sarif
  const target = resolveTarget(args._[0] ?? '.')
  const noAi = Boolean(args.flags['no-ai']) || args.flags.ai === false
  await ensureProvider({ json, quiet, noAi })
  const spinner = new Spinner()
  // Progress goes to stderr so --json stdout stays pipeable
  const showProgress = !quiet && !json

  const result = await runScan(target, {
    code: args.flags.code !== false && !args.flags['no-code'],
    secrets: args.flags.secrets !== false && !args.flags['no-secrets'],
    deps: args.flags.deps !== false && !args.flags['no-deps'],
    ai: !noAi,
    deep: !args.flags['no-deep'] && args.flags.deep !== false,
    scalability: Boolean(args.flags.scalability),
    save: !args.flags['no-save'],
    onProgress: (phase, msg) => {
      if (!showProgress) return
      if (phase.endsWith('-done')) spinner.succeed(msg)
      else if (phase.endsWith('-error')) spinner.fail(msg)
      else if (phase.endsWith('-skip')) spinner.skip(msg)
      else spinner.start(msg)
    }
  })
  spinner.stop()

  if (json) process.stdout.write(renderJson(result) + '\n')
  else if (!quiet) process.stdout.write(renderTerminal(result, { verbose: Boolean(args.flags.verbose) }) + '\n')

  if (sarif) {
    const file = typeof sarif === 'string' ? sarif : 'snagify.sarif'
    writeFileSync(file, renderSarif(result), 'utf-8')
    if (!quiet && !json) process.stderr.write(`${green('✓')} SARIF written to ${file}\n`)
  }
  const md = str(args.flags.md)
  if (md) {
    writeFileSync(md, renderMarkdown(result), 'utf-8')
    if (!quiet && !json) process.stderr.write(`${green('✓')} Markdown report written to ${md}\n`)
  }

  const minScore = num(args.flags['min-score'])
  if (minScore !== undefined) {
    // A gate cannot certify a score built on a crashed scanner
    if (hasScannerFailure(result)) {
      process.stderr.write(`${red('FAIL')}: a scanner failed, so the score cannot be trusted against min-score ${minScore}\n`)
      return 1
    }
    if (result.score < minScore) {
      process.stderr.write(`${red('FAIL')}: score ${result.score} is below the required minimum ${minScore}\n`)
      return 1
    }
    process.stderr.write(`${green('PASS')}: score ${result.score} meets the minimum ${minScore}\n`)
  }
  return 0
}

async function cmdFix(args: Args): Promise<number> {
  const target = resolveTarget(args._[0] ?? '.')
  if (!hasProvider()) {
    process.stderr.write(`${red('✗')} AI fixes need a provider. Run: snagify config --key <key>  ${gray('(or --provider ollama for local)')}\n`)
    return 2
  }
  const spinner = new Spinner()
  spinner.start('Scanning…')
  const result = await runScan(target, { scalability: false, save: false, onProgress: (p, m) => { if (!p.endsWith('-done')) spinner.start(m) } })
  spinner.stop()

  const fixable = (result.analysis?.findings ?? []).filter(f => f.file)
  if (!fixable.length) {
    process.stdout.write(`${green('✓')} Nothing to fix — no findings with an associated file.\n`)
    return 0
  }
  process.stdout.write(`\n${bold(`${fixable.length} fixable finding${fixable.length === 1 ? '' : 's'}`)}\n\n`)

  const auto = Boolean(args.flags.yes)
  let applied = 0
  for (const f of fixable) {
    process.stdout.write(`${sevColor(f.severity, f.severity.toUpperCase())} ${bold(f.title)}\n`)
    process.stdout.write(gray(`  ${f.file}${f.line !== null ? `:${f.line}` : ''}\n`))
    spinner.start('Generating patch…')
    let patch
    try { patch = await generateFix(target, f) } catch (e) {
      spinner.fail(`Could not generate a patch: ${String(e).replace(/^Error: /, '')}`)
      continue
    }
    spinner.stop()
    if (patch.explanation) process.stdout.write(gray(`  ${patch.explanation}\n`))
    process.stdout.write('\n' + renderDiff(patch, { red, green, gray }) + '\n\n')

    const answer = auto ? 'y' : (await ask(`  Apply this patch? [y/N/q] `)).toLowerCase()
    if (answer === 'q') break
    if (answer !== 'y') { process.stdout.write(gray('  skipped\n\n')); continue }
    try {
      const backupId = applyPatch(target, patch)
      applied++
      process.stdout.write(`  ${green('✓ applied')} ${gray(`(undo: snagify fix --revert ${backupId})`)}\n\n`)
    } catch (e) {
      process.stdout.write(`  ${red('✗')} ${String(e).replace(/^Error: /, '')}\n\n`)
    }
  }
  process.stdout.write(`${bold(`${applied} patch${applied === 1 ? '' : 'es'} applied`)}${applied ? gray(' — re-run snagify to verify') : ''}\n`)
  return 0
}

function cmdHistory(args: Args): number {
  const del = str(args.flags.delete)
  if (del) {
    const entry = findEntry(del)
    if (!entry) { process.stderr.write(`No scan found matching "${del}"\n`); return 1 }
    deleteScan(entry.id)
    process.stdout.write(`${green('✓')} Deleted scan ${gray(entry.id.slice(0, 8))} (${entry.folderName})\n`)
    return 0
  }
  if (args.flags.clear) {
    const all = readIndex()
    for (const e of all) deleteScan(e.id)
    process.stdout.write(`${green('✓')} Cleared ${all.length} scan${all.length === 1 ? '' : 's'}.\n`)
    return 0
  }
  const list = readIndex()
  if (!list.length) { process.stdout.write(gray('No scans recorded yet.\n')); return 0 }
  process.stdout.write(`\n${bold(`${list.length} scan${list.length === 1 ? '' : 's'}`)}\n\n`)
  for (const e of list) {
    const d = new Date(e.date).toLocaleString()
    process.stdout.write(
      `  ${gray(e.id.slice(0, 8))}  ${scoreColor(e.securityScore, String(e.securityScore).padStart(3))}  ${bold(e.folderName.padEnd(22).slice(0, 22))} ${gray(d)}\n`
    )
  }
  process.stdout.write('\n' + gray('  snagify show <id>            for detail\n'))
  process.stdout.write(gray('  snagify history --delete <id>  to remove\n'))
  return 0
}

function cmdShow(args: Args): number {
  const id = args._[0]
  if (!id) { process.stderr.write('Usage: snagify show <id>\n'); return 2 }
  const entry = findEntry(id)
  if (!entry) { process.stderr.write(`No scan found matching "${id}"\n`); return 1 }
  const payload = loadPayload(entry.id)
  process.stdout.write(`\n${bold(entry.folderName)}  ${scoreColor(entry.securityScore, `${entry.securityScore}/100`)}\n`)
  process.stdout.write(gray(`${entry.folderPath}\n${new Date(entry.date).toLocaleString()}\n\n`))
  if (entry.summary) process.stdout.write(`${entry.summary}\n\n`)
  for (const f of payload.findings ?? []) {
    process.stdout.write(`  ${sevColor(f.severity, f.severity.toUpperCase().padEnd(8))} ${f.title}\n`)
    if (f.file) process.stdout.write(gray(`           ${f.file}${f.line !== null ? `:${f.line}` : ''}\n`))
  }
  if (payload.scalability) {
    const s = payload.scalability
    process.stdout.write(`\n  ${bold('Load readiness')} ${scoreColor(s.scalabilityScore, `${s.scalabilityScore}/100`)}\n`)
    for (const b of s.bottlenecks) process.stdout.write(`  ${sevColor(b.risk, b.risk.toUpperCase().padEnd(8))} ${b.title}\n`)
  }
  process.stdout.write('\n')
  return 0
}

async function cmdIgnore(args: Args): Promise<number> {
  const target = resolveTarget(args._[0] ?? '.')
  const list = getSuppressions(target)
  const removeKey = str(args.flags.remove)
  if (removeKey) {
    const next = removeSuppression(target, removeKey)
    process.stdout.write(`${green('✓')} Restored. ${next.length} still ignored.\n`)
    return 0
  }
  if (args.flags.clear) {
    for (const s of list) removeSuppression(target, s.key)
    process.stdout.write(`${green('✓')} Cleared ${list.length} suppression${list.length === 1 ? '' : 's'}.\n`)
    return 0
  }
  if (args.flags.add) {
    // Interactive: pick from the latest findings for this project
    const entry = readIndex().find(e => e.folderPath === target)
    if (!entry) { process.stderr.write('No scan recorded for this project yet — run `snagify scan` first.\n'); return 1 }
    const findings = loadPayload(entry.id).findings ?? []
    if (!findings.length) { process.stderr.write('No findings to ignore.\n'); return 1 }
    findings.forEach((f, i) => process.stdout.write(`  ${String(i + 1).padStart(2)}. ${sevColor(f.severity, f.severity.toUpperCase().padEnd(8))} ${f.title}\n`))
    const pick = Number(await ask('\n  Ignore which number? '))
    const chosen = findings[pick - 1]
    if (!chosen) { process.stderr.write('Invalid selection.\n'); return 1 }
    const next = addSuppression(target, chosen)
    process.stdout.write(`${green('✓')} Ignored "${chosen.title}". ${next.length} total.\n`)
    return 0
  }
  if (!list.length) { process.stdout.write(gray('No ignored findings for this project.\n')); return 0 }
  process.stdout.write(`\n${bold(`${list.length} ignored finding${list.length === 1 ? '' : 's'}`)}\n\n`)
  for (const s of list) {
    process.stdout.write(`  ${sevColor(s.severity, s.severity.toUpperCase().padEnd(8))} ${s.title}\n`)
    process.stdout.write(gray(`           ${s.file || '(no file)'}\n`))
    process.stdout.write(gray(`           restore: snagify ignore --remove "${s.key}"\n`))
  }
  process.stdout.write('\n')
  return 0
}

function cmdHook(args: Args): number {
  const action = args._[0] ?? 'status'
  const target = resolveTarget(args._[1] ?? '.')
  const minScore = num(args.flags['min-score']) ?? 60
  try {
    if (action === 'install') {
      const p = hook.install(target, minScore)
      process.stdout.write(`${green('✓')} Pre-commit guard installed at ${gray(p)} (min score ${minScore})\n`)
      process.stdout.write(gray('  Requires `snagify` on PATH. Bypass once with: git commit --no-verify\n'))
      return 0
    }
    if (action === 'uninstall') {
      hook.uninstall(target)
      process.stdout.write(`${green('✓')} Pre-commit guard removed.\n`)
      return 0
    }
    process.stdout.write(hook.isInstalled(target)
      ? `${green('✓')} Pre-commit guard is installed.\n`
      : `${gray('−')} No Snagify pre-commit guard in this repo.\n`)
    return 0
  } catch (e) {
    process.stderr.write(`${red('✗')} ${String(e).replace(/^Error: /, '')}\n`)
    return 1
  }
}

async function cmdConfig(args: Args): Promise<number> {
  const key = str(args.flags.key)
  const model = str(args.flags.model)
  const provider = str(args.flags.provider) as ProviderId | undefined
  const baseUrl = str(args.flags['base-url'])

  if (args.flags.clear) { saveConfig({}); process.stdout.write(`${green('✓')} Config cleared.\n`); return 0 }

  if (key || model || provider || baseUrl) {
    const cfg = loadConfig()
    if (provider) {
      if (!PROVIDERS[provider]) {
        process.stderr.write(`${red('✗')} Unknown provider "${provider}". Options: ${Object.keys(PROVIDERS).join(', ')}\n`)
        return 2
      }
      cfg.provider = provider
    }
    if (key) {
      cfg.apiKey = key
      // Infer the provider from the key shape unless one was given
      if (!provider) {
        const guessed = detectProvider(key)
        if (guessed) cfg.provider = guessed
      }
    }
    if (model) cfg.model = model
    if (baseUrl) cfg.baseUrl = baseUrl
    saveConfig(cfg)
    const active = resolveProvider()
    process.stdout.write(`${green('✓')} Saved${active ? ` — using ${bold(PROVIDERS[active.provider].label)} / ${activeModel()}` : ''}\n`)
    return 0
  }

  if (args.flags.test) {
    const active = resolveProvider()
    if (!active) { process.stderr.write(`${yellow('!')} No provider configured.\n`); return 1 }
    process.stderr.write(gray(`  Testing ${PROVIDERS[active.provider].label} (${activeModel()})…\n`))
    const { ok, detail } = await testProvider(active)
    process.stdout.write(ok ? `${green('✓')} Provider reachable and responding.\n` : `${red('✗')} ${detail}\n`)
    return ok ? 0 : 1
  }

  const active = resolveProvider()
  process.stdout.write(`\n  ${gray('Provider')}  ${active ? PROVIDERS[active.provider].label : yellow('not configured')}\n`)
  process.stdout.write(`  ${gray('Model')}     ${activeModel()}\n`)
  const keyLabel = !active ? yellow('not set')
    : !PROVIDERS[active.provider].needsKey ? gray('not required')
    : active.apiKey ? green(maskKey(active.apiKey))
    : yellow('not set')
  process.stdout.write(`  ${gray('API key')}   ${keyLabel}\n`)
  if (active?.baseUrl) process.stdout.write(`  ${gray('Base URL')}  ${active.baseUrl}\n`)
  process.stdout.write(`\n  ${bold('Supported providers')}\n`)
  for (const [id, spec] of Object.entries(PROVIDERS)) {
    process.stdout.write(`    ${gray(id.padEnd(20))} ${spec.label}\n`)
  }
  process.stdout.write(`\n  ${gray('snagify config --key <key>                       auto-detects the provider')}\n`)
  process.stdout.write(`  ${gray('snagify config --provider ollama --model llama3.1  local, no key needed')}\n`)
  process.stdout.write(`  ${gray('snagify config --provider openai-compatible --base-url <url> --key <key>')}\n`)
  process.stdout.write(`  ${gray('snagify config --test                            verify it works')}\n\n`)
  return 0
}

function cmdDoctor(): number {
  process.stdout.write(`\n${bold('Snagify environment')}\n\n`)
  const tools: Tool[] = ['semgrep', 'gitleaks', 'osv-scanner']
  let missing = 0
  for (const t of tools) {
    const p = findTool(t)
    if (p) process.stdout.write(`  ${green('✓')} ${t.padEnd(14)} ${gray(p)}\n`)
    else { missing++; process.stdout.write(`  ${red('✗')} ${t.padEnd(14)} ${yellow('not found')} ${gray('— ' + INSTALL_HINT[t])}\n`) }
  }
  const active = resolveProvider()
  process.stdout.write(active
    ? `  ${green('✓')} ${'ai provider'.padEnd(14)} ${PROVIDERS[active.provider].label} ${gray(activeModel())}\n`
    : `  ${yellow('−')} ${'ai provider'.padEnd(14)} ${yellow('not configured — AI features disabled')}\n`)
  process.stdout.write(`  ${green('✓')} ${'node'.padEnd(14)} ${gray(process.version)}\n`)
  const pruned = pruneHistory()
  if (pruned) process.stdout.write(`\n  ${gray(`cleaned ${pruned} orphaned history file(s)`)}\n`)
  process.stdout.write(missing
    ? `\n  ${yellow(`${missing} scanner${missing === 1 ? '' : 's'} missing`)} ${gray('— those checks will be skipped')}\n\n`
    : `\n  ${green('All scanners ready.')}\n\n`)
  return missing ? 1 : 0
}

// ── main ────────────────────────────────────────────────────────────────────

async function main(): Promise<number> {
  const argv = process.argv.slice(2)
  const args = parseArgs(argv)

  if (args.flags.version || args._[0] === 'version') { process.stdout.write(`snagify ${VERSION}\n`); return 0 }
  if (args.flags.help || args._[0] === 'help') { process.stdout.write(HELP); return 0 }

  const known = ['scan', 'fix', 'ignore', 'history', 'show', 'hook', 'config', 'doctor']
  const cmd = known.includes(args._[0]) ? args._.shift()! : 'scan'

  switch (cmd) {
    case 'scan': return cmdScan(args)
    case 'fix': {
      const revert = str(args.flags.revert)
      if (revert) {
        const file = revertPatch(revert)
        process.stdout.write(`${green('✓')} Reverted ${file}\n`)
        return 0
      }
      return cmdFix(args)
    }
    case 'ignore': return cmdIgnore(args)
    case 'history': return cmdHistory(args)
    case 'show': return cmdShow(args)
    case 'hook': return cmdHook(args)
    case 'config': return cmdConfig(args)
    case 'doctor': return cmdDoctor()
    default: process.stdout.write(HELP); return 0
  }
}

process.on('SIGINT', () => { killActiveScans(); process.stderr.write('\nCancelled.\n'); process.exit(130) })

main()
  .then(code => process.exit(code))
  .catch(err => {
    process.stderr.write(`${red('✗')} ${String(err?.message ?? err).replace(/^Error: /, '')}\n`)
    process.exit(1)
  })
