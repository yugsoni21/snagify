import { existsSync, mkdirSync, readFileSync, writeFileSync, unlinkSync, statSync } from 'fs'
import { sep } from 'path'

const MARKER = '# snagify-pre-commit-guard'

function hookPath(repo: string): string {
  const gitDir = repo + sep + '.git'
  if (!existsSync(gitDir) || !statSync(gitDir).isDirectory()) {
    throw new Error('Not a git repository — run "git init" first, or point at the repo root')
  }
  const hooks = gitDir + sep + 'hooks'
  if (!existsSync(hooks)) mkdirSync(hooks, { recursive: true })
  return hooks + sep + 'pre-commit'
}

export function isInstalled(repo: string): boolean {
  try {
    const p = hookPath(repo)
    return existsSync(p) && readFileSync(p, 'utf-8').includes(MARKER)
  } catch { return false }
}

export function install(repo: string, minScore: number): string {
  const p = hookPath(repo)
  if (existsSync(p) && !readFileSync(p, 'utf-8').includes(MARKER)) {
    throw new Error('A pre-commit hook from another tool already exists — remove it first or chain manually')
  }
  const script = `#!/bin/sh
${MARKER}
# Blocks commits when the Snagify security score falls below ${minScore}.
# Bypass once with: git commit --no-verify
REPO_ROOT="$(git rev-parse --show-toplevel)"
snagify scan "$REPO_ROOT" --no-ai --min-score ${minScore} --quiet
if [ $? -ne 0 ]; then
  echo ""
  echo "Commit blocked by Snagify security gate."
  echo "Fix the findings, or bypass once with: git commit --no-verify"
  exit 1
fi
exit 0
`
  writeFileSync(p, script, { encoding: 'utf-8', mode: 0o755 })
  return p
}

export function uninstall(repo: string): void {
  const p = hookPath(repo)
  if (!existsSync(p)) return
  if (!readFileSync(p, 'utf-8').includes(MARKER)) {
    throw new Error('The existing pre-commit hook was not installed by Snagify — refusing to delete it')
  }
  unlinkSync(p)
}
