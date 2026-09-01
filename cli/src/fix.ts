import { readFileSync, writeFileSync, existsSync, mkdirSync, unlinkSync } from 'fs'
import { join, sep } from 'path'
import { randomUUID } from 'crypto'
import { configDir } from './config.js'
import { resolveFindingFile } from './ai.js'
import type { FixPatch } from './types.js'

function backupDir(): string {
  const d = join(configDir(), 'backups')
  if (!existsSync(d)) mkdirSync(d, { recursive: true })
  return d
}

/** Apply a patch, saving the original so it can be reverted. */
export function applyPatch(rootPath: string, patch: FixPatch): string {
  const target = resolveFindingFile(rootPath, patch.file)
  const content = readFileSync(target, 'utf-8')
  const idx = content.indexOf(patch.search)
  if (idx === -1) throw new Error('Patch no longer matches the file — it may have changed since generation')
  // Refuse ambiguous patches rather than guessing which occurrence to edit
  if (content.indexOf(patch.search, idx + 1) !== -1) {
    throw new Error('Patch matches multiple locations — too ambiguous to apply safely')
  }
  const backupId = randomUUID()
  writeFileSync(join(backupDir(), `${backupId}.json`), JSON.stringify({ filePath: target, original: content }), 'utf-8')
  writeFileSync(target, content.slice(0, idx) + patch.replace + content.slice(idx + patch.search.length), 'utf-8')
  return backupId
}

export function revertPatch(backupId: string): string {
  // Strict UUID shape — hex and hyphens only, so no path separators can reach the sink below
  if (!/^[0-9a-f-]{36}$/i.test(backupId)) throw new Error('Invalid backup id')
  const p = backupDir() + sep + backupId + '.json'
  if (!existsSync(p)) throw new Error('Backup not found — cannot undo')
  const { filePath, original } = JSON.parse(readFileSync(p, 'utf-8')) as { filePath: string; original: string }
  writeFileSync(filePath, original, 'utf-8')
  unlinkSync(p)
  return filePath
}

/** Unified-diff style preview for the terminal. */
export function renderDiff(patch: FixPatch, color: { red: (s: string) => string; green: (s: string) => string; gray: (s: string) => string }): string {
  const lines: string[] = []
  for (const l of patch.search.split('\n')) lines.push(color.red(`  - ${l}`))
  for (const l of patch.replace.split('\n')) lines.push(color.green(`  + ${l}`))
  return lines.join('\n')
}
