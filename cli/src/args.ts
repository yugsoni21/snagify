/** Dependency-free argv parsing, kept separate from the entry point so it is
 *  importable (and testable) without executing the CLI. */

export interface Args {
  _: string[]
  flags: Record<string, string | boolean>
}

const SHORT: Record<string, string> = { v: 'verbose', q: 'quiet', h: 'help', V: 'version', y: 'yes' }

export function parseArgs(argv: string[]): Args {
  const _: string[] = []
  const flags: Record<string, string | boolean> = {}
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a.startsWith('--')) {
      const [k, inline] = a.slice(2).split('=', 2)
      if (inline !== undefined) { flags[k] = inline; continue }
      const next = argv[i + 1]
      if (next && !next.startsWith('-')) { flags[k] = next; i++ } else flags[k] = true
    } else if (a.startsWith('-') && a.length > 1) {
      flags[SHORT[a.slice(1)] ?? a.slice(1)] = true
    } else _.push(a)
  }
  return { _, flags }
}

export const str = (v: string | boolean | undefined): string | undefined =>
  typeof v === 'string' ? v : undefined

export const num = (v: string | boolean | undefined): number | undefined => {
  const s = str(v)
  if (s === undefined) return undefined
  const n = Number(s)
  return Number.isFinite(n) ? n : undefined
}
