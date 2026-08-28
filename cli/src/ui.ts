/** Terminal formatting. Zero deps — raw ANSI, disabled when not a TTY or NO_COLOR is set. */

const enabled = process.stdout.isTTY && !process.env.NO_COLOR && process.env.TERM !== 'dumb'

const wrap = (open: number, close: number) => (s: string): string =>
  enabled ? `\x1b[${open}m${s}\x1b[${close}m` : s

export const bold = wrap(1, 22)
export const dim = wrap(2, 22)
export const red = wrap(31, 39)
export const green = wrap(32, 39)
export const yellow = wrap(33, 39)
export const blue = wrap(34, 39)
export const magenta = wrap(35, 39)
export const cyan = wrap(36, 39)
export const gray = wrap(90, 39)

export const SEVERITY_COLOR: Record<string, (s: string) => string> = {
  critical: red, high: (s) => wrap(38, 39)(`\x1b[38;5;208m${s}\x1b[39m`), medium: yellow, low: gray
}

/** High needs a 256-color orange; fall back cleanly when color is off. */
export function sevColor(sev: string, text: string): string {
  if (!enabled) return text
  switch (sev) {
    case 'critical': return `\x1b[31m${text}\x1b[39m`
    case 'high': return `\x1b[38;5;208m${text}\x1b[39m`
    case 'medium': return `\x1b[33m${text}\x1b[39m`
    default: return `\x1b[90m${text}\x1b[39m`
  }
}

export function scoreColor(score: number, text: string): string {
  if (score >= 71) return green(text)
  if (score >= 41) return yellow(text)
  return red(text)
}

/** Progress lines go to stderr so `--json` on stdout stays pipeable. */
export class Spinner {
  private frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
  private i = 0
  private timer: NodeJS.Timeout | null = null
  private label = ''

  start(label: string): void {
    this.label = label
    if (!process.stderr.isTTY) { process.stderr.write(`→ ${label}\n`); return }
    this.stop()
    this.timer = setInterval(() => {
      process.stderr.write(`\r${cyan(this.frames[this.i++ % this.frames.length])} ${this.label}   `)
    }, 80)
  }

  succeed(msg: string): void {
    this.stop()
    process.stderr.write(`${green('✓')} ${msg}\n`)
  }

  fail(msg: string): void {
    this.stop()
    process.stderr.write(`${red('✗')} ${msg}\n`)
  }

  skip(msg: string): void {
    this.stop()
    process.stderr.write(`${gray('−')} ${gray(msg)}\n`)
  }

  stop(): void {
    if (this.timer) { clearInterval(this.timer); this.timer = null }
    if (process.stderr.isTTY) process.stderr.write('\r\x1b[2K')
  }
}

export function hr(width = 56): string {
  return gray('─'.repeat(width))
}

/** Wrap prose to a width, indenting continuation lines. */
export function wrapText(text: string, width: number, indent = ''): string {
  const words = text.split(/\s+/)
  const lines: string[] = []
  let line = ''
  for (const w of words) {
    if (line && (line + ' ' + w).length > width) { lines.push(line); line = w }
    else line = line ? line + ' ' + w : w
  }
  if (line) lines.push(line)
  return lines.map((l, i) => (i === 0 ? l : indent + l)).join('\n')
}
