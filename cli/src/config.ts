import { homedir } from 'os'
import { join } from 'path'
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from 'fs'
import { detectProvider, PROVIDERS, type ProviderConfig, type ProviderId } from './providers.js'

export interface Config {
  provider?: ProviderId
  apiKey?: string
  model?: string
  baseUrl?: string
  minScore?: number
}

const DIR = process.env.SNAGIFY_HOME || join(homedir(), '.snagify')
const CONFIG_PATH = join(DIR, 'config.json')

export function configDir(): string {
  if (!existsSync(DIR)) mkdirSync(DIR, { recursive: true, mode: 0o700 })
  return DIR
}

export function loadConfig(): Config {
  try { return JSON.parse(readFileSync(CONFIG_PATH, 'utf-8')) as Config } catch { return {} }
}

export function saveConfig(cfg: Config): void {
  configDir()
  writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2), 'utf-8')
  // Holds an API key — keep it owner-readable only
  try { chmodSync(CONFIG_PATH, 0o600) } catch { /* best effort */ }
}

/** Env vars win over stored config, so CI never needs a config file. */
export function resolveProvider(): ProviderConfig | null {
  const stored = loadConfig()
  const envProvider = process.env.SNAGIFY_PROVIDER?.trim() as ProviderId | undefined
  const envModel = process.env.SNAGIFY_MODEL?.trim()
  const envBase = process.env.SNAGIFY_BASE_URL?.trim()

  // Provider-specific env keys, checked in a predictable order
  const envKeys: Array<[ProviderId, string | undefined]> = [
    ['anthropic', process.env.ANTHROPIC_API_KEY],
    ['openai', process.env.OPENAI_API_KEY],
    ['google', process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY],
    ['openai-compatible', process.env.SNAGIFY_API_KEY]
  ]

  if (envProvider && PROVIDERS[envProvider]) {
    const key = envKeys.find(([p]) => p === envProvider)?.[1] || process.env.SNAGIFY_API_KEY || stored.apiKey
    if (!PROVIDERS[envProvider].needsKey || key) {
      return { provider: envProvider, apiKey: key?.trim(), model: envModel || stored.model, baseUrl: envBase || stored.baseUrl }
    }
  }
  for (const [provider, key] of envKeys) {
    if (key?.trim()) return { provider, apiKey: key.trim(), model: envModel || stored.model, baseUrl: envBase || stored.baseUrl }
  }
  // Ollama needs no key, so an explicit stored choice is enough
  if (stored.provider) {
    if (!PROVIDERS[stored.provider].needsKey || stored.apiKey) {
      return { provider: stored.provider, apiKey: stored.apiKey, model: envModel || stored.model, baseUrl: envBase || stored.baseUrl }
    }
  }
  if (stored.apiKey) {
    const guessed = detectProvider(stored.apiKey) ?? 'anthropic'
    return { provider: guessed, apiKey: stored.apiKey, model: envModel || stored.model, baseUrl: envBase || stored.baseUrl }
  }
  return null
}

export function hasProvider(): boolean {
  return resolveProvider() !== null
}

export function activeModel(): string {
  const p = resolveProvider()
  return p ? (p.model || PROVIDERS[p.provider].defaultModel) : '—'
}

export function maskKey(key: string): string {
  if (key.length <= 12) return '••••'
  return key.slice(0, 7) + '…' + key.slice(-4)
}
