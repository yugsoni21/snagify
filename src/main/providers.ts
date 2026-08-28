/**
 * Multi-provider LLM layer.
 *
 * One `complete()` call, several backends. Each provider uses its own native
 * JSON mode where it has one — that matters here because every prompt in this
 * tool demands strict JSON back.
 */

export type ProviderId = 'anthropic' | 'openai' | 'google' | 'ollama' | 'openai-compatible'

export interface ProviderConfig {
  provider: ProviderId
  apiKey?: string
  model?: string
  baseUrl?: string
}

export const PROVIDERS: Record<ProviderId, { label: string; needsKey: boolean; defaultModel: string; keyUrl?: string }> = {
  anthropic: { label: 'Anthropic (Claude)', needsKey: true, defaultModel: 'claude-sonnet-4-6', keyUrl: 'https://console.anthropic.com/settings/keys' },
  openai: { label: 'OpenAI (GPT)', needsKey: true, defaultModel: 'gpt-4o', keyUrl: 'https://platform.openai.com/api-keys' },
  google: { label: 'Google (Gemini)', needsKey: true, defaultModel: 'gemini-2.0-flash', keyUrl: 'https://aistudio.google.com/apikey' },
  ollama: { label: 'Ollama (local, private)', needsKey: false, defaultModel: 'llama3.1', keyUrl: 'https://ollama.com/download' },
  'openai-compatible': { label: 'OpenAI-compatible (Groq, OpenRouter, Together, LM Studio…)', needsKey: true, defaultModel: 'llama-3.3-70b-versatile' }
}

/** Infer the provider from a key's shape so users rarely have to say it. */
export function detectProvider(key: string): ProviderId | null {
  const k = key.trim()
  if (k.startsWith('sk-ant-')) return 'anthropic'
  if (k.startsWith('AIza')) return 'google'
  if (k.startsWith('gsk_')) return 'openai-compatible'   // Groq
  if (k.startsWith('sk-or-')) return 'openai-compatible' // OpenRouter
  if (k.startsWith('sk-')) return 'openai'
  return null
}

export class ProviderError extends Error {}

interface CompleteOpts {
  system: string
  user: string
  maxTokens: number
  /** Ask the backend for strict JSON when it supports it. */
  json?: boolean
}

const RETRYABLE = new Set([429, 500, 502, 503, 529])

async function post(url: string, headers: Record<string, string>, body: unknown, maxTokens: number): Promise<Response> {
  return fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
    // Long analyses on slow local models still need to finish
    signal: AbortSignal.timeout(Math.max(120_000, maxTokens * 60))
  })
}

/** Send one completion request, retrying transient failures. */
export async function complete(cfg: ProviderConfig, opts: CompleteOpts): Promise<string> {
  const model = cfg.model || PROVIDERS[cfg.provider].defaultModel
  const spec = PROVIDERS[cfg.provider]
  if (spec.needsKey && !cfg.apiKey) {
    throw new ProviderError(`${spec.label} needs an API key — configure it in Settings`)
  }

  for (let attempt = 0; attempt < 3; attempt++) {
    if (attempt > 0) await new Promise(r => setTimeout(r, attempt * 15_000))
    let res: Response
    try {
      res = await dispatch(cfg, model, opts)
    } catch (e) {
      if (attempt === 2) throw new ProviderError(`${spec.label} request failed: ${String(e).slice(0, 160)}`)
      continue
    }
    if (RETRYABLE.has(res.status) && attempt < 2) continue
    if (!res.ok) {
      const detail = (await res.text().catch(() => '')).slice(0, 240)
      throw new ProviderError(`${spec.label} API ${res.status}: ${detail}`)
    }
    const data = await res.json() as Record<string, unknown>
    const text = extractText(cfg.provider, data)
    if (!text) throw new ProviderError(`${spec.label} returned an empty response`)
    return text
  }
  throw new ProviderError(`${spec.label} rate limited after 3 attempts — try again shortly`)
}

function dispatch(cfg: ProviderConfig, model: string, opts: CompleteOpts): Promise<Response> {
  const { system, user, maxTokens, json } = opts
  switch (cfg.provider) {
    case 'anthropic':
      return post('https://api.anthropic.com/v1/messages', {
        'x-api-key': cfg.apiKey!,
        'anthropic-version': '2023-06-01',
        'anthropic-beta': 'prompt-caching-2024-07-31'
      }, {
        model,
        max_tokens: maxTokens,
        system: [{ type: 'text', text: system, cache_control: { type: 'ephemeral' } }],
        messages: [{ role: 'user', content: user }]
      }, maxTokens)

    case 'google': {
      const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(cfg.apiKey!)}`
      return post(url, {}, {
        systemInstruction: { parts: [{ text: system }] },
        contents: [{ role: 'user', parts: [{ text: user }] }],
        generationConfig: {
          maxOutputTokens: maxTokens,
          ...(json ? { responseMimeType: 'application/json' } : {})
        }
      }, maxTokens)
    }

    case 'ollama': {
      const base = (cfg.baseUrl || process.env.OLLAMA_HOST || 'http://localhost:11434').replace(/\/$/, '')
      return post(`${base}/api/chat`, {}, {
        model,
        messages: [{ role: 'system', content: system }, { role: 'user', content: user }],
        stream: false,
        ...(json ? { format: 'json' } : {}),
        options: { num_predict: maxTokens }
      }, maxTokens)
    }

    case 'openai':
    case 'openai-compatible': {
      const base = (cfg.baseUrl || 'https://api.openai.com/v1').replace(/\/$/, '')
      // Reasoning-era models renamed the token budget field
      const usesCompletionTokens = /^(o\d|gpt-5)/.test(model)
      return post(`${base}/chat/completions`, {
        Authorization: `Bearer ${cfg.apiKey}`
      }, {
        model,
        messages: [{ role: 'system', content: system }, { role: 'user', content: user }],
        ...(usesCompletionTokens ? { max_completion_tokens: maxTokens } : { max_tokens: maxTokens }),
        ...(json ? { response_format: { type: 'json_object' } } : {})
      }, maxTokens)
    }
  }
}

function extractText(provider: ProviderId, data: Record<string, unknown>): string {
  switch (provider) {
    case 'anthropic': {
      const content = data.content as Array<{ text?: string }> | undefined
      return content?.map(c => c.text ?? '').join('') ?? ''
    }
    case 'google': {
      const cand = (data.candidates as Array<{ content?: { parts?: Array<{ text?: string }> } }> | undefined)?.[0]
      return cand?.content?.parts?.map(p => p.text ?? '').join('') ?? ''
    }
    case 'ollama': {
      const msg = data.message as { content?: string } | undefined
      return msg?.content ?? ''
    }
    default: {
      const choices = data.choices as Array<{ message?: { content?: string } }> | undefined
      return choices?.[0]?.message?.content ?? ''
    }
  }
}

/** Quick reachability/auth check for `snagify doctor`. */
export async function testProvider(cfg: ProviderConfig): Promise<{ ok: boolean; detail: string }> {
  try {
    const text = await complete(cfg, {
      system: 'Reply with strict JSON only.',
      user: 'Return exactly: {"ok":true}',
      maxTokens: 64,
      json: true
    })
    return { ok: text.includes('ok'), detail: text.slice(0, 80).replace(/\s+/g, ' ') }
  } catch (e) {
    return { ok: false, detail: String(e instanceof Error ? e.message : e).slice(0, 160) }
  }
}
