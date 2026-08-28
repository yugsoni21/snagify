// Supabase Edge Function: LemonSqueezy webhook → mark account licensed
//
// Deploy:  supabase functions deploy lemonsqueezy-webhook --no-verify-jwt
// Secrets: supabase secrets set LEMONSQUEEZY_WEBHOOK_SECRET=<from LS dashboard>
//
// In LemonSqueezy: Settings → Webhooks → add
//   https://<project-ref>.functions.supabase.co/lemonsqueezy-webhook
// with events: order_created, subscription_cancelled, order_refunded

import { createClient } from 'jsr:@supabase/supabase-js@2'

const HMAC_ALGO = { name: 'HMAC', hash: 'SHA-256' }

async function verifySignature(secret: string, payload: string, signature: string): Promise<boolean> {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), HMAC_ALGO, false, ['sign'])
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload))
  const expected = Array.from(new Uint8Array(mac)).map(b => b.toString(16).padStart(2, '0')).join('')
  return expected === signature.toLowerCase()
}

Deno.serve(async (req) => {
  const secret = Deno.env.get('LEMONSQUEEZY_WEBHOOK_SECRET') ?? ''
  const signature = req.headers.get('X-Signature') ?? ''
  const payload = await req.text()

  if (!secret || !(await verifySignature(secret, payload, signature))) {
    return new Response('Invalid signature', { status: 401 })
  }

  const event = JSON.parse(payload)
  const eventName: string = event?.meta?.event_name ?? ''
  const email: string = (event?.data?.attributes?.user_email ?? '').toLowerCase().trim()
  const orderId: string = String(event?.data?.id ?? '')
  if (!email) return new Response('No email in payload', { status: 400 })

  // Service-role client bypasses RLS — safe here, never shipped to clients
  const supabase = createClient(
    Deno.env.get('SUPABASE_URL')!,
    Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
  )

  if (eventName === 'order_created') {
    // O(1) lookup via RPC (see schema.sql) — auth.admin.listUsers() is paginated
    // and silently truncates past the first page, so never scan it for a match
    const { data: existingId, error: rpcError } = await supabase.rpc('get_user_id_by_email', { p_email: email })
    if (rpcError) return new Response(`User lookup failed: ${rpcError.message}`, { status: 500 })

    let userId = existingId as string | null
    if (!userId) {
      // No account yet — create one so the license has an owner; user sets password via email reset
      const { data: created, error } = await supabase.auth.admin.createUser({ email, email_confirm: true })
      if (error) return new Response(`Could not create user: ${error.message}`, { status: 500 })
      userId = created.user.id
    }

    // Idempotent: unique index on lemonsqueezy_order_id makes webhook retries no-ops
    const { error: upsertError } = await supabase.from('licenses').upsert(
      { user_id: userId, email, status: 'active', lemonsqueezy_order_id: orderId },
      { onConflict: 'lemonsqueezy_order_id', ignoreDuplicates: true }
    )
    if (upsertError) return new Response(`License write failed: ${upsertError.message}`, { status: 500 })
    return new Response('License created', { status: 200 })
  }

  if (eventName === 'subscription_cancelled' || eventName === 'order_refunded') {
    // Key deactivation to the specific order, matching how order_created keys the upsert —
    // an email match would wrongly deactivate every license the customer owns.
    // order_refunded: data.id IS the order id. subscription_cancelled: the order id
    // lives in attributes.order_id (data.id is the subscription id).
    const orderRef = eventName === 'order_refunded' ? orderId : String(event?.data?.attributes?.order_id ?? '')
    const update = { status: eventName === 'order_refunded' ? 'refunded' : 'cancelled', updated_at: new Date().toISOString() }
    const query = supabase.from('licenses').update(update)
    const { error: updError } = orderRef
      ? await query.eq('lemonsqueezy_order_id', orderRef)
      : await query.eq('email', email)  // last-resort fallback if the payload lacks an order id
    if (updError) return new Response(`Deactivation failed: ${updError.message}`, { status: 500 })
    return new Response('License deactivated', { status: 200 })
  }

  return new Response('Event ignored', { status: 200 })
})
