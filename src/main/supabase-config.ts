// ---------------------------------------------------------------------------
// Supabase project configuration
//
// 1. Create a free project at https://supabase.com/dashboard
// 2. Project Settings → API → copy the Project URL and anon/public key here
// 3. Run supabase/schema.sql in the SQL editor (creates the licenses table)
// 4. Deploy supabase/functions/lemonsqueezy-webhook (marks accounts licensed
//    after purchase) — see supabase/SETUP.md
//
// While these are empty, the app falls back to license-key activation.
// The anon key is safe to embed in the app — row-level security protects data.
// ---------------------------------------------------------------------------

export const SUPABASE_URL = ''
export const SUPABASE_ANON_KEY = ''

export const supabaseConfigured = (): boolean =>
  SUPABASE_URL.startsWith('https://') && SUPABASE_ANON_KEY.length > 20
