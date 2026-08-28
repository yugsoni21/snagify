# Snagify account login — Supabase setup

The app supports two activation modes:

- **License key** (current default) — active while Supabase is not configured
- **Account login** — email/password accounts; a purchase on snagify.ca attaches
  a license to the account, and the app activates automatically on sign-in

Since snagify.ca is a static site (Hostinger), everything server-side lives in
Supabase's free tier. No changes to the website hosting are needed beyond a
"Buy" link to LemonSqueezy checkout.

## Steps

1. **Create the project** — https://supabase.com/dashboard → New project (free).

2. **Create the table** — SQL Editor → paste and run `schema.sql` from this folder.

3. **Point the app at your project** — Project Settings → API, then copy into
   `src/main/supabase-config.ts`:
   - Project URL → `SUPABASE_URL`
   - anon/public key → `SUPABASE_ANON_KEY` (safe to embed; RLS protects data)

   Rebuild the app. The login screen replaces the license-key screen automatically.

4. **Wire up purchases** — deploy the webhook so LemonSqueezy orders mark
   accounts licensed:

   ```sh
   npm i -g supabase
   supabase login
   supabase link --project-ref <your-project-ref>
   supabase secrets set LEMONSQUEEZY_WEBHOOK_SECRET=<signing secret>
   supabase functions deploy lemonsqueezy-webhook --no-verify-jwt
   ```

   In LemonSqueezy → Settings → Webhooks, add
   `https://<project-ref>.functions.supabase.co/lemonsqueezy-webhook`
   with events `order_created`, `subscription_cancelled`, `order_refunded`,
   and set the same signing secret.

5. **(Optional) Email confirmation** — Supabase Auth → Providers → Email.
   With confirmation ON, new users must click the email link before sign-in
   (the app shows the right message either way).

## Flow after setup

- Buyer purchases on snagify.ca → LemonSqueezy fires the webhook → license row
  becomes `active` for their email (account auto-created if they never registered).
- They install Snagify, sign in with that email → app finds the active license →
  fully activated. No key to type.
- Refunds/cancellations flip the license off on next app launch.
