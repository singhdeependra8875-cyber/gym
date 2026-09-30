# GymDesk Cloudflare + D1 migration

This version keeps the existing `public/index.html` UI and replaces the Express/better-sqlite3 server with a Cloudflare Worker + D1 backend.

## 1. Keep the current main branch safe

From the existing GymDesk project:

    git checkout main
    git pull
    git checkout -b cloudflare-d1

Do not delete the existing `server.js` yet. It remains useful for the local Node/SQLite version.

## 2. Replace/add these files

- Add `worker.js`
- Add `wrangler.jsonc`
- Add `migrations/0001_init.sql`
- Replace `package.json` with the Cloudflare version in this folder
- Keep the existing `public/` folder unchanged

The Worker expects two Cloudflare secrets:

- `OWNER_PASSWORD` = choose a new strong gym-owner password; do not commit it.
- `SESSION_SECRET` = a separate random secret; do not commit it.

Set them with Wrangler:

    npx wrangler secret put OWNER_PASSWORD
    npx wrangler secret put SESSION_SECRET

When prompted, enter the values without quotes.

## 3. Install Wrangler

    npm install

## 4. Apply the D1 schema

    npx wrangler d1 migrations apply gymdesk-db --remote

It should apply migration `0001_init.sql` and create the `kv` table.

## 5. Test locally

    npx wrangler dev

Open the local URL Wrangler prints. The browser UI should load. Local D1 is separate from production unless you explicitly use remote mode, so this is safe for testing.

## 6. Deploy

    npx wrangler deploy

The Worker will use the existing `gymdesk-db` database through the `DB` binding.

## 7. Test production

Test in this order:

1. Login with the new `OWNER_PASSWORD`.
2. Add a member.
3. Refresh.
4. Edit the member.
5. Renew the member.
6. Check payment history.
7. Check dashboard collection.
8. Test WhatsApp.
9. Test Messages templates.
10. Test Settings persistence.
11. Export backup.
12. Log out and log in again.

Do not test Restore until the normal save/load path is confirmed.
