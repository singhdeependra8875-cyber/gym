# GymDesk

Owner-only gym membership manager using Node + Express + SQLite. It tracks members, plans, renewals, payment history, monthly collections and WhatsApp reminders.

## Run locally on Windows PowerShell
```powershell
npm install
$env:OWNER_PASSWORD="choose-a-strong-password"
npm start
```
Open `http://localhost:3000`.

## Environment variables
- `OWNER_PASSWORD` (required): owner login password.
- `SECRET` (optional): random secret used to sign login cookies. If omitted, a secret is derived from the password.
- `DB_PATH` (optional): SQLite file path. Default: `./gymdesk.db`.
- `PORT` (optional): default `3000`.

## Data safety
- Data is stored in SQLite and must live on persistent storage in production.
- The server keeps 30 daily snapshots in the same database.
- Use Settings > Export backup periodically and keep a copy outside the server.
- Restore validates the complete backup before replacing the current data.

## Production note
This is still an owner-only application, not a multi-user SaaS. For public deployment use HTTPS, persistent disk/volume storage, a strong password, and a separately configured `SECRET`.
