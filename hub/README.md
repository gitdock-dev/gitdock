# GitDock Hub

Central server for the GitDock multi-machine dashboard. Agents on each of your machines send git status snapshots to the Hub; you view all machines and sync issues in one place.

## Hosted vs self-host

| | Hosted (hub.gitdock.dev) | Self-host (this repo) |
|---|--------------------------|------------------------|
| **Infrastructure** | We manage hosting, SSL, backups, uptime | You deploy and maintain your own server |
| **Pricing** | One machine free; unlimited machines for $5/month | No cost to us; you pay only for your server |
| **Limits** | Free: 1 machine. Pro: unlimited | No limits; full control |
| **Support** | Billing and hosted service support | Community support; see main [README](../README.md) |

Prefer not to manage infrastructure? Use our [hosted Hub](https://hub.gitdock.dev). Otherwise, self-host by following the steps below.

## Quick start (local)

1. Copy `.env.example` to `.env` and set:
   - `HUB_SECRET` – long random string for signing session cookies (min 32 characters)
   - `HUB_DB_KEY` – (optional) key to encrypt the database at rest (min 32 characters). Omit for local dev.

2. Install and run:

```bash
cd hub
npm install
npm start
```

3. Open http://localhost:3848, click **Create account**, register with your email and a strong password (min 8 chars, one uppercase, one number), then sign in.

4. Go to **Settings**, click **Create key**, and copy the API key (shown once).

5. In your main GitDock folder (where `server.js` runs), open **Dashboard** → **Configure Hub** and set:
   - **Hub URL**: `http://localhost:3848` (or your deployed URL)
   - **API Key**: the key you copied
   - **Machine name**: e.g. "My Desktop"
   - **Send snapshot every**: 3 minutes (or 1–60)

6. Restart your local GitDock server (`node server.js`). It will send snapshots to the Hub automatically.

### Ver alterações locais antes de subir

Para testar melhorias no Hub antes de fazer deploy:

1. Rode o Hub localmente (`cd hub && npm start`).
2. Abra http://localhost:3848, crie conta ou faça login, vá em **Settings** e crie uma API key (ex.: label "Local dev").
3. No GitDock (app principal), use **Configure Hub** ou edite `config.json`: **Hub URL** = `http://localhost:3848`, **API Key** = a key criada no passo 2.
4. Reinicie o servidor do GitDock (`node server.js`). O snapshot será enviado ao Hub local.
5. No navegador, use Overview → clique na máquina para ver projetos, busca e filtros.

Para voltar a usar o Hub em produção (ex.: Render), altere de novo a URL e a API key no Configure Hub ou em `config.json`.

## Deploy on Render

1. Create a new **Web Service** on [Render](https://render.com).

2. Connect your repo and set:
   - **Root Directory**: `hub` (if the repo root is the parent of `hub`)
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`

3. In the service **Environment** tab, add:
   - `HUB_SECRET` – a long random string (e.g. `openssl rand -hex 32`)
   - `HUB_DB_KEY` – (optional) 32+ character key to encrypt the database
   - `PORT` – Render sets this automatically; you can leave it blank
   - For **hosted freemium** (optional): see [Lemon Squeezy (hosted Hub only)](#lemon-squeezy-hosted-hub-only) below.

4. Deploy. Your Hub URL will be `https://<your-service>.onrender.com`. You can add a custom domain (e.g. `hub.gitdock.dev`) in Render → Settings → Custom Domains.

5. In each machine’s GitDock dashboard, use **Configure Hub** and set the Hub URL to that URL and the API key you created in the Hub **Settings**.

## API key management

- **One key per user**: Use the same API key on all your machines (desktop, laptop, etc.).
- **Create key**: Settings → Generate new key → copy the key immediately (it is not shown again).
- **Revoke key**: If a key is compromised, revoke it in Settings and create a new one; then update `config.json` or the Configure Hub form on each machine.

## Local GitDock config (optional)

You can configure the Hub in `config.json` instead of the dashboard:

```json
{
  "accounts": { ... },
  "machine": {
    "id": "auto-generated-uuid",
    "name": "My Desktop"
  },
  "hub": {
    "url": "https://hub.gitdock.dev",
    "apiKey": "gdk_xxxxxxxxxxxxxxxxxxxx",
    "intervalMinutes": 3
  }
}
```

- `machine.id` is created automatically when the Hub is configured; you can leave it out.
- `machine.name` is the label shown for this machine on the Hub.
- `hub.intervalMinutes` must be between 1 and 60.

## Lemon Squeezy (hosted Hub only)

If you run the **hosted** Hub (e.g. hub.gitdock.dev) and want to offer Pro ($5/month, unlimited machines) via Lemon Squeezy:

1. **Lemon Squeezy**
   - Create a subscription product (e.g. "GitDock Hub Pro") at $5/month.
   - In **Webhooks**, add a webhook URL: `https://hub.gitdock.dev/api/webhooks/lemonsqueezy` (or your Hub URL).
   - Choose events: `subscription_created`, `subscription_updated`, `subscription_expired`, `subscription_cancelled`, `subscription_resumed`, `subscription_paused`.
   - Copy the **Signing secret** (used to verify webhook requests).

2. **Hub environment (e.g. Render)**
   - `LEMONSQUEEZY_WEBHOOK_SECRET` – the webhook signing secret from Lemon Squeezy.
   - `LEMONSQUEEZY_CHECKOUT_URL` – the full checkout URL for your product (so the Hub Settings "Upgrade to Pro" button can link to it).

3. **User matching**
   - The webhook matches subscriptions to Hub users by **customer email**. Users must use the same email when signing up at the Hub and when purchasing on Lemon Squeezy.

## Security

- **Dashboard**: sign up with email + password (bcrypt). Session cookie is httpOnly and signed; CSRF token for mutations.
- **Agents**: authenticate with API key in `Authorization: Bearer <key>` header.
- **Database**: optional encryption at rest via `HUB_DB_KEY` (better-sqlite3-multiple-ciphers; works on Windows, Linux, Mac). Passwords and API keys are hashed.
- Only git metadata is sent (branch, ahead/behind, last commit, dirty state). No source code, tokens, or passwords.
- Use HTTPS in production (Render provides it).

## Data stored

- **SQLite** (`hub.db`): users (email, password hash), API keys (hashed, per user), machines and snapshots (per user), audit log (login, register, key created/revoked). Optional encryption via `HUB_DB_KEY` (library: better-sqlite3-multiple-ciphers, prebuilt for Windows/Linux/Mac).
