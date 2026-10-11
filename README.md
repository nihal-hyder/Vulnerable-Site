# Northfield Supply Co. &mdash; Deliberately Vulnerable Demo Store

A realistic-looking e-commerce site (outdoor/camping gear) built specifically
as a **target for testing pentesting tools** &mdash; AI-driven or otherwise.
It ships with a separate admin panel where you can switch each of 7 built-in
vulnerabilities on or off individually, so you can verify a tool both finds
a vulnerability when it's open *and* correctly reports it as fixed when it's
closed.

> ⚠️ **This application is intentionally insecure.** Do not deploy it to a
> public server, a shared network, or anywhere reachable by anyone other
> than you. Run it only on `localhost` / an isolated VM / an isolated
> container, for authorized testing of your own tools against your own
> machine. See **Safety & scope** below.

---

## Quick start

Requires Node.js 18+ (tested on Node 22). No native build tools needed &mdash;
everything is pure JavaScript (SQLite runs via WASM, not a native addon).

```bash
npm install
npm start
```

Then open:

- **Storefront:** http://localhost:3000/
- **Pentest admin panel:** http://localhost:3000/admin (default login `admin` / `admin123`)

The app creates its own SQLite database file on first run
(`data/store.sqlite`) with demo products, users, reviews and orders already
seeded. Delete the files in `data/` at any time to reset to a clean state.

### Demo storefront accounts

| Username     | Password         | Notes                      |
|--------------|------------------|-----------------------------|
| `demo`       | `trailblazer`    | regular customer, has orders |
| `junebug`    | `pinecone88`     | regular customer, has orders |
| `storeadmin` | `S0uthRidge!2024`| flagged as admin in the DB (not related to the pentest panel) |

You can also just click "Create an account" and register your own.

### Pentest admin panel

The control panel at `/admin` is separate from the storefront accounts above
and from the `storeadmin` user. It's the dashboard *you* use to arm/disarm
vulnerabilities while you test a scanner or tool against the site.

- Default login: **admin / admin123**
- Override with environment variables before starting the app:
  ```bash
  ADMIN_PANEL_USER=myuser ADMIN_PANEL_PASSWORD='something-long' npm start
  ```
- Every vulnerability starts **ON** (open) by default on a fresh database.
- Flip any individual switch, or use "Open all vulnerabilities" / "Close all
  vulnerabilities" for a clean before/after comparison run.
- State is written to `data/vuln-state.json` and persists across restarts.

---

## What's inside

```
server.js            Express app entrypoint
routes/
  store.js            Storefront routes (shop, cart, auth, account, uploads)
  admin.js             Pentest admin panel routes
lib/
  db.js                 SQLite (sql.js/WASM) layer + demo data seed
  vulnState.js           Vulnerability on/off state + definitions
  ftpControl.js           Starts/stops the real anonymous FTP fixture
  util.js                 Small helpers (HTML escaping, price formatting)
views/                  EJS templates (storefront + admin panel)
public/                 CSS (no build step, no external JS framework)
fixtures/               Fake .env / backup.zip content for the exposure demo
ftp-root/               Files served over the FTP fixture
uploads/                 Where avatar uploads land (gitignored, auto-created)
data/                   SQLite DB file + vuln toggle state (gitignored)
```

The storefront is server-rendered (Express + EJS), backed by a real SQL
engine (`sql.js`, SQLite compiled to WebAssembly &mdash; no native compilation
step, so `npm install` works on any machine with Node). This matters for the
SQL injection demo: queries genuinely run against a real SQLite engine, so
real injection payloads behave the way they would against a real app.

---

## The 7 vulnerabilities

All of these are toggled from `/admin`. "Vulnerable" below describes the
behavior when the switch is **ON**; "Fixed" describes the switch **OFF**.

### 1. SQL Injection &mdash; `CWE-89`
**Where:** `POST /login`, `GET /search?q=`
**Vulnerable:** Both endpoints build SQL by string concatenation.
  - Login: try username `storeadmin' --` with any password &mdash; comments out
    the password check and logs you in as that account.
  - Search: try `q='` to trigger a raw SQL error (error-based injection
    surface), or craft a `UNION SELECT` payload against the 8-column
    `products` table.
**Fixed:** Both use parameter-bound queries (`?` placeholders via sql.js's
  prepared statements).

### 2. Stored XSS &mdash; `CWE-79`
**Where:** `POST /product/:id/review`, rendered on `GET /product/:id`
**Vulnerable:** Review bodies are rendered back to every visitor without
  HTML-escaping. Post a review containing `<script>alert(document.cookie)</script>`
  and reload the product page.
**Fixed:** Review bodies are HTML-escaped before rendering.

### 3. IDOR (Insecure Direct Object Reference) &mdash; `CWE-639`
**Where:** `GET /account/orders/:id`
**Vulnerable:** Orders are looked up by numeric ID only, with no check that
  the order belongs to the logged-in user. Log in as `demo`, place an order,
  then edit the order ID in the URL to view another customer's order.
**Fixed:** The order's `user_id` is compared against the session user; a
  mismatch returns `403`.

### 4. Insecure / Unrestricted File Upload &mdash; `CWE-434`
**Where:** `POST /account/avatar`
**Vulnerable:** Any file extension/content-type is accepted as an "avatar"
  and served back from `/uploads/<filename>` with its original extension and
  content-type, inline. Upload an `.html` file containing a `<script>` tag,
  then open the returned URL directly in a browser.
**Fixed:** Only `image/png`, `image/jpeg`, `image/gif` are accepted
  (checked via sniffed mimetype, not the filename), and files are always
  renamed to a random name with a safe extension.

### 5. CSRF (Cross-Site Request Forgery) &mdash; `CWE-352`
**Where:** `POST /account/email`
**Vulnerable:** The "change account email" form has no anti-CSRF token, so
  a form on another origin can submit it on behalf of a logged-in victim
  (standard cookie-riding CSRF).
**Fixed:** A per-session token is required and validated server-side.

### 6. Sensitive Data Exposure &mdash; `CWE-200`
**Where:** `GET /.env`, `GET /backup.zip`
**Vulnerable:** Both paths are directly reachable and return fixture
  content that looks like a leaked environment file and a database backup
  containing fake customer data.
**Fixed:** Both return `404`.

### 7. Open / Anonymous FTP Service &mdash; `CWE-284`
**Where:** `ftp://127.0.0.1:2121` (a real, separate FTP server)
**Vulnerable:** A genuine FTP service (via [`ftp-srv`](https://www.npmjs.com/package/ftp-srv))
  starts alongside the web app and accepts **any** username/password as
  anonymous login, exposing a folder that mirrors site backups:
  ```
  ftp 127.0.0.1 2121
  # user: anonymous, password: anything
  ```
**Fixed:** The FTP service is stopped entirely; the port is closed and
  connection attempts are refused.

---

## Using this with an automated/AI pentesting tool

A typical test run:

1. `npm start`, confirm the storefront loads at `localhost:3000`.
2. Go to `/admin`, click **"Open all vulnerabilities"** for a baseline
   "fully vulnerable" run, and point your tool at `http://localhost:3000/`.
3. Record what your tool finds.
4. Click **"Close all vulnerabilities"**, re-run your tool, and confirm it
   now reports a clean result (or at least doesn't re-report the same 7
   issues).
5. For more granular testing, flip vulnerabilities on **one at a time** and
   confirm your tool correctly attributes each finding to the right issue
   (right CWE, right endpoint) rather than just noticing "something's
   different."

The admin panel also exposes `GET /admin/api/state` (JSON) if you want to
script around the current toggle state from your tool's test harness.

---

## Safety & scope

- **Never expose this outside your own machine.** There is no rate
  limiting, no WAF, and several of the toggles (especially the FTP service
  and file upload) are genuinely dangerous if reachable from the open
  internet or an untrusted network.
- The FTP service binds to `0.0.0.0` on port 2121 so tools on the same host
  or VM can reach it; if you run this inside a container/VM for isolation,
  keep that container/VM off any network you don't control.
- All "secrets" in `fixtures/env.demo` and `fixtures/backup.zip` are fake
  and generated for this project only &mdash; they are not real credentials
  for anything.
- Only use this against **your own tooling, on infrastructure you own or
  are authorized to test.** Don't repurpose the vulnerable code paths here
  against any other application.

---

## Resetting to a clean state

```bash
rm -f data/*.sqlite data/*.json
rm -f uploads/*
npm start
```

This regenerates the seed data and resets every vulnerability back to its
default (open) state.

---

## License

MIT. Built as a test fixture; not affiliated with any real outdoor gear
brand. "Northfield Supply Co." and all products are fictional.
