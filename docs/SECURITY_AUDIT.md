# Security audit: public demo

**Scope:** the public dashboard at `https://98-81-148-190.sslip.io/` (nginx → `webui.py --mode mock`),
the dashboard source in this repository, and the landing page at `https://apexstudiollc.com/treasury/`.
**Date:** 2026-11-03 (UTC). **Method:** black-box probing from outside with non-destructive, read-only
requests, plus a white-box review of `webui.py`, `store.py` and the dashboard JavaScript.

The demo moves fake money in a mock sandbox, so the realistic risks are **availability** (someone
breaking the demo for everyone) and **hygiene** (what the deployment says about the product's
standards). No finding exposes secrets, real accounts or code execution.

## Summary

| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | High | Anyone can lock all three public demo accounts and take the demo down | Fixed in code (`TREASURY_PUBLIC_DEMO=1`) |
| 2 | Medium | All visitors share one demo: one person's acts or reset change everyone's screen | Fixed in code (private sandbox per visitor) |
| 3 | Medium | No rate limiting: sign-in spam, session floods and audit-log growth | Fixed in `deploy/` (nginx `limit_req`) + session cap |
| 4 | Low | Origin check accepts any `Origin` on the deployed build | Fixed in code (`TREASURY_PUBLIC_ORIGIN`) |
| 5 | Low | Session cookie is missing `Secure` | Fixed in code |
| 6 | Low | No `Strict-Transport-Security` | Fixed in code + nginx |
| 7 | Info | `Server: nginx/1.28.3 (Ubuntu)` discloses version and OS | Fixed in `deploy/` (`server_tokens off`) |
| 8 | Info | Any `Host` header is served | Fixed in code + nginx `server_name` |
| 9 | Info | No `Permissions-Policy` / `Cross-Origin-*-Policy` headers | Fixed in code |
| 10 | Info | Deployed code differs from `main` | Deploy from a tagged commit |
| 11 | Info | Let's Encrypt cert expires 2027-02-01 | Confirm the certbot renewal timer |

## What is already solid

* **TLS:** TLS 1.2 and 1.3 only (1.0/1.1 refused), valid Let's Encrypt certificate, HTTP → HTTPS `301`.
* **Network surface:** only ports 22, 80 and 443 answer; the app port (8080) is not reachable from outside.
  SSH accepts **public keys only** (no passwords).
* **Headers:** a strict CSP (`default-src 'none'`, no inline script), `X-Frame-Options: DENY`,
  `nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`.
* **Session and CSRF:** `HttpOnly; SameSite=Strict` cookie, a per-session CSRF token checked in constant
  time on every state change, a fresh session on sign-in (no fixation), 15-minute idle and 4-hour
  absolute expiry. No CORS headers are sent, so other sites cannot read the token.
* **Access control:** every API route returns `401` without a signed-in session; the signer must be the
  signed-in approver; acts must run in order.
* **Input handling:** 64 KB body cap, JSON-only bodies, field length checks; unsupported methods return
  `501`/`405`; no path traversal, dotfiles, status pages or directory listings.
* **Output handling:** the dashboard escapes every server value before it reaches `innerHTML`; secret
  fields (digests, payee fingerprints, PIN hashes, lockout state) are stripped from JSON responses.
* **Auth errors:** unknown ids and wrong PINs give the same message with equalised timing (no account
  enumeration).

## Findings

### 1. High: demo account lockout takes the demo down

The store locks an approver after 5 wrong PINs, doubles the wait with each further batch of 5 (up to
24 h) and never resets the count. That is correct for real money, but the demo PINs are published and
the three accounts are shared by every visitor. About 30 wrong guesses per account lock all three for a
day, and **Reset demo** needs a signed-in user, so the demo stays down until the process restarts.
Wrong PINs typed on approval cards count too.

**Fix:** with `TREASURY_PUBLIC_DEMO=1`, the published demo PINs are checked in constant time *before*
any store is touched, both at sign-in and on card signing. A stranger's guesses never reach the
lockout counter. Correct sign-ins are still verified by the sandbox's own audit store, and a failed
guess boots nothing.

### 2. Medium: one shared demo for every visitor

`webui.py` holds a single `DemoSession`. Two visitors at once see each other's acts, and anyone can
press **Reset demo** and wipe someone else's run mid-presentation. The event log also shows which
approver did what.

**Fix:** in public demo mode each signed-in visitor gets a private mock sandbox (its own mock bank,
agent and throwaway database). Reset closes only your own sandbox. Sandboxes close and their files are
deleted on sign-out or expiry, and `TREASURY_MAX_DEMOS` caps how many run at once, evicting the least
recently used idle one first.

### 3. Medium: no rate limiting

A 40-request burst was answered without a single `429`. Unthrottled, an attacker can:

* hammer `/api/login`, where each failure is written to the HMAC-chained audit log (disk growth);
* load `/` without a cookie in a loop, where each request allocates a session that lives 15 minutes
  (memory growth);
* tie up the single-threaded app server.

**Fix:** [`deploy/nginx-treasury-demo.conf`](../deploy/nginx-treasury-demo.conf) limits sign-in and
signing to 10/min per IP, the API to 10/s and pages to 5/s, caps connections per IP, allow-lists the
routes and methods, and adds timeouts. The app now caps anonymous sessions at 5,000, evicting the
oldest first.

### 4. Low: Origin check accepts any origin

A sign-in posted with `Origin: https://evil.example` and a valid CSRF token reached the credential
check. The deployed build appears to have relaxed `_same_origin` to work behind nginx. The CSRF token
and `SameSite=Strict` still stop real cross-site attacks, so this is a defence-in-depth gap.

**Fix:** set `TREASURY_PUBLIC_ORIGIN=https://<host>`. Behind the proxy, only that exact origin may
post: `http://` and other origins get `403`. The Host allow-list gains the public host, so no other
relaxation is needed.

### 5–9. Low and info: cookie, HSTS, banner, Host, extra headers

With `TREASURY_PUBLIC_ORIGIN` on `https`, the cookie carries `Secure` and the app sends
`Strict-Transport-Security`. Every response also gets `Permissions-Policy`,
`Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Resource-Policy: same-origin`. The nginx
config turns off `server_tokens`, and the app refuses unknown `Host` headers with `403`.

### 10–11. Deployment hygiene

* The running build differs from `main` (origin handling and on-page PINs). Deploy from a tag so what
  is audited is what runs.
* The certificate is valid until **2027-02-01**. Confirm renewal with `systemctl list-timers | grep certbot`
  and `sudo certbot renew --dry-run`.

## Landing page (`apexstudiollc.com/treasury/`)

A static page with no forms, cookies or user input. It has no inline event handlers, and its
`<meta http-equiv="Content-Security-Policy">` pins the single inline script by SHA-256 hash. It
allows only Google Fonts, YouTube thumbnails and the `youtube-nocookie.com` player. Every new-tab link
uses `rel="noopener"`. **If you edit the inline script, update the hash** or the page's animations stop.

## Deploying the fixes

```bash
# on the server
cd /opt/treasury-controller && git fetch && git checkout <tag-or-main>

sudo cp deploy/treasury-proxy.conf /etc/nginx/snippets/treasury-proxy.conf
sudo cp deploy/nginx-treasury-demo.conf /etc/nginx/sites-available/treasury-demo
sudo sed -i 's/demo.example.com/98-81-148-190.sslip.io/g' /etc/nginx/sites-available/treasury-demo
sudo ln -sf /etc/nginx/sites-available/treasury-demo /etc/nginx/sites-enabled/treasury-demo
sudo nginx -t && sudo systemctl reload nginx

sudo useradd --system --no-create-home --shell /usr/sbin/nologin treasury 2>/dev/null || true
sudo cp deploy/treasury-demo.service /etc/systemd/system/
sudo sed -i 's#https://demo.example.com#https://98-81-148-190.sslip.io#' /etc/systemd/system/treasury-demo.service
sudo systemctl daemon-reload && sudo systemctl enable --now treasury-demo
```

Remove any older nginx site or process that served the dashboard, so only one is running.

**Verify afterwards:**

```bash
curl -sI https://98-81-148-190.sslip.io/ | grep -iE 'strict-transport|set-cookie|server:'
# expect: HSTS present, cookie has "Secure", Server shows "nginx" with no version
for i in $(seq 1 15); do curl -s -o /dev/null -w '%{http_code} ' -X POST https://98-81-148-190.sslip.io/api/login; done; echo
# expect: 403s, then 429s once the sign-in limit kicks in
```

## Not covered

To keep the live demo usable, the following were deliberately *not* tested: wrong-PIN lockout
against the real demo accounts (confirmed in code instead), actions that would change the shared demo
state, load or denial-of-service testing, OS patch level, and cloud firewall rules beyond what is
visible from outside.

The new behaviour is covered by `tests/test_public_demo.py` (6 tests). The full suite (287 tests),
`pyflakes` and `bandit` pass.
