# Day-1 Production Readiness Plan

**Project:** `treasury-controller` — Airwallex adaptive treasury agent
**Scan date:** 2026-10-23
**Scan basis:** every Python module, fixture, SQLite schema, HTTP route, and embedded UI asset in the tree; the passing test suite; and a direct inspection of the bundled database. There is no git history, so the working tree is the source of truth.

**Tree measured:** 28 Python modules (7,326 lines excluding tests), 6 test modules, 3 fixture files, no deployment artifacts (`Dockerfile`, `pyproject.toml`, `requirements.txt`, CI config all absent).
**Runtime verified:** `.venv/bin/python -m pytest` → **250 passed** on CPython 3.14.8. The only non-default database index is `one_live_payout_per_invoice` (`store.py:386-387`), confirmed by inspecting `state/mock/20261019T073357Z-74e83f.db`.

This plan does **not** repeat the findings already fixed in `AUDIT_PASS3_2026-10-23.md` §6 (S20–S33): dashboard sign-in, schema-object verification by SQL text, invoice-identity derivation, Airwallex host allowlisting, payout identity, settled-conversion ceiling re-binding, unresolved lookup handling, expired-card adoption, and in-transaction payee-pin audit rows are already in the tree. The gaps below are what remains.

> **Implementation status (2026-10-23):** #02 (funded execution and deferral rescheduling), #13 (approval-card facts), #14 (poll-safe signing), #15-lite (halt/stale banners and disabled actions), and #01-lite (explicit mock mode and honest labels) are implemented and covered by tests. Line references below are from the pre-change scan; the tree now has 254 passing tests.

**Priority key:** **P0 Blocker** = do not put real money or real users through this path. **P1 High** = launch-week incident or failed audit. **P2 Polish** = visible friction or scale degradation, safe to schedule after P0/P1.

---

## Pillar 1 — Core Feature Completeness & Mock Eradication

### 01 · The dashboard permanently boots a mock bank

**Priority:** P0 Blocker
**Location:** `webui.py:170-198` (`_boot` constructs `MockAirwallex`, forces `mode="mock"`, sets operator `"demo.operator"`, seeds demo identities), `webui.py:634` (hardcoded “Mock sandbox” pill), `webui.py:715` (demo footer), `webui.py:853` (loopback server).
**Day-1 risk:** Every path into the dashboard is a demo path. `MockAirwallex` is constructed unconditionally at `webui.py:173-175`; `open_store(..., mode="mock", ...)` at `:179` writes to `state/mock`; `seed_mock_database` and `seed_mock_payees` at `:187-189` enrol demo approvers and pin payees. Point this at production and operators still see a fake bank, fake balances, and fixture counterparties. There is no way to operate the real ledger from the UI, so the “product” cannot be used on launch day at all.
**Exact fix:**
1. Add a single `Runtime` factory in `runtime.py`: `build_runtime(settings, mode, cycle_id) -> Runtime` holding `client`, `store`, `simulator`, `screener`, `agent`. Make `demo.py` and `webui.py` both call it; delete the duplicated wiring.
2. In `_boot`, branch on an explicit mode: `demo` starts `MockAirwallex` and seeds; `live` constructs `AirwallexClient(settings.base_url, settings.client_id, settings.api_key)`, calls `open_store(settings, mode="live", cycle_id=...)`, uses `settings.operator`, and **never imports or seeds demo data**.
3. Gate both seeds behind `if mode == "demo"` and move them out of `_boot` so live cannot reach them even by a mistaken flag.
4. Add `--mode {live,demo}` to the `webui.py` argparse block and refuse `--mode live` unless the startup checks in #19 pass.
5. Put `mode` and `company` into the state payload (`webui.py:315-328`) and render the pill and footer from them instead of literal strings at `:634`/`:715`.
6. Add a test that boots the live path with a stub client and asserts `MockAirwallex` is never instantiated and the store path is `state/treasury.db`, not `state/mock/*`.

### 02 · `FUNDED` and `DEFERRED` obligations never execute or reschedule

**Priority:** P0 Blocker
**Location:** `agent.py:685-707` (`execute()` handles only `FX_PLANNED`, `AWAITING_APPROVAL`, `CONVERTED`, `ESCALATED`), `agent.py:419-446` (`_apply_decision` creates `FUNDED`/`DEFERRED`), `agent.py:1094-1123` (`refresh_payouts` only examines `CONVERTED`), `models.py:91-104` (`FUNDED → PAID` is legal; `DEFERRED` only returns through re-decision), `policy.py:220-229` (deferral text promises “pushed 7 days”).
**Day-1 risk:** A bill the planner classifies `FUND` — the ordinary same-currency case — is recorded, displayed, and then never paid; `execute()` has no branch for `State.FUNDED`. A `DEFER` decision says “pushed 7 days to next week” at `policy.py:228`, but nothing stores that date and nothing re-evaluates it. On launch day, operating cash quietly fails to leave the account and deferred bills are never revisited.
**Exact fix:**
1. Add `deferred_until: datetime | None` and `funding_source` to `ObligationRecord`; persist both in the snapshot (see #03).
2. Add `elif rec.state is State.FUNDED: results.append(self._pay_funded(rec))` and `elif rec.state is State.DEFERRED and rec.deferred_until and rec.deferred_until <= now: results.append(self._replan_deferred(rec))` to `execute()`.
3. Implement `_pay_funded`: reserve a payout with the existing idempotency key (`payout:{ob.id}`), then call `_pay` directly for base-currency/local obligations; if the payee is foreign-currency, call `_convert_and_pay` instead.
4. Implement `_replan_deferred`: run the single-obligation planner against the current ledger, apply the resulting decision through `_apply_decision`, and set `deferred_until = now + policy.deferral_horizon_days` on a repeated deferral. The transition table already permits `DEFERRED → FUNDED/FX_PLANNED/AWAITING_APPROVAL/ESCALATED` (`models.py:95-96`).
5. In `policy.py:220-229`, stamp the actual `deferred_until` on the decision rather than only writing it into the reason text.
6. Expose `deferred_until` in the snapshot and UI, and add tests that a `FUND` obligation reaches `PAID` in the mock and a `DEFER` obligation re-enters planning after an injected clock advance.

### 03 · No durable cycle state or resume path

**Priority:** P0 Blocker
**Location:** `agent.py:264-266` (records built from constructor fixtures and kept only in memory), `agent.py:327-328` (`checkpoint` only writes a snapshot), `store.py:1003-1006` (`save_snapshot` exists; **no loader exists**), `webui.py:207-212` (`reset` closes the store and discards the cycle), `webui.py:154-168` (one `DemoSession` owns the only live agent).
**Day-1 risk:** A restart, crash, or deploy loses every decision, ledger movement, commitment, approval link, and transfer reference. Snapshots are write-only, so they provide no recovery. The next process starts a fresh cycle while an approved card and an in-flight transfer still exist in the old database; the invoice stays locked, or a manual retry pays it twice. This is the difference between “restart” and “incident” on launch day.
**Exact fix:**
1. Add `ObligationRecord.to_state()` / `from_state()` covering `decision`, `history`, `approval_id`, `conversion`, `transfer`, `deferred_until`, and `funding_source`.
2. Add `Store.latest_snapshot(cycle_id)`, `Store.load_snapshot(cycle_id, act)`, and `Store.list_open_cycles()` (cycles not closed at `store.py` schema). Return typed dictionaries, not raw rows.
3. Add `TreasuryAgent.resume(cycle_id)`: reconstruct records, rehydrate `ApprovalBook` (it already reloads open cards at `agent.py:255-263`), call `refresh_payouts()` and the `OperationStore` reconciliation path, and mark the agent `halted` if any operation is `unresolved` rather than guessing.
4. Call `checkpoint` after every state transition (`_apply_decision`, `_convert_and_pay`, `_pay`, `refresh_payouts`), not only once per act at `demo.py:534-543`. The write is small; the recovery value is large.
5. In `webui.py:_boot`, detect an open cycle via `Store.list_open_cycles()` and resume it instead of creating a new one. Add an explicit `POST /api/resume` for a finance controller and make `/api/reset` archive the old database, require a typed reason, and write a `cycle_reset` audit row before closing it.
6. Add a crash-injection test that raises between the Airwallex send and `_update_payout_row` (`agent.py:1065-1080`), restarts the agent, and asserts no duplicate transfer and a resolved local row.

### 04 · The entire operational data plane is fixture-only

**Priority:** P0 Blocker
**Location:** `simulation.py:116-154` (`load_scenario` is the only source of obligations, receipt, deposit, and payout specs), `fixtures/scenario.json` (3 fixture files total), `agent.py:230-240` (constructor takes fixture obligations and payouts), `manage.py:165-186` (`pin-payee` derives the payee from the scenario file), `screening.py:64-82` (one local JSON list, no provider or refresh), `webui.py:172-174` (scenario loaded on every boot).
**Day-1 risk:** There is no way to onboard a real bill, a real payee, a real deposit, or a real sanctions list. `pin-payee` can only pin beneficiaries that already exist in `fixtures/scenario.json`. Screening uses a fictitious bundled list and a token-equality matcher; a real supplier is either refused or falsely cleared. The only inbound balance event is the demo simulator, so production has no webhook path. This is not a missing integration — it is the absence of the operational data plane.
**Exact fix:**
1. Add tables: `obligations` (cycle-scoped invoice facts, `due_at`, state, version), `payees` (`payee_key`, legal name, bank details, fingerprint, verification status, `verified_at`, `verified_by`), and `screening_versions` (source, version, hash, loaded_at).
2. Add `manage.py import-obligations --file invoices.csv` applying the same validation as `validate_scenario` (`simulation.py:51-100`) and `manage.py pin-payee --obligation <id> --iban ... --swift ... --file <json>` that writes the payee master directly. Remove the scenario dependency from the production path; keep `load_scenario` only for `--mode demo`.
3. Replace `ListScreener` with a `Screener` protocol (`version`, `screen(name, country)`); add a vendor/OpenSanctions adapter, a `manage.py refresh-screening` command, persisted versions, and rescreening of active payees whenever the list version changes.
4. Add `POST /webhooks/deposits` with an HMAC signature header, a timestamp window, and a replay-protection table keyed by provider event id; call `TreasuryAgent.on_balance_event` from the webhook, not from the demo simulator.
5. Make the web UI read obligations and payees from the store; the fixture loader must fail live startup (covered by #19).

---

## Pillar 2 — Security, Auth & Data Isolation

### 05 · Any signed-in approver can run every act and reset the shared cycle

**Priority:** P0 Blocker
**Location:** `webui.py:154-168` (one global `DemoSession` for every browser), `webui.py:405-409` (`_signed_in` checks only that a session is authenticated), `webui.py:452-457` (act gate is sequence-only), `webui.py:475-491` (`act1`–`act4` and `reset` dispatch without a role check), `webui.py:854` (`srv.session = DemoSession()`).
**Day-1 risk:** Authentication is real (S22), but authorization is not. A read-only or treasury-only approver can run Act 4 and execute payments, or press Reset and destroy the only shared cycle for every operator; `DemoSession.reset()` at `:207-212` closes the store and wipes the session log. There is no per-cycle ownership, no role matrix at the operation level, and no separation between the person requesting an act and the person executing it. One user can disrupt treasury for the whole company.
**Exact fix:**
1. Define an explicit `ACTION_ROLES` matrix: act1–act3 → `{"finance_controller", "treasury_approver"}`; act4 → `{"finance_controller"}`; reset → `{"finance_controller"}`; sign → the card's existing `ROLE_FOR_KIND` (`approvals.py:26-31`).
2. In `_dispatch`, load the approver from the store by `session.approver_id` on every request, reject inactive accounts, check the matrix, and write an `admin_refused` audit row before returning 403.
3. Replace the process-wide `demo.act` integer with `cycles.act` in SQLite and key the runtime by `cycle_id`; sessions carry their `cycle_id`, and a request for another cycle is rejected. Routes become `/api/cycles/<id>/act/<n>` rather than process-global verbs.
4. Make reset require a finance controller, a typed reason, and an audit row written before the old store is closed; disable reset entirely in live mode.
5. Audit the actor for every act (`approver:<id>`), not `demo.operator`.
6. Add tests: a `treasury_approver` gets 403 on act4/reset; a deactivated session gets 403 on its next request.

### 06 · Login is an unthrottled CPU and denial-of-service amplifier

**Priority:** P1 High
**Location:** `store.py:108-114` (lockout doubling), `store.py:778-783` (`_require_approver_integrity` calls full `verify()`), `store.py:838-861` (`authenticate` runs scrypt and resets failure counters), `webui.py:459-468` (login route has no per-IP or per-account limit).
**Day-1 risk:** Five wrong PINs for an approver trigger the lockout path, so an attacker who knows approver ids can lock every approver and stop all payments with a trivial script. Every attempt also runs a full O(n) audit-chain verification plus scrypt before it can return; unauthenticated traffic becomes a CPU and disk amplification vector. There is no per-IP limit, no CAPTCHA/proof-of-work, no alert threshold, and no self-service or controller-driven unlock.
**Exact fix:**
1. Add a sliding-window limiter per `(approver_id, client_ip)` and a coarser per-IP cap, returning `429` with `Retry-After`. Settings: `TREASURY_AUTH_PER_MINUTE`, `TREASURY_AUTH_BURST`.
2. For unknown approver ids, run a fixed precomputed scrypt dummy so response time does not reveal account existence.
3. Replace the full `verify()` call in `_require_approver_integrity` with an integrity cache keyed by `(database, head_hash)` and invalidated on local writes; #09 covers the mechanism.
4. Keep the 5-failure lockout but do not zero the counter when applying it; persist `locked_until`, expose a finance-controller `manage.py unlock-approver --by ...` command, and audit `approver_unlocked`.
5. Emit `auth_failed` with approver id, IP, and user agent; alert on a threshold (see #18). Never log the PIN.

### 07 · TLS, cookie, and origin handling only works on localhost

**Priority:** P0 Blocker
**Location:** `webui.py:357-360` (session cookie has `HttpOnly`/`SameSite` but no `Secure` and no `__Host-` prefix), `webui.py:363-366` (trusted `Host` is only `127.0.0.1`/`localhost` plus the bound port), `webui.py:373-377` (same-origin comparison reconstructs `http://`), `webui.py:853` (loopback bind).
**Day-1 risk:** Behind a TLS reverse proxy, the legitimate `Host` and `Origin` are the public domain, so every state-changing request is rejected as untrusted — or, if the checks are loosened to make it work, the session cookie and PIN travel without `Secure`/HSTS and the same-origin check compares against the wrong scheme. There is no supported way to expose this dashboard safely.
**Exact fix:**
1. Add `Settings.public_origin` (`TREASURY_PUBLIC_ORIGIN`, e.g. `https://treasury.example.com`), `trusted_proxies`, and `port`; validate it in #19.
2. Rewrite `_trusted_host` to accept the configured host:port, and only trust `X-Forwarded-Host`/`X-Forwarded-Proto` when the peer is a listed proxy.
3. Rewrite `_same_origin` to compare a parsed origin tuple against `urlsplit(settings.public_origin)`, not a hardcoded `http://` string.
4. Emit `__Host-treasury_session=...; Secure; HttpOnly; SameSite=Strict; Path=/` whenever the public origin is HTTPS; add `Strict-Transport-Security: max-age=31536000; includeSubDomains` on TLS requests.
5. Keep the app bound to loopback and document a TLS-terminating proxy (Caddy/nginx) as the only supported exposure; add a test that simulates proxy headers from a configured and an unconfigured peer.

### 08 · Approver lifecycle and session revocation are incomplete

**Priority:** P1 High
**Location:** `store.py:795-821` (only `enroll_approver` and `set_approver_active`; no PIN reset, no role change), `webui.py:94-104` (`WebSession` stores no approver version), `webui.py:368-371` (session lookup never re-checks the approver row), `webui.py:431-438` (state endpoint trusts the session), `webui.py:452-457` (act authorization would trust it too).
**Day-1 risk:** A deactivated approver keeps a valid session until idle expiry (up to `IDLE_SECONDS`) because sessions are never revalidated against `active`. A compromised PIN cannot be rotated: there is no `change-pin`, no controller-initiated reset, and no role-change command. Offboarding and incident response both require editing SQLite by hand — which the audit design forbids — or deleting the database.
**Exact fix:**
1. Add `approvers.version` (bumped on PIN, role, or active-state change) and `must_change_pin`.
2. Add audited store methods: `change_pin(approver_id, old, new)`, `reset_pin(by, approver_id, new, reason)`, `set_roles(by, approver_id, roles)`, and make `set_approver_active` bump `version`. Record `pin_changed`, `pin_reset`, `roles_changed`, and `approver_deactivated` events.
3. Store `approver_version` in `WebSession`; on every request, reload the approver and drop the session if inactive or the version differs. `Sessions.drop_all(approver_id)` for immediate revocation.
4. Add `manage.py change-pin`, `manage.py reset-pin`, and `manage.py set-roles`; require a finance controller for reset/role changes and never allow self-enrolment.
5. Move PIN policy to settings: minimum 8 characters, allow passphrases, reject the current PIN, and force a change after a controller reset. Document the migration for existing 6-digit PINs.

---

## Pillar 3 — Database Integrity & Backend Resilience

### 09 · Full-chain verification runs inside the authentication write path

**Priority:** P1 High
**Location:** `store.py:545-553` (`tx` opens `BEGIN IMMEDIATE`), `store.py:778-783` (`_require_approver_integrity` invokes full `verify()`), `store.py:823-858` (`get_approver`, `list_approvers`, and `authenticate` all call it), `store.py:1032-1129` (`verify()` runs `PRAGMA integrity_check`, foreign-key check, full schema comparison, O(n) HMAC walk, row-state checks, and approval-digest checks).
**Day-1 risk:** Every login, approver lookup, and roster read performs an O(n) walk of the entire audit chain and a full SQLite integrity check while holding a write transaction. At a few hundred thousand audit rows — months, not years — login latency becomes seconds and every authentication blocks the single writer. A treasury UI that stalls during a payment approval is an availability incident.
**Exact fix:**
1. Keep the full `verify()` on store open (already S20) and in `manage.py verify-audit`, but remove it from request-path methods.
2. Add `Store._verified_head` and `Store._verified_at`; `verify_if_needed()` compares `PRAGMA data_version` and the current head hash against the cache and only walks rows appended since the last verified seq.
3. Change `_require_approver_integrity` to verify only the approver row's signed state hash and the head continuity, not the whole chain.
4. Move `PRAGMA integrity_check` to open and to a scheduled maintenance command; never run it inside `authenticate`.
5. Add a benchmark test with 100,000 audit rows asserting `authenticate` stays under 100 ms, and a test that a tampered row appended by another connection still invalidates the cache.

### 10 · The schema has no query indexes beyond one payout constraint

**Priority:** P2 Polish
**Location:** `store.py:208-413` (schema; the only non-default index is `one_live_payout_per_invoice` at `:386-387`), queries at `store.py:652` (head), `:665` (audit list), `:886` (approvals by cycle), `:943`/`:952` (payout by payee/reference), `:999` (payout list), `:1061` (full audit export).
**Day-1 risk:** Every dashboard poll (`webui.py:844`, every 4 seconds per client), every approval lookup, and every payout reservation scans the full table. With a seven-year retention target (AUDIT_REPORT §6.4), the audit log and payouts table make the UI and `verify` progressively slower, and longer scans hold the SQLite write lock longer.
**Exact fix:**
1. Introduce `PRAGMA user_version` migrations applied idempotently at `Store.__init__`; record each migration's SQL text so `verify()` can confirm it.
2. Add:
   - `CREATE INDEX idx_audit_cycle_seq ON audit_log(cycle_id, seq);`
   - `CREATE INDEX idx_audit_event_seq ON audit_log(event, seq);`
   - `CREATE INDEX idx_approvals_cycle_status ON approvals(cycle_id, status);`
   - `CREATE INDEX idx_approvals_status_expires ON approvals(status, expires_at);`
   - `CREATE INDEX idx_payouts_cycle_status ON payouts(cycle_id, status);`
   - `CREATE INDEX idx_payouts_payee_ref ON payouts(payee_fingerprint, reference, currency);`
   - `CREATE INDEX idx_payee_history_key ON payee_history(payee_key, id);`
   - `CREATE INDEX idx_operations_status ON operations(status);`
3. Extend the schema text expectations so `verify-audit` fails if an index is dropped.
4. Add `EXPLAIN QUERY PLAN` assertions in tests for the five hot queries to prevent a future query from reintroducing a table scan.

### 11 · External timeouts are demo-tuned constants and transient lag halts the agent

**Priority:** P1 High
**Location:** `agent.py:307-318` (`_sync` waits a hardcoded duration), `agent.py:624-636` (`on_balance_event` waits 20 s), `agent.py:857` (10 s sync after conversion), `agent.py:912-918` (`_await_settlement` polls 5 × 1 s), `agent.py:1070` (10 s sync before payout), `airwallex_client.py:118-120` (20 s timeout, 4 retries), `config.py:57-74` (no timeout, poll, or settlement settings).
**Day-1 risk:** These windows are sized for `MockAirwallex`. A real sandbox or production settlement that takes 11 seconds either leaves the ledger stale and the next decision wrong, or trips `_await_settlement` and halts the agent. The values cannot be tuned per environment without editing code, and a slow upstream holds the web request thread because there is no async pending state.
**Exact fix:**
1. Add settings: `HTTP_TIMEOUT_SECONDS`, `POLL_DEADLINE_SECONDS`, `POLL_INTERVAL_SECONDS`, `SETTLEMENT_ATTEMPTS`, and pass them into `AirwallexClient` and `TreasuryAgent`.
2. On deadline expiry, persist the operation as `pending` and return `ExecutionResult(ob_id, "pending", "settlement not final by deadline")`; do **not** call `_halt`. Reserve `_halt` for a confirmed mismatch (wrong amount, currency, or counterparty).
3. Add `TreasuryAgent.reconcile_pending()` that queries transfer/conversion status by `request_id`; call it at the start of `execute()` and on each web refresh.
4. Audit `poll_timeout` with the request id and elapsed time; expose pending operations in the snapshot and UI (#15).
5. Add tests with a fake clock for the deadline boundary and a slow-client stub that returns `PROCESSING` before `PAID`.

### 12 · Writes lack busy retries and post-money database failures desync local state

**Priority:** P1 High
**Location:** `store.py:545-553` (`tx` has no `busy_timeout` or retry), `store.py:637-646` (only `append_audit` retries “locked”, three times), `store.py:864-883` (`save_approval`), `store.py:930-948` (`reserve_payout`), `store.py:957-963` (`update_payout`), `agent.py:1065` (transfer sent) followed by `agent.py:1077-1080` (`_update_payout_row`).
**Day-1 risk:** A second connection, a backup, or an admin read can produce `SQLITE_BUSY`; every non-audit write surfaces it as an HTTP 500. Worse, `_pay` sends the Airwallex transfer and only then updates the payout row. If that update fails, money has moved while the local ledger says it has not; a restart or retry can re-send, and the invoice lock becomes inconsistent. This is the highest-consequence failure in the money path after the missing state machine.
**Exact fix:**
1. Set `PRAGMA busy_timeout=5000` (or `sqlite3.connect(..., timeout=5)`) and add a `Store._write(fn)` wrapper with bounded, jittered retries for `locked`/`busy` errors; apply it to every write method, not just `append_audit`.
2. Reorder `_pay`: insert the payout reservation in `status='submitting'` with the stable `request_id` **before** the Airwallex call; after the call, update to `status='submitted'` with `transfer_id`. If the second write fails, leave `submitting`/`unresolved` and reconcile by `request_id`; never generate a new request id on retry.
3. Add `OperationStore` reconciliation for payouts, mirroring the existing operation journal (`journal.py:109-136`), and surface unresolved rows through `manage.py list-payouts`.
4. Add a fault-injection test that raises inside `update_payout` after a mock transfer succeeds and asserts the next run reconciles rather than duplicates.

---

## Pillar 4 — UI/UX Polish & 5-State Coverage

### 13 · The approval card hides destination, FX ceiling, evidence, explanation, and expiry

**Priority:** P1 High
**Location:** `webui.py:746-761` (`signCard` renders amount, counterparty, eligible roles, requester, and code only), `approvals.py:105-120` (`for_reader` already returns `destination`, `sell_currency`, `max_sell_amount`, `evidence`, `explanation`, `created_at`, `expires_at`), CLI parity at `demo.py:132-141` (destination, pay-with ceiling, expiry, evidence).
**Day-1 risk:** An approver is asked to sign a payment without seeing the masked destination account, the maximum FX sell amount, the evidence that triggered the card, the agent's explanation, or when the card expires. They cannot catch a re-pointed payee, an FX ceiling they did not intend, or a stale card; the signature becomes a click, not an informed approval. This directly undermines the digest-binding control the whole design is sold on.
**Exact fix:**
1. Extend `signCard` to render every field returned by `for_reader`: destination, `sell_currency` + `max_sell_amount`, evidence list, explanation, `requested_by`, `created_at`, and `expires_at` with a live countdown.
2. Keep `digest` and the destination fingerprint off the screen (they are already excluded by `for_reader`); show the masked destination only.
3. Warn visually when `expires_at` is under five minutes; disable sign when expired and refresh the card state.
4. Put the extra detail behind a `<details>` element if card height is a concern, but keep destination and expiry always visible.
5. Add a snapshot assertion that these fields are present and a DOM test that the rendered card contains them.

### 14 · Four-second polling destroys in-progress approval inputs

**Priority:** P1 High
**Location:** `webui.py:754-757` (PIN, approver id, code, and note inputs live inside each card), `webui.py:793-794` (`$("apprList").innerHTML = ...` on every render), `webui.py:844` (`setInterval(..., 4000)`), `webui.py:801-806` (`refresh()` fetches and renders).
**Day-1 risk:** A user who starts typing an approver id, PIN, or card code has the entire form replaced every four seconds. The input is lost, the PIN may be partially submitted, and repeated failed attempts count toward the lockout in #06. Approval becomes a race against the poll timer — a guaranteed launch-day support ticket.
**Exact fix:**
1. Replace the wholesale `innerHTML` assignment with a keyed reconciliation by `data-id`: create/update/remove cards individually and only update the fields that changed.
2. Skip re-rendering a card while `document.activeElement` is inside it, or while any of its inputs has a value; resume after blur with a one-second debounce.
3. Pause the interval while an approval request is in flight and while the tab is hidden (`document.visibilityState`), and refresh immediately on focus.
4. Alternatively, move signing into a modal that is outside the polled region; keep the list read-only behind it.
5. Add a browser test that types into the PIN field, waits six seconds, and asserts the value survives.

### 15 · No loading, error, or halted state; failed refreshes look like live data

**Priority:** P1 High
**Location:** `webui.py:731-738` (`api()` has no timeout, no abort, no catch), `webui.py:801-806` (`refresh()` has no error handling), `webui.py:315-328` (snapshot omits `halted`, `halt_reason`, `last_error`, `updated_at`, and `mode`), `agent.py:1143-1164` (`agent.snapshot()` computes `halted`, but the web path bypasses it), `webui.py:762-800` (render assumes success).
**Day-1 risk:** A network failure, a 500, or a halted agent leaves the previous balances and states on screen with no indication that they are stale. An operator can approve a card against a halted or disconnected agent; a slow request hangs the page because `fetch` has no timeout. There is no loading skeleton and no empty state, so a fresh cycle looks broken.
**Exact fix:**
1. Make `DemoSession.snapshot()` delegate to `agent.snapshot()` and add `halted`, `halt_reason`, `last_error`, `updated_at` (server monotonic + wall clock), and `mode` to the payload.
2. Render a persistent banner when `halted` is true, disable act/sign buttons, and show the reason; add a separate connection banner when the last refresh failed or is older than 15 seconds.
3. Add `AbortController` with a 10-second timeout to `api()`, catch network/parse errors, and return a typed `{status, json, error}` instead of throwing into the void.
4. Implement the five states explicitly: initial skeleton (KPI placeholders, table rows, card skeleton), loading (per-act spinner, disabled buttons), empty (“No obligations loaded”, “No approvals pending”), error (banner + Retry), and success (with “updated Ns ago”).
5. Add `role="alert"` to the halt/connection banner and `aria-live="polite"` to the toast; keep the toast from auto-hiding on errors.

### 16 · Demo branding, hardcoded policy, and form accessibility

**Priority:** P2 Polish
**Location:** `webui.py:634` (literal “Mock sandbox” pill), `webui.py:715` (demo/team footer), `webui.py:672`, `:679`, `:689`, `:725` (literal `$10,000` in copy and hints) despite the server sending `policy.reserve_floor` at `:323-326`; `webui.py:753-757` (`label` elements not associated with inputs), `webui.py:601` (toast has no `aria-live`), `webui.py:615-616` (existing mobile breakpoints).
**Day-1 risk:** A production deployment either advertises itself as a mock or silently displays a policy number that no longer matches the server configuration. Screen-reader users cannot associate the four signing fields with their labels, and the toast (the only error channel) is invisible to assistive technology. The mobile layout exists but has not been exercised with keyboard or screen-reader users.
**Exact fix:**
1. Render the pill and footer from `snapshot.mode` and the company name; remove “Team Apex Studio” and “demo against offline mock sandbox” outside demo mode.
2. Replace every literal `$10,000` and every hint that embeds it with `fmt$(r.policy.reserve_floor)` (and the threshold where relevant); derive all policy copy from the snapshot.
3. Give each input a unique `id` and each label a matching `for` (`sign-{approval_id}-pin`, etc.), or wrap the input inside the label. Add `autocomplete="username"`/`autocomplete="current-password"` where appropriate.
4. Make the toast and banners `role="status"`/`aria-live="polite"`; keep focus on the first invalid field after a 400/403.
5. Test at 375 px and with keyboard-only navigation; enforce a 44 px minimum touch target for sign/reject buttons and ensure the fixed toast does not cover the action row.

---

## Pillar 5 — Deployment, Observability & Launch Hygiene

### 17 · No deployable artifact, no CI, and a single-threaded server

**Priority:** P0 Blocker
**Location:** `webui.py:853` (`HTTPServer(("127.0.0.1", args.port), Handler)` is single-threaded; `log_message` is suppressed at `:519-520`), `requirements-dev.txt:1-2` (`pytest>=8` only), `README.md:18-27` (manual `pip install -r requirements-dev.txt` + `python3 -m pytest`), no `Dockerfile`/`pyproject.toml`/`requirements.txt`/CI anywhere in the tree.
**Day-1 risk:** One slow request blocks every operator because the server processes connections serially; there is no reproducible install, no non-root container, no TLS termination, and no CI gate to keep the 250 tests, `bandit`, and `pyflakes` green. Deploying requires an engineer to hand-build a Python environment, and a regression can ship because nothing runs the controls on change.
**Exact fix:**
1. Add `pyproject.toml` with `requires-python = ">=3.11"`, no runtime dependencies, and a `dev` extra for pytest/bandit/pyflakes; pin dev versions in a lock file.
2. Replace `HTTPServer` with `ThreadingHTTPServer` plus a bounded concurrency semaphore (or run the standard-library WSGI app under a production server); keep the SQLite connection owned by the request thread or serialize writes through a single worker.
3. Add a non-root `Dockerfile` (`python:3.14-slim`, `USER app`, `HEALTHCHECK` hitting `/healthz`, `/data` volume for `TREASURY_STATE_DIR`) and a compose example with Caddy for TLS.
4. Add `.github/workflows/ci.yml` running `pytest`, `bandit -r . -x ./.venv,./tests`, `pyflakes *.py tests/*.py`, and a `demo.py --mock --no-color` smoke on every push and PR.
5. Document the supported topology: app on loopback, TLS proxy in front, one writer, state on an encrypted volume (ties to AUDIT_REPORT §6.2–6.3).

### 18 · No health/readiness endpoints, structured logs, or metrics

**Priority:** P1 High
**Location:** `webui.py:412-439` (GET routes: `/`, static, `/api/state` only; no health), `webui.py:441-491` (POST routes), `webui.py:496-498` (unexpected errors print a traceback to the console), `webui.py:519-520` (`log_message` is a no-op), `webui.py:856-857` (serve loop).
**Day-1 risk:** An orchestrator has nothing to probe, so it cannot distinguish “process up but database broken” from healthy. Access logs are disabled entirely, and errors are unstructured tracebacks. A halted agent, a wave of failed logins, a duplicate invoice, or a failed `verify-audit` is invisible until someone notices money did not move.
**Exact fix:**
1. Add unauthenticated `/healthz` (process alive) and `/readyz` (store open, audit cache valid, audit key present, agent not halted, state dir writable). Return 503 with reason codes, never secrets.
2. Replace `print_exc` and the no-op `log_message` with a JSON logger: `ts`, `level`, `request_id`, `actor`, `method`, `route`, `status`, `duration_ms`, `event`, `error_class`. Redact PINs, tokens, cookies, digests, and account numbers.
3. Add counters/gauges: `auth_failures_total`, `agent_halts_total`, `payouts_released_total`, `audit_verify_failures_total`, `pending_approvals_age_seconds`, `last_successful_checkpoint_age_seconds`. Expose loopback-only `/metrics` or push to the chosen monitoring system.
4. Configure alerts for the events in `AUDIT_REPORT.md` §6.10 plus readiness failures and backup age (#20).
5. Include a request id in every response (`X-Request-ID`) and in the audit `data` where an operator action is recorded.

### 19 · Configuration is validated late, and the default is silently mock

**Priority:** P1 High
**Location:** `config.py:85-101` (`load_dotenv` only warns about loose `.env` permissions), `config.py:150-178` (`load_settings` validates only the base URL and LLM provider), `runtime.py:41-48` (the audit key is required only when a store is opened), `webui.py:170-190` (always mock regardless of settings), `.env.example` (no mode, port, public origin, or timeout settings).
**Day-1 risk:** An operator can launch the dashboard believing it is live while it is silently mock (#01). In the real path, missing audit keys, an unwritable state directory, no screening list, or zero active controllers are discovered only at the first payment or first login. A world-readable `.env` with the audit key is accepted with a warning, and there is no single startup assertion that the environment is production-safe.
**Exact fix:**
1. Add `TREASURY_MODE` (`live|demo`), `TREASURY_PUBLIC_ORIGIN`, `TREASURY_PORT`, `TREASURY_TRUSTED_PROXIES`, timeouts, and the auth limits from #06/#11 to `Settings` and `.env.example`.
2. Add `Settings.validate()` called at the end of `load_settings`: in live mode require an audit key, a writable state dir, a screening source, an HTTPS public origin, and at least one active `finance_controller`; in demo mode require none of these. Refuse a `.env` whose mode is more permissive than 0600 in live.
3. Add `manage.py preflight` that opens the store read-only, verifies the chain, checks the key, checks approver count, checks the state dir, and prints a redacted summary; use it as the container entrypoint and in CI.
4. Make `webui.py --mode` and `TREASURY_MODE` agree; a mismatch exits 2 before the server binds.
5. Add a test for every validation failure so a future field cannot be forgotten.

### 20 · Backup, anchoring, retention, and restore are manual and unverified

**Priority:** P1 High
**Location:** `manage.py:239-247` (`anchor` only prints/appends when invoked by hand), `manage.py:284-296` (`backup` writes a copy and `.sha256`, no scheduling), `demo.py:406-410` (anchor only when `TREASURY_ANCHOR_FILE` happens to be set), `store.py:568` (retention text), `store.py:1026-1030` (`head`).
**Day-1 risk:** If the host is lost or encrypted by ransomware, the ledger is gone. Anchors are only written when someone remembers to run the command; a gap between anchors means truncation or replacement can go undetected. There is no off-host immutable copy, no retention schedule, no restore drill, and no alert when the last backup is stale — so the seven-year retention claim in `AUDIT_REPORT.md` §6.4 is unsupported by any automation.
**Exact fix:**
1. Add `manage.py maintain --by <controller> --backup-dir <path> --anchor-file <path>`: verify the chain, take a `backup`, write the `.sha256`, append the head to the anchor JSONL, and optionally invoke a configured upload hook (`TREASURY_BACKUP_UPLOAD_CMD`, e.g. `aws s3 cp --object-lock-mode COMPLIANCE`).
2. Schedule it daily with a systemd timer, cron, or container job; add `TREASURY_BACKUP_DIR` and `TREASURY_BACKUP_MAX_AGE_HOURS`.
3. Add `manage.py restore-check --backup <file> --key <key>` that opens the copy read-only with the key epoch in force, runs `verify()`, and returns nonzero on failure; run it monthly and after every schema migration.
4. Alert when the last successful backup exceeds 26 hours, when the anchor head differs from the live head beyond the expected window, or when disk free falls below two backup sizes.
5. Document key epochs: a new key means a new database, old databases verified with the old key and retained; losing the key makes the chain unverifiable (AUDIT_REPORT §6.2).

---

## Implementation batches

All 20 items are covered exactly once. Batch A is recommended first: it closes the exposure and operability gaps without requiring live credentials, and it prevents the live loop from being exposed on a single-user, non-revocable, unmonitored server.

| Batch | Theme | Items | Why this order |
|---|---|---|---|
| **A — Expose safely** | Authorization, TLS, sessions, deploy, health, config | **05, 06, 07, 08, 17, 18, 19** | The dashboard can be attacked or misconfigured before it can move real money; these are mostly independent of live credentials and can be verified locally. |
| **B — Real money loop** | Live mode, execution, resume, ingestion, integrity, timeouts, backups | **01, 02, 03, 04, 09, 11, 12, 20** | Requires the perimeter from A. This is the batch that makes the product able to take a real invoice end to end and survive a restart. |
| **C — Operator experience** | Indexes and five-state UI | **10, 13, 14, 15, 16** | Improves scale and daily usability after the money path is correct; lowest risk of destabilizing controls. |

**Dependency notes**

- **01 depends on 19** for an explicit mode and startup validation; do not add a live boot path before the mode can be trusted.
- **02 depends on 03** for durable `deferred_until`/record state; otherwise a deferred obligation is lost on restart.
- **12 should land before 02** exercises real transfers, because `_pay` must be reordered to journal the request id before the external call.
- **09 depends on 10** for a fast incremental verification path; adding indexes first keeps the post-change benchmark meaningful.
- **04 is the long pole.** A real obligation/payee/screening ingestion model is the difference between a demo and a product; it should be scoped as its own milestone inside Batch B.

---

*Prepared from the current tree on 2026-10-23. No live Airwallex credentials were configured during the scan; sandbox behavior is inferred from `airwallex_client.py`, `simulation.py`, and the mock, not from a live call.*
