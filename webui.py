#!/usr/bin/env python3
"""Enterprise web UI for the Adaptive Treasury Controller.

    python3 webui.py --mode mock              # serves the dashboard on http://127.0.0.1:8080
    python3 webui.py --mode mock --port 9000  # custom port

Boots the real TreasuryAgent against the offline mock sandbox (no credentials) and
exposes the four-act demo through a dashboard. Nothing is approved automatically: a
person signs in as an approver (identity + passcode, verified by the store, which locks
the account for a doubling wait after each five failed tries) and types each card's code
before the agent may move money. Standard library only.

The demo identities below exist so the sandbox can be driven without a bank; their
PINs are seeded into a throwaway database and are never rendered to a screen.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import threading
import time
import traceback
from decimal import Decimal
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent import AgentHalted, TreasuryAgent
from airwallex_client import AirwallexClient
from approvals import ROLE_FOR_KIND, ApprovalError, ApprovalRequest
from config import DEFAULT_POLICY, load_settings
from email_reader import make_reader
from explainer import Explainer
from llm import make_llm
from mock_sandbox import MOCK_API_KEY, MOCK_CLIENT_ID, MockAirwallex
from models import State
from policy import autonomous_fx_limit
from runtime import make_screener, new_cycle_id, open_store
from simulation import SandboxSimulator, load_scenario
from store import AuthError, DuplicatePayout, StoreError

SESSION_COOKIE = "treasury_session"
IDLE_SECONDS = 15 * 60
ABSOLUTE_SECONDS = 4 * 60 * 60
MAX_BODY = 64 * 1024
CSP = ("default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'")


# Never rendered. The confirmation code is a prefix of the approval digest and the destination
# fingerprint identifies the payee's real account, so shipping either to the page would hand a
# browser-side script what a signature is supposed to prove the approver read off the card.
SECRET_FIELDS = frozenset({"digest", "destination_fp", "pin_hash", "salt", "kdf", "state_hash",
                           "failed_attempts", "locked_until", "api_key", "client_key"})


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------
def ser(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, State):
        return obj.value
    if isinstance(obj, ApprovalRequest):
        return ser(obj.for_reader())
    if isinstance(obj, (list, tuple)):
        return [ser(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): ser(v) for k, v in obj.items()}
    if hasattr(obj, "__dataclass_fields__"):
        out = {}
        for f in obj.__dataclass_fields__:
            if f in SECRET_FIELDS:
                continue
            try:
                out[f] = ser(getattr(obj, f))
            except Exception:  # pragma: no cover - a field that cannot be read is not shown
                out[f] = None
        return out
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


# ---------------------------------------------------------------------------
# Browser sessions: cookie-authenticated, per-session CSRF, idle + absolute expiry
# ---------------------------------------------------------------------------
class WebSession:
    def __init__(self, token: str, csrf: str, approver_id: str | None):
        self.token = token
        self.csrf = csrf
        self.approver_id = approver_id
        self.created = time.monotonic()
        self.last_seen = time.monotonic()

    @property
    def authenticated(self) -> bool:
        return self.approver_id is not None


class Sessions:
    """Anonymous sessions exist only to carry a CSRF token to the sign-in form; signing in
    replaces them, so a token planted on an attacker's page cannot become a live session."""

    def __init__(self):
        self._lock = threading.Lock()
        self._by_token: dict[str, WebSession] = {}

    def _issue(self, approver_id: str | None) -> WebSession:
        session = WebSession(secrets.token_hex(32), secrets.token_hex(32), approver_id)
        self._by_token[session.token] = session
        return session

    def anonymous(self) -> WebSession:
        with self._lock:
            self._prune()
            return self._issue(None)

    def get(self, token: str | None) -> WebSession | None:
        if not token:
            return None
        with self._lock:
            self._prune()
            session = self._by_token.get(token)
            if session:
                session.last_seen = time.monotonic()
            return session

    def sign_in(self, old_token: str | None, approver_id: str) -> WebSession:
        with self._lock:
            self._by_token.pop(old_token, None)
            return self._issue(approver_id)

    def drop(self, token: str | None) -> None:
        with self._lock:
            self._by_token.pop(token, None)

    def _prune(self) -> None:
        now = time.monotonic()
        for token, session in list(self._by_token.items()):
            if now - session.last_seen > IDLE_SECONDS or now - session.created > ABSOLUTE_SECONDS:
                self._by_token.pop(token, None)


# ---------------------------------------------------------------------------
# Agent lifecycle
# ---------------------------------------------------------------------------
WEB_MODE = "mock"  # the dashboard boots only the offline mock sandbox; live runs through demo.py/manage.py


class DemoSession:
    """One agent, one mock bank, one cycle. Guarded by a lock: the HTTP server is threaded only
    in name here, and SQLite writes belong to the thread that opened the store."""

    def __init__(self):
        self.lock = threading.Lock()
        self.agent = None
        self.mock = None
        self.scenario = None
        self.cycle = None
        self.log = []
        self.act = 0
        self.opening_coverage = None
        self.simulator = None
        self._boot()

    def _boot(self):
        settings = load_settings()
        scenario = load_scenario()
        mock = MockAirwallex(balances=scenario.operating_cash, rates_usd_per_unit=scenario.mock_rates,
                             swift_fees=dict(DEFAULT_POLICY.swift_fees))
        base_url = mock.start()
        client = AirwallexClient(base_url, MOCK_CLIENT_ID, MOCK_API_KEY, api_version=settings.api_version)
        llm = make_llm(settings)
        cycle = new_cycle_id()
        store = open_store(settings, mode="mock", cycle_id=cycle)
        screener = make_screener(settings)
        cap = scenario.operating_cash if settings.apply_scenario_cash_cap else None
        agent = TreasuryAgent(client, obligations=scenario.obligations,
                              receipt=scenario.expected_receipt, payouts=scenario.payouts,
                              reader=make_reader(llm), explainer=Explainer(llm),
                              store=store, cycle_id=cycle, operator="demo.operator",
                              mode="mock", screener=screener, cash_cap=cap)
        from demo import seed_mock_database, seed_mock_payees  # mock-only identities and payee pins
        seed_mock_database(store)
        seed_mock_payees(agent, scenario)
        self.agent = agent
        self.mock = mock
        self.scenario = scenario
        self.cycle = cycle
        self.simulator = SandboxSimulator(client)
        self.act = 0
        self.opening_coverage = None
        self.log = [{"t": time.time(), "kind": "system",
                     "msg": f"Session started · cycle {cycle} · mock sandbox online"}]

    def close(self) -> None:
        with self.lock:
            try:
                self.agent.store.close()
            finally:
                self.mock.stop()

    def reset(self):
        with self.lock:
            self.agent.store.close()
            self.mock.stop()
            self._boot()
            return {"ok": True}

    def event(self, kind, msg, data=None):
        entry = {"t": time.time(), "kind": kind, "msg": msg}
        if data is not None:
            entry["data"] = data
        self.log.append(entry)

    # -- acts ---------------------------------------------------------------
    def run_act1(self):
        with self.lock:
            a = self.agent
            a.audit.act = "act1"
            a.bootstrap()
            tri = a.triage()
            self.opening_coverage = float(tri.coverage)
            a.checkpoint("act1")
            self.act = 1
            self.event("act", "Act 1 complete: initial triage", {
                "coverage": float(tri.coverage), "confidence": float(tri.confidence),
                "limit": float(tri.limit)})
            return {"ok": True, "triage": ser(tri)}

    def run_act2(self):
        with self.lock:
            a = self.agent
            a.audit.act = "act2"
            ev = a.ingest_customer_email(self.scenario.customer_email)
            a.checkpoint("act2")
            self.act = 2
            self.event("act", "Act 2 complete: confidence drop from customer email", {
                "limit_before": float(ev.limit_before), "limit_after": float(ev.limit_after)})
            return {"ok": True, "event": ser(ev)}

    def run_act3(self):
        with self.lock:
            a = self.agent
            a.audit.act = "act3"
            dep = self.scenario.deposit
            self.simulator.deposit(amount=dep.amount, currency=dep.currency,
                                   payer_name=dep.payer_name, reference=dep.reference)
            rc = a.on_balance_event(currency=dep.currency, amount=dep.amount, reference=dep.reference)
            a.checkpoint("act3")
            self.act = 3
            self.event("act", f"Act 3 complete: deposit {dep.reference} recalculated", {"changes": len(rc.changes)})
            return {"ok": True, "recalculation": ser(rc), "deposit": ser(dep)}

    def sign(self, *, decision, approval_id, approver_id, pin, confirm_code, reason=""):
        """A person signs or rejects one bound card. The PIN is checked by the store (which locks
        the account after five failures) and never by this module; the code is the card's own."""
        with self.lock:
            a = self.agent
            a.audit.act = "act4"
            if decision == "reject":
                req = a.reject(approval_id, approver_id=approver_id, pin=pin, reason=reason)
            else:
                req = a.approve(approval_id, approver_id=approver_id, pin=pin, confirm_code=confirm_code)
            self.event("ok" if decision != "reject" else "warn",
                       f"{approver_id} {'rejected' if decision == 'reject' else 'signed'} {req.kind} {req.id}")
            return {"ok": True, "approval": req.for_reader(), "pending": len(a.pending_approvals())}

    def run_act4(self):
        with self.lock:
            a = self.agent
            pending = a.pending_approvals()
            if pending:
                return {"ok": False, "error": f"{len(pending)} card(s) still await a signature"}
            a.audit.act = "act4"
            results = a.execute()
            a.audit.act = "close"
            gated = a.pending_approvals()
            if gated:
                # Execution itself can gate funded bills above the autonomous payout
                # cap. Those cards did not exist when act 4 started, so the act stays
                # locked until a human signs them and act 4 runs again.
                return {"ok": False, "error": f"{len(gated)} card(s) still await a signature"}
            report = a.reserve_report()
            verify = a.store.verify()
            self.act = 4
            self.event("act", "Act 4 complete: execution + reserve confirmed", {"executed": len(results)})
            return {"ok": True, "results": ser(results), "reserve": ser(report),
                    "audit": {"entries": verify.entries, "chain": verify.chain, "verified": verify.ok,
                              "problems": verify.problems[:3]}}

    def snapshot(self):
        with self.lock:
            a = self.agent
            if a is None:
                return {"ok": False}
            balances = {}
            committed = {}
            if a.ledger:
                balances = {c: float(v) for c, v in a.ledger.balances.items()}
                committed = {c: float(a.ledger.committed(c)) for c in a.ledger.currencies()}
            obligations = []
            for rec in a.records.values():
                ob = rec.ob
                obligations.append({
                    "id": ob.id, "label": ob.name, "counterparty": ob.counterparty,
                    "amount": float(ob.amount), "currency": ob.currency,
                    "due_hours": ob.due_in_hours, "state": rec.state.value,
                    "decision": ser(rec.decision) if rec.decision else None,
                    "approval_id": rec.approval_id,
                    "deferred_until": rec.deferred_until.isoformat() if rec.deferred_until else None,
                })
            approvals = []
            for req in a.pending_approvals():
                card = req.for_reader()
                card["eligible_roles"] = sorted(ROLE_FOR_KIND.get(req.kind, set()))
                approvals.append(card)
            return {
                "ok": True, "act": self.act, "cycle": self.cycle, "mode": WEB_MODE,
                "halted": bool(a.halted), "halt_reason": a.halted, "updated_at": time.time(),
                "balances": balances, "committed": committed,
                "confidence": float(a.confidence),
                "autonomous_limit": float(autonomous_fx_limit(a.confidence)),
                "opening_coverage": self.opening_coverage,
                "obligations": obligations,
                "pending_approvals": approvals,
                "policy": {
                    "reserve_floor": float(DEFAULT_POLICY.reserve_floor),
                    "single_payment_threshold": float(DEFAULT_POLICY.single_payment_approval_threshold),
                },
                "log": self.log[-50:],
            }


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "TreasuryUI/1.0"

    # -- responses ------------------------------------------------------------
    def _send(self, body: bytes, content_type: str, code=200, cookie: str | None = None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for value in (f"Content-Security-Policy: {CSP}", "X-Frame-Options: DENY", "Referrer-Policy: no-referrer",
                      "X-Content-Type-Options: nosniff", "Cache-Control: no-store"):
            name, _, val = value.partition(": ")
            self.send_header(name, val)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200, cookie: str | None = None):
        self._send(json.dumps(obj).encode(), "application/json", code, cookie)

    def _html(self, body: str, code=200, cookie: str | None = None):
        self._send(body.encode(), "text/html; charset=utf-8", code, cookie)

    def _cookie(self, token: str, *, clear=False) -> str:
        age = 0 if clear else IDLE_SECONDS
        return (f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={age}"
                + ("; Expires=Thu, 01 Jan 1970 00:00:00 GMT" if clear else ""))

    # -- guards ---------------------------------------------------------------
    def _trusted_host(self):
        hosts = self.headers.get_all("Host", [])
        return len(hosts) == 1 and hosts[0].lower() in {
            f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}

    def _session(self) -> WebSession | None:
        cookie = SimpleCookie(self.headers.get("Cookie") or "")
        morsel = cookie.get(SESSION_COOKIE)
        return self.server.sessions.get(morsel.value if morsel else None)

    def _same_origin(self) -> bool:
        origin = self.headers.get("Origin")
        if origin is None:
            return True  # same-origin navigation sends no Origin; the Host check still applies
        return origin == "http://" + self.headers.get("Host", "").lower()

    def _body(self) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            return None
        if not 0 < length <= MAX_BODY:
            return None
        if "json" not in (self.headers.get("Content-Type") or "").lower():
            return None
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def _guarded(self, body: dict | None) -> tuple[WebSession | None, dict | None]:
        """Host + origin + CSRF for every state change. Returns (session, body) or responds and
        returns (None, ...) when the request is not from this session's own page."""
        session = self._session()
        token = self.headers.get("X-CSRF-Token") or ""
        if (not self._trusted_host() or not self._same_origin() or session is None
                or not secrets.compare_digest(token, session.csrf)):
            self._json({"ok": False, "error": "invalid request origin or session token"}, 403)
            return None, None
        return session, (body if body is not None else {})

    def _signed_in(self, session: WebSession | None) -> bool:
        if session is None or not session.authenticated:
            self._json({"ok": False, "error": "sign-in required"}, 401)
            return False
        return True

    # -- routes ----------------------------------------------------------------
    def do_GET(self):
        path = urlparse(self.path).path
        if not self._trusted_host():
            self._json({"ok": False, "error": "untrusted host"}, 403)
            return
        if path == "/":
            session = self._session()
            if session is None:
                session = self.server.sessions.anonymous()
                self._html(PAGE.replace("__CSRF__", session.csrf), cookie=self._cookie(session.token))
                return
            self._html(PAGE.replace("__CSRF__", session.csrf))
            return
        if path == "/static/app.js":
            self._send(APP_JS.encode(), "text/javascript; charset=utf-8")
            return
        if path == "/static/app.css":
            self._send(APP_CSS.encode(), "text/css; charset=utf-8")
            return
        if path == "/api/state":
            session = self._session()
            if not self._signed_in(session):
                return
            state = self.server.session.snapshot()
            state["approver"] = session.approver_id
            self._json(state)
            return
        self._json({"ok": False, "error": "not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._body()
        if path == "/api/login":
            session, body = self._guarded(body)
            if session is not None:
                self._login(session, body)
            return
        session, body = self._guarded(body)
        if session is None or not self._signed_in(session):
            return
        required_act = {"/api/act1": 0, "/api/act2": 1, "/api/act3": 2, "/api/act4": 3}
        demo = self.server.session
        if path in required_act and demo.act != required_act[path]:
            self._json({"ok": False, "error": "act is out of sequence or already completed"}, 409)
            return
        self._dispatch(path, body, demo, session)

    def _login(self, session, body):
        approver_id = str(body.get("approver_id") or "")[:64]
        pin = str(body.get("pin") or "")[:64]
        try:
            self.server.session.agent.store.authenticate(approver_id, pin)
        except (AuthError, StoreError) as exc:
            # A failed dashboard sign-in is a chained audit event like every other
            # CLI auth failure, so a guessing run leaves a record instead of silence.
            self.server.session.agent.audit.record(
                "dashboard_auth_failed", f"Dashboard sign-in failed for {approver_id or '?'}: {exc}.",
                actor=f"unauthenticated:{approver_id or '?'}")
            self._json({"ok": False, "error": str(exc)}, 403)
            return
        fresh = self.server.sessions.sign_in(session.token, approver_id)
        self._json({"ok": True, "approver": approver_id}, cookie=self._cookie(fresh.token))

    def _dispatch(self, path, body, demo, session):
        try:
            if path == "/api/logout":
                self.server.sessions.drop(session.token)
                self._json({"ok": True}, cookie=self._cookie("x", clear=True))
            elif path == "/api/act1":
                self._json(demo.run_act1())
            elif path == "/api/act2":
                self._json(demo.run_act2())
            elif path == "/api/act3":
                self._json(demo.run_act3())
            elif path == "/api/act4":
                out = demo.run_act4()
                self._json(out, 409 if not out.get("ok") else 200)
            elif path == "/api/sign":
                self._sign(body, demo, session)
            elif path == "/api/reset":
                if body.get("confirm") is not True:
                    self._json({"ok": False, "error": "reset needs an explicit confirm"}, 400)
                    return
                self.server.sessions.drop(session.token)
                self._json(demo.reset(), cookie=self._cookie("x", clear=True))
            else:
                self._json({"ok": False, "error": "not found"}, 404)
        except (AuthError, ApprovalError, AgentHalted, DuplicatePayout, StoreError, ValueError) as exc:
            self._json({"ok": False, "error": str(exc)}, 409)
        except Exception:  # noqa: BLE001 - never reflect an internal failure to the browser
            traceback.print_exc()
            self._json({"ok": False, "error": "internal error; see the server console"}, 500)

    def _sign(self, body, demo, session):
        text = {f: body.get(f) for f in ("approval_id", "approver_id", "pin", "confirm_code", "reason")}
        for field in ("approval_id", "approver_id", "pin", "confirm_code"):
            value = text[field]
            if not isinstance(value, str) or not 1 <= len(value) <= 200:
                self._json({"ok": False, "error": f"{field} is required"}, 400)
                return
        if not isinstance(text["reason"], str) or len(text["reason"]) > 200:
            text["reason"] = ""
        decision = body.get("decision")
        if decision not in ("approve", "reject"):
            self._json({"ok": False, "error": "decision must be approve or reject"}, 400)
            return
        if session.approver_id != text["approver_id"]:
            self._json({"ok": False, "error": "the signed-in approver must sign this card themselves"}, 403)
            return
        self._json(demo.sign(decision=decision, reason=text["reason"], **{
            f: text[f] for f in ("approval_id", "approver_id", "pin", "confirm_code")}))

    def log_message(self, *args):
        pass


# ---------------------------------------------------------------------------
# The dashboard
# ---------------------------------------------------------------------------
APP_CSS = r"""
:root{
  --bg:#0b0f17; --panel:#111827; --panel2:#0f1622; --line:#1f2b3d;
  --txt:#e6edf6; --mut:#8b98ad; --acc:#3b82f6; --ok:#22c55e; --warn:#f59e0b;
  --bad:#ef4444; --teal:#14b8a6;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--txt);font:14px/1.55 -apple-system,"Segoe UI",Inter,Roboto,sans-serif;min-height:100vh}
header.top{display:flex;align-items:center;gap:14px;padding:14px 28px;border-bottom:1px solid var(--line);background:#0d1420;position:sticky;top:0;z-index:10}
.logo{width:38px;height:38px;flex-shrink:0;border-radius:10px;background:linear-gradient(135deg,#3b82f6,#14b8a6);display:flex;align-items:center;justify-content:center;font-weight:800;font-size:18px;color:#fff}
.brand h1{font-size:16px;font-weight:700;letter-spacing:.2px}
.brand p{font-size:12px;color:var(--mut)}
.hdr-right{margin-left:auto;display:flex;align-items:center;gap:10px}
.pill{font-size:11px;padding:4px 12px;border-radius:999px;border:1px solid var(--line);color:var(--mut);letter-spacing:.6px;text-transform:uppercase}
.pill.live{color:var(--ok);border-color:#14532d;background:#052e16}
.mode-banner{background:#1c1206;border-bottom:1px solid #78350f;color:#fbbf24;font-size:12px;text-align:center;padding:7px 14px;letter-spacing:.3px}
.banner{border-radius:10px;padding:11px 14px;margin:0 0 16px;font-size:13px;line-height:1.45}
.banner.halt{background:#450a0a;border:1px solid #991b1b;color:#fecaca}
.banner.stale{background:#422006;border:1px solid #a16207;color:#fde68a}
.appr-card .evidence{margin:0;padding-left:16px;color:#e9d5ff;font-size:12px}
.appr-card .expiry{color:#fbbf24;font-size:12px}
.pill.signed{color:#93c5fd;border-color:#1e3a8a;background:#172554}
main{max-width:1380px;margin:0 auto;padding:24px 28px 60px}
.acts{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:22px}
.act-card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;cursor:pointer;transition:.15s;position:relative;overflow:hidden}
.act-card:hover{border-color:var(--acc)}
.act-card.done{border-color:#14532d}
.act-card.active{border-color:var(--acc);box-shadow:0 0 0 1px var(--acc)}
.act-card .n{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:1px}
.act-card h3{font-size:14px;margin:4px 0 6px}
.act-card p{font-size:12px;color:var(--mut);min-height:34px}
.act-card .st{position:absolute;top:12px;right:12px;font-size:11px;padding:2px 9px;border-radius:99px;background:#1a2433;color:var(--mut)}
.act-card.done .st{background:#052e16;color:var(--ok)}
.act-card.active .st{background:#1d4ed8;color:#fff}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:22px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px}
.kpi .l{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px}
.kpi .v{font-size:26px;font-weight:700;font-variant-numeric:tabular-nums}
.kpi .s{font-size:12px;color:var(--mut);margin-top:4px}
.grid2{display:grid;grid-template-columns:1.6fr 1fr;gap:12px;margin-bottom:22px}
.card{min-width:0;overflow-x:auto;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px}
.card h2{font-size:13px;text-transform:uppercase;letter-spacing:1px;color:var(--mut);margin-bottom:14px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--mut);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.6px;padding:8px 10px;border-bottom:1px solid var(--line)}
td{padding:10px;border-bottom:1px solid #16202f;font-variant-numeric:tabular-nums}
tr:last-child td{border-bottom:none}
tr:hover td{background:#131c2b}
.badge{display:inline-block;font-size:11px;font-weight:700;padding:3px 10px;border-radius:99px;letter-spacing:.4px;text-transform:uppercase}
.b-fund{background:#052e16;color:var(--ok)} .b-conv{background:#172554;color:#93c5fd}
.b-def{background:#422006;color:var(--warn)} .b-esc{background:#450a0a;color:#fca5a5}
.b-pend{background:#1a2433;color:var(--mut)} .b-paid{background:#052e16;color:var(--ok)}
.b-appr{background:#3b0764;color:#d8b4fe}
.bar{height:10px;background:#1a2433;border-radius:99px;overflow:hidden;margin:10px 0 6px;position:relative}
.bar>div{height:100%;border-radius:99px;transition:width .5s}
.bar .floor-mark{position:absolute;top:-3px;bottom:-3px;width:2px;background:var(--warn)}
.gauge-wrap{display:flex;align-items:center;gap:16px}
.gauge{width:110px;height:110px;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-direction:column;background:conic-gradient(var(--acc) 0deg,#1a2433 0deg);position:relative;flex:none}
.gauge::before{content:"";position:absolute;inset:12px;border-radius:50%;background:var(--panel)}
.gauge b,.gauge span{position:relative;z-index:1}
.gauge b{font-size:22px} .gauge span{font-size:10px;color:var(--mut);text-transform:uppercase}
.log{max-height:340px;overflow-y:auto;font-size:12.5px}
.log .e{padding:8px 10px;border-left:2px solid var(--line);margin-bottom:6px;background:var(--panel2);border-radius:0 8px 8px 0}
.log .e.act{border-color:var(--acc)} .log .e.warn{border-color:var(--warn)} .log .e.ok{border-color:var(--ok)}
.log .t{color:var(--mut);font-size:11px;margin-right:8px;font-variant-numeric:tabular-nums}
.appr-card{border:1px dashed #7c3aed;border-radius:10px;padding:14px;background:#150a2e;margin-bottom:10px}
.appr-card h4{color:#d8b4fe;font-size:13px;margin-bottom:8px}
.appr-card dl{display:grid;grid-template-columns:130px 1fr;font-size:12.5px;gap:4px 10px}
.appr-card dt{color:var(--mut)} .appr-card dd{font-variant-numeric:tabular-nums}
.sign{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:12px;padding-top:12px;border-top:1px dashed #4c1d95}
.sign .full{grid-column:1/-1}
.sign label{font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:var(--mut);display:block;margin-bottom:3px}
.sign input{width:100%;background:#0b1120;border:1px solid #3b4a63;border-radius:7px;color:var(--txt);padding:8px;font-size:13px;font-family:ui-monospace,Menlo,Consolas,monospace}
.sign input:focus{outline:none;border-color:#7c3aed}
.sign .row{display:flex;gap:8px;margin-top:10px;grid-column:1/-1}
.btn{display:inline-block;background:var(--acc);color:#fff;border:none;border-radius:8px;padding:10px 22px;font-size:13px;font-weight:700;cursor:pointer;transition:.15s}
.btn:hover{background:#2563eb} .btn:disabled{background:#1e293b;color:var(--mut);cursor:not-allowed}
.btn.ghost{background:transparent;border:1px solid var(--line);color:var(--txt)}
.btn.ghost:hover{border-color:var(--acc)}
.btn.violet{background:#7c3aed} .btn.violet:hover{background:#6d28d9}
.btn.red{background:transparent;border:1px solid #7f1d1d;color:#fca5a5}
.toolbar{display:flex;gap:10px;align-items:center;margin-bottom:18px}
#toast{position:fixed;bottom:24px;right:24px;background:#111827;border:1px solid var(--line);border-radius:10px;padding:12px 18px;font-size:13px;display:none;z-index:50;max-width:380px}
.stepper{display:flex;gap:0;margin-bottom:22px}
.step{flex:1;text-align:center;padding:10px;font-size:12px;color:var(--mut);border-bottom:3px solid var(--line);text-transform:uppercase;letter-spacing:.8px}
.step.done{color:var(--ok);border-color:var(--ok)} .step.now{color:#fff;border-color:var(--acc)}
footer{color:var(--mut);font-size:12px;text-align:center;padding:20px}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.login{max-width:420px;margin:8vh auto;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:26px 26px 22px}
.login h2{font-size:14px;text-transform:uppercase;letter-spacing:1px;color:var(--mut);margin-bottom:14px}
.login p{font-size:13px;color:var(--mut);margin-bottom:16px}
.login label{font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:var(--mut);display:block;margin:12px 0 4px}
.login input{width:100%;background:#0b1120;border:1px solid #3b4a63;border-radius:8px;color:var(--txt);padding:10px;font-size:14px}
.login .who{font-size:12px;color:var(--mut);margin-top:14px;line-height:1.7}
.login .who b{color:var(--txt);font-weight:600}
[hidden]{display:none!important}
@media(max-width:900px){.acts,.kpis{grid-template-columns:1fr 1fr}.grid2{grid-template-columns:1fr}}
@media(max-width:600px){header.top{flex-wrap:wrap;padding:14px 18px}.brand{flex:1;min-width:0}.hdr-right{width:100%;justify-content:flex-end}main{padding:20px 16px 40px}.toolbar{flex-wrap:wrap}.kpi{padding:14px 12px}.kpi .v{font-size:23px}.sign{grid-template-columns:1fr}}
"""

PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="csrf" content="__CSRF__">
<link rel="icon" href="data:,">
<link rel="stylesheet" href="/static/app.css">
<title>Adaptive Treasury Controller · Apex Components Co.</title>
</head>
<body>
<div class="mode-banner" role="status">Demo mode · offline mock sandbox · no real accounts or money</div>
<header class="top">
  <div class="logo">A</div>
  <div class="brand"><h1>Adaptive Treasury Controller</h1><p>Apex Components Co. · Airwallex Agentic Banking Hackathon · Track 1</p></div>
  <div class="hdr-right">
    <span class="pill live">● Demo · mock sandbox</span>
    <span class="pill" id="whoPill">not signed in</span>
    <span class="pill" id="cyclePill">—</span>
    <button class="btn ghost" id="btnSignout" hidden type="button">Sign out</button>
    <button class="btn ghost" id="btnReset" hidden type="button">Reset demo</button>
  </div>
</header>

<section class="login" id="login">
  <h2>Sign in as an approver</h2>
  <p>This dashboard is wired only to the offline mock sandbox; no real accounts or money are involved.
     It only moves demo money after a named approver signs each card. Identity and passcode are
     checked by the audit store; five wrong codes lock the account for 15 minutes, and each further
     batch of five doubles the wait without ever resetting the count.</p>
  <form id="loginForm" autocomplete="off">
    <label for="loginId">Approver id</label>
    <input id="loginId" name="approver_id" maxlength="64" required>
    <label for="loginPin">PIN</label>
    <input id="loginPin" name="pin" type="password" maxlength="64" required>
    <div class="row"><button class="btn" id="btnLogin" type="submit">Sign in</button></div>
  </form>
  <div class="who">
    <div><b>sam.treasury</b> treasury_approver · signs FX conversions</div>
    <div><b>dana.controller</b> finance_controller · signs policy exceptions</div>
    <div><b>casey.compliance</b> compliance_officer · signs screening reviews</div>
    <div>The sandbox PINs are seeded by <span class="mono">demo.py</span>, not served to this page.</div>
  </div>
</section>

<div id="dash" hidden>
<main>
  <div class="banner halt" id="haltBanner" role="alert" hidden></div>
  <div class="banner stale" id="staleBanner" role="status" aria-live="polite" hidden></div>
  <div class="stepper" id="stepper">
    <div class="step" id="s0">Ready</div><div class="step" id="s1">Act 1 · Triage</div>
    <div class="step" id="s2">Act 2 · Email shock</div><div class="step" id="s3">Act 3 · Deposit</div>
    <div class="step" id="s4">Act 4 · Execute</div>
  </div>

  <div class="toolbar">
    <button class="btn" id="btnAct" type="button">Run Act 1 · Triage</button>
    <span style="color:var(--mut);font-size:13px" id="hint">Five obligations fall due in 72 hours. Cash above the $10,000 reserve floor covers only part of them.</span>
  </div>

  <div class="kpis">
    <div class="kpi"><div class="l">USD Balance</div><div class="v" id="kUsd">—</div><div class="s" id="kUsdS">opening</div></div>
    <div class="kpi"><div class="l">Opening cash coverage</div><div class="v" id="kCov">—</div><div class="s">of total need, above floor</div></div>
    <div class="kpi"><div class="l">Forecast confidence</div><div class="v" id="kConf">—</div><div class="s" id="kConfS">autonomous FX limit</div></div>
    <div class="kpi"><div class="l">Reserve floor</div><div class="v" style="color:var(--warn)">$10,000</div><div class="s" id="kFloor">hard line · never planned through</div></div>
  </div>

  <div class="grid2">
    <div class="card">
      <h2>Obligations · next 72 hours</h2>
      <table><thead><tr><th>#</th><th>Obligation</th><th>Amount</th><th>Due</th><th>Decision</th><th>Status</th></tr></thead>
      <tbody id="obBody"><tr><td colspan="6" style="color:var(--mut)">Run Act 1 to triage.</td></tr></tbody></table>
      <h2 style="margin-top:20px">Cash position vs reserve floor</h2>
      <div class="bar" id="cashBar"><div id="cashFill" style="width:0%;background:linear-gradient(90deg,#3b82f6,#14b8a6)"></div><div class="floor-mark" id="floorMark" style="left:30%"></div></div>
      <div style="display:flex;justify-content:space-between;font-size:12px;color:var(--mut)"><span id="cashLbl">—</span><span>floor $10,000</span></div>
    </div>
    <div class="card">
      <h2>Forecast confidence</h2>
      <div class="gauge-wrap">
        <div class="gauge" id="gauge"><b id="gVal">—</b><span>confidence</span></div>
        <div><div style="font-size:13px" id="confDetail">Awaiting triage.</div>
        <div style="font-size:12px;color:var(--mut);margin-top:6px" id="limitDetail"></div></div>
      </div>
      <h2 style="margin-top:20px">Approval cards awaiting a signature</h2>
      <div id="apprList"><p style="color:var(--mut);font-size:13px">None.</p></div>
    </div>
  </div>

  <div class="grid2">
    <div class="card"><h2>Event log</h2><div class="log" id="elog"></div></div>
    <div class="card"><h2>Why this is agentic</h2>
      <div style="font-size:13px;color:var(--mut);display:grid;gap:12px">
        <div><b style="color:var(--txt)">Policy in code, judgment in the model.</b><br>The model reads the customer email and explains exceptions. It never touches amounts, limits, or reserves.</div>
        <div><b style="color:var(--txt)">Confidence-gated autonomy.</b><br>When bank data and invoices agree, the agent converts freely. When an email contradicts the forecast, the same action needs a human.</div>
        <div><b style="color:var(--txt)">Event-driven recalculation.</b><br>A deposit re-plans only the decisions scarce cash touched. Everything else stands.</div>
        <div><b style="color:var(--txt)">Approval binding.</b><br>Every card is a SHA-256 digest of amount, currency, counterparty, destination, and evidence. Single use, expiring, superseded on change. You sign it here with your own PIN.</div>
      </div>
    </div>
  </div>
</main>
<footer>Adaptive Treasury Controller · Demo mode · offline mock sandbox · no real money · audit chain verified per cycle</footer>
</div>
<div id="toast" role="status" aria-live="polite"></div>
<script src="/static/app.js" defer></script>
</body>
</html>"""

APP_JS = r"""
const $=id=>document.getElementById(id);
let S=null, busy=false, refreshing=false, lastOk=0;
const HINTS=["Five obligations fall due in 72 hours. Cash above the $10,000 reserve floor covers only part of them.",
"A customer email contradicts the receipt forecast. Watch the confidence — and the autonomy limit — fall.",
"A $25,000 deposit lands mid-cycle. The agent recalculates only the decisions scarce cash touched.",
"Sign every card below with your PIN, then execute. Reserve confirmed.",
"All four acts done. Reserve floor intact, every action in the audit log."];
function csrf(){const m=document.querySelector?document.querySelector('meta[name="csrf"]'):null;return m?m.content:""}
function toast(m){const t=$("toast");t.textContent=m;t.style.display="block";clearTimeout(t._h);t._h=setTimeout(()=>t.style.display="none",5200)}
function fmt$(n){return n==null||isNaN(n)?"—":"$"+Number(n).toLocaleString("en-US",{minimumFractionDigits:2,maximumFractionDigits:2})}
async function api(p,method,body){
  const o={method:method||"POST",headers:{"X-CSRF-Token":csrf()}};
  if(body!==undefined){o.headers["Content-Type"]="application/json";o.body=JSON.stringify(body)}
  const ctl=new AbortController(); const timer=setTimeout(()=>ctl.abort(),10000); o.signal=ctl.signal;
  try{
    const r=await fetch(p,o);let j={};try{j=await r.json()}catch(e){}
    return {status:r.status,json:j};
  }finally{clearTimeout(timer)}
}
function setStale(msg){const b=$("staleBanner");if(!b)return;b.textContent=msg||"";b.hidden=!msg}
function stateBadge(st){const m={pending:["b-pend","pending"],funded:["b-fund","funded"],fx_planned:["b-conv","fx planned"],awaiting_approval:["b-appr","awaiting approval"],converted:["b-conv","converted"],deferred:["b-def","deferred"],escalated:["b-esc","escalated"],paid:["b-paid","paid"]};const x=m[st]||["b-pend",st];return `<span class="badge ${x[0]}">${esc(x[1])}</span>`}
function decBadge(d){if(!d)return"—";const m={FUND:["b-fund","fund"],CONVERT:["b-conv","convert"],DEFER:["b-def","defer"],ESCALATE:["b-esc","escalate"]};const x=m[d.action]||["b-pend",d.action];return `<span class="badge ${x[0]}">${esc(x[1])}</span> <span style="color:var(--mut);font-size:11px">${esc(d.rule||"")}</span>`}
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
function fmtWhen(iso){if(!iso)return "—";const d=new Date(iso);return isNaN(d.getTime())?"—":d.toLocaleString()}
function signingInProgress(){
  const list=$("apprList");
  if(!list||typeof list.contains!=="function"||typeof list.querySelectorAll!=="function")return false;
  if(list.contains(document.activeElement))return true;
  return Array.from(list.querySelectorAll("input")).some(i=>i.value.trim()!=="");
}
function showLogin(){ $("login").hidden=false; $("dash").hidden=true; $("btnSignout").hidden=true; $("btnReset").hidden=true;
  $("whoPill").textContent="not signed in"; $("whoPill").className="pill" }
function showDash(who){ $("login").hidden=true; $("dash").hidden=false; $("btnSignout").hidden=false; $("btnReset").hidden=false;
  $("whoPill").textContent="signed in · "+who; $("whoPill").className="pill signed" }
function signCard(a){
  const evidence=(a.evidence||[]).map(x=>`<li>${esc(x)}</li>`).join("");
  const ceiling=a.max_sell_amount==null?"—":`${esc(a.sell_currency||"")} ${Number(a.max_sell_amount).toLocaleString("en-US",{minimumFractionDigits:2,maximumFractionDigits:2})} max`;
  const expires=a.expires_at?new Date(a.expires_at):null;
  const expired=!!expires&&!isNaN(expires.getTime())&&expires.getTime()<=Date.now();
  return `<div class="appr-card" data-id="${esc(a.id)}"><h4>APPROVAL REQUIRED · ${esc(a.kind)}</h4><dl>
    <dt>Amount</dt><dd>${esc(a.currency)} ${esc(Number(a.amount).toLocaleString())}</dd>
    <dt>Counterparty</dt><dd>${esc(a.counterparty)}</dd>
    <dt>Destination</dt><dd class="mono">${esc(a.destination||"—")}</dd>
    <dt>Pay with</dt><dd>${ceiling}</dd>
    <dt>Evidence</dt><dd>${evidence?`<ul class="evidence">${evidence}</ul>`:"—"}</dd>
    <dt>Why</dt><dd>${esc(a.explanation||"—")}</dd>
    <dt>Needs</dt><dd>${esc((a.eligible_roles||[]).join(" or "))}</dd>
    <dt>Requested by</dt><dd>${esc(a.requested_by)}</dd>
    <dt>Created</dt><dd>${esc(fmtWhen(a.created_at))}</dd>
    <dt>Expires</dt><dd class="${expired?"expiry":""}">${esc(fmtWhen(a.expires_at))}${expired?" · EXPIRED":""}</dd>
    <dt>Code</dt><dd class="mono">${esc(a.code)}</dd></dl>
    <div class="sign">
      <div class="full"><label>Approver id</label><input data-field="approver" maxlength="64" value=""></div>
      <div><label>PIN</label><input data-field="pin" type="password" maxlength="64"></div>
      <div><label>Card code</label><input data-field="code" maxlength="16" placeholder="${esc(a.code)}"></div>
      <div class="full"><label>Note (recorded if you reject)</label><input data-field="reason" maxlength="200"></div>
      <div class="row"><button class="btn violet" data-act="approve" type="button"${expired?" disabled":""}>Sign &amp; bind</button>
      <button class="btn red" data-act="reject" type="button">Reject</button></div>
    </div></div>`;
}
function render(r){
  const halt=!!r.halted;
  const hb=$("haltBanner");
  hb.hidden=!halt;
  hb.textContent=halt?("Agent halted — "+(r.halt_reason||"see the audit log")+". Execution and signing are disabled."):"";
  $("cyclePill").textContent="cycle "+String(r.cycle||"").slice(-6);
  for(let i=0;i<=4;i++){const el=$("s"+i);el.className="step"+(i<r.act||r.act===4?" done":i===r.act?" now":"")}
  const usd=r.balances.USD;
  $("kUsd").textContent=fmt$(usd);
  $("kUsdS").textContent="committed "+fmt$((r.committed||{}).USD||0);
  $("kCov").textContent=r.opening_coverage==null?"—":Math.round(r.opening_coverage*100)+"%";
  const obs=r.obligations;
  if(obs.length){
    $("obBody").innerHTML=obs.map(o=>`<tr><td>${o.id}</td><td><b>${esc(o.label)}</b><br><span style="color:var(--mut);font-size:12px">${esc(o.counterparty)}</span></td><td>${esc(o.currency)} ${Number(o.amount).toLocaleString()}</td><td>${o.due_hours}h${o.deferred_until?`<br><span style="color:var(--mut);font-size:11px">review ${esc(fmtWhen(o.deferred_until))}</span>`:""}</td><td>${decBadge(o.decision)}</td><td>${stateBadge(o.state)}</td></tr>`).join("");
  }
  const floor=r.policy.reserve_floor;
  $("cashFill").style.width=Math.min(100,((usd||0)/(floor*2))*100)+"%";
  $("floorMark").style.left="50%";
  $("cashLbl").textContent=`${fmt$(usd)} balance · ${fmt$(Math.max(0,(usd||0)-floor))} above floor`;
  const c=r.confidence;
  $("kConf").textContent=r.act>=1&&c!=null?c.toFixed(2):"—";
  if(r.act>=1){
    const lim=r.autonomous_limit;
    $("kConfS").textContent="autonomous FX limit "+fmt$(lim);
    $("gVal").textContent=c!=null?c.toFixed(2):"—";
    $("gauge").style.background=`conic-gradient(var(--acc) ${c*360}deg,#1a2433 0deg)`;
    $("confDetail").textContent=c>=0.8?"Bank and invoice data agree the receipt is coming.":"A customer email contradicted the forecast. Autonomy reduced.";
    $("limitDetail").textContent="Autonomous FX limit "+fmt$(lim)+". Conversions above it need a human.";
  }else{
    $("kConfS").textContent="autonomous FX limit";
    $("gVal").textContent="—";
    $("gauge").style.background="conic-gradient(var(--acc) 0deg,#1a2433 0deg)";
    $("confDetail").textContent="Run triage to assess the receipt forecast.";
    $("limitDetail").textContent="The autonomy limit follows forecast confidence.";
  }
  const ap=r.pending_approvals||[];
  if(!signingInProgress()){
    $("apprList").innerHTML=ap.length?ap.map(signCard).join(""):'<p style="color:var(--mut);font-size:13px">None.</p>';
  }
  if(halt&&typeof document.querySelectorAll==="function"){document.querySelectorAll('#apprList button[data-act]').forEach(x=>x.disabled=true)}
  $("elog").innerHTML=(r.log||[]).slice().reverse().map(e=>{const d=new Date(e.t*1000);const ts=d.toTimeString().slice(0,8);return `<div class="e ${esc(e.kind)}"><span class="t">${ts}</span>${esc(e.msg)}</div>`}).join("");
  const b=$("btnAct");
  if(halt){b.disabled=true;b.textContent="Agent halted";$("hint").textContent="Resolve the halt in the audit log; the agent will not execute until it is cleared."}
  else if(r.act>=4){b.disabled=true;b.textContent="Demo complete";$("hint").textContent=HINTS[4]}
  else if(r.act===3&&ap.length){b.disabled=true;b.textContent="Run Act 4 · Execute";$("hint").textContent=ap.length+" card(s) still need a signature above. Act 4 stays locked until they are signed or rejected."}
  else{b.disabled=false;b.textContent="Run Act "+(r.act+1)+" · "+["Triage","Email shock","Deposit arrives","Execute"][r.act];$("hint").textContent=HINTS[r.act]}
}
async function refresh(){
  if(refreshing)return;
  refreshing=true;
  try{
    const r=await api("/api/state","GET");
    if(r.status===401){setStale("");showLogin();return}
    if(!r.json.ok){setStale("");showLogin();return}
    S=r.json; lastOk=Date.now(); setStale(""); showDash(S.approver||"?"); render(S);
  }catch(e){
    setStale("Connection lost — showing the last known data. Retrying…");
  }finally{refreshing=false}
}
async function runNextAct(){
  if(busy||!S||S.act>=4)return;
  if(S.halted){toast("Agent halted: "+(S.halt_reason||"resolve the halt first"));return}
  busy=true; $("btnAct").disabled=true;
  try{const n=S.act+1;toast("Running Act "+n+"…");const r=await api("/api/act"+n);
    if(!r.json.ok)toast("Act "+n+": "+(r.json.error||"failed"));else toast("Act "+n+" complete.");
  }catch(e){toast("Error: "+e.message)}busy=false;await refresh();
}
async function decide(btn){
  if(S&&S.halted){toast("Agent halted: "+(S.halt_reason||"signing is disabled"));return}
  const card=btn.closest(".appr-card"); const id=card.getAttribute("data-id");
  const field=n=>{const el=card.querySelector('[data-field="'+n+'"]');return el?el.value.trim():""};
  const approver=field("approver"), pin=field("pin"), code=field("code");
  if(!approver||!pin||!code){toast("Approver id, PIN and the card code are all required");return}
  if(btn.disabled)return;
  btn.disabled=true;
  try{const r=await api("/api/sign","POST",{approval_id:id,approver_id:approver,pin:pin,confirm_code:code,
                                            decision:btn.getAttribute("data-act"),reason:field("reason")});
    if(r.json.ok){card.querySelectorAll("input").forEach(i=>i.value=""); if(card.contains(document.activeElement))document.activeElement.blur()}
    toast(r.json.ok?(btn.getAttribute("data-act")==="approve"?"Signed. The card is bound to you.":"Rejected. The card is released to a human."):"Signature refused: "+(r.json.error||"failed"));
  }catch(e){toast("Signature failed: "+e.message)}finally{await refresh()}
}
async function resetAll(){
  if(busy)return; busy=true;
  try{const r=await api("/api/reset","POST",{confirm:true}); if(r.json.ok){location.reload()}else toast("Reset failed: "+(r.json.error||""))}
  catch(e){toast("Reset failed: "+e.message)}finally{busy=false}
}
async function signOut(){ if(busy)return; busy=true; try{await api("/api/logout")}catch(e){}finally{busy=false;location.reload()} }
async function doLogin(ev){
  ev.preventDefault();
  const approver=$("loginId").value.trim(), pin=$("loginPin").value;
  if(!approver||!pin){toast("Enter your approver id and PIN");return}
  try{
    const r=await api("/api/login","POST",{approver_id:approver,pin:pin});
    if(r.json.ok){location.reload()}else{toast("Sign-in failed: "+(r.json.error||"not authorised"))}
  }catch(e){toast("Sign-in failed: "+e.message)}
}
document.addEventListener("DOMContentLoaded",()=>{
  $("btnAct").addEventListener("click",runNextAct);
  $("btnReset").addEventListener("click",resetAll);
  $("btnSignout").addEventListener("click",signOut);
  $("loginForm").addEventListener("submit",doLogin);
  $("apprList").addEventListener("click",ev=>{const b=ev.target.closest?ev.target.closest("button[data-act]"):null;if(b)decide(b)});
  refresh(); setInterval(()=>{if(!busy)refresh()},4000);
  setInterval(()=>{if(S&&lastOk&&Date.now()-lastOk>15000)setStale("Data is stale — last successful update was "+Math.round((Date.now()-lastOk)/1000)+"s ago. Retrying…")},5000);
  document.addEventListener("visibilitychange",()=>{if(!document.hidden)refresh()});
});
"""


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=(WEB_MODE,),
                    help="execution mode; the dashboard currently supports only the offline mock sandbox")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args(argv)
    if args.mode != WEB_MODE:
        ap.error("webui.py is mock-only; use demo.py --live or manage.py for live execution")
    srv = HTTPServer(("127.0.0.1", args.port), Handler)
    srv.session = DemoSession()
    srv.sessions = Sessions()
    print(f"Treasury Controller UI → http://127.0.0.1:{args.port}  (mode: {args.mode}; offline demo only)")
    print("Every approval needs a named approver and their PIN; nothing is signed automatically.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.session.close()
        srv.server_close()


if __name__ == "__main__":
    main()
