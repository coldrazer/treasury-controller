"""Behavioral regressions for the application audit; all money stays in the mock bank."""
import copy
import hashlib
import http.client
import importlib
import json
import re
import shutil
import sqlite3
import subprocess
import threading
import demo
import store as store_module
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from http.server import HTTPServer

import pytest

from airwallex_client import AirwallexError, AmbiguousResultError
from agent import AgentHalted, account_fields, payee_key
from approvals import ApprovalError, ApprovalStatus
from config import DEFAULT_POLICY, ConfigError, load_settings
from conftest import APPROVERS, AUDIT_KEY, OPERATOR, D, approve, pin_cycle, pin_draft
from demo import DEMO_APPROVERS
from email_reader import LLMEmailReader, RuleBasedReader, SignalValidationError, parse_signal
from explainer import Explainer
from forecast import apply_email
from journal import OperationStore
from models import State, q2
from screening import ListScreener
from store import AuthError, ChainIntegrityError, DuplicatePayout, LEGACY_SCHEMA, PAYOUT_INDEX, Store, StoreError
from test_agent_e2e import approve_fx, run_acts_1_to_3


def test_replaced_controller_credentials_cannot_authenticate(store):
    salt = b"attacker-salt-123"
    digest = hashlib.scrypt(b"935728", salt=salt, n=16384, r=8, p=1, dklen=32)
    with sqlite3.connect(store.path) as attacker:
        attacker.execute("UPDATE approvers SET salt=?, pin_hash=? WHERE approver_id='dana.controller'",
                         (salt, digest))
    with pytest.raises(AuthError, match="integrity"):
        store.authenticate("dana.controller", "935728")
    assert not store.verify().ok


@pytest.mark.parametrize("change", [
    "roles='[\"finance_controller\"]'", "active=0", "failed_attempts=4",
    "locked_until='2099-01-01T00:00:00+00:00'", "display_name='Impostor'", "kdf='none'",
])
def test_approver_state_edits_are_detected_before_read_or_resign(store, change):
    with sqlite3.connect(store.path) as attacker:
        attacker.execute(f"UPDATE approvers SET {change} WHERE approver_id='sam.treasury'")
    with pytest.raises(AuthError, match="integrity"):
        store.get_approver("sam.treasury")
    with pytest.raises(AuthError, match="integrity"):
        store.set_approver_active("sam.treasury", True)
    assert not store.verify().ok


def test_old_approver_state_cannot_be_replayed_after_deactivation(store):
    store.set_approver_active("sam.treasury", False)
    with sqlite3.connect(store.path) as attacker:
        attacker.execute("UPDATE approvers SET active=1 WHERE approver_id='sam.treasury'")
    with pytest.raises(AuthError, match="integrity"):
        store.authenticate("sam.treasury", APPROVERS["sam.treasury"][2])
    assert not store.verify().ok


def test_approver_read_uses_the_same_snapshot_as_integrity_check(store, monkeypatch):
    check = store._require_approver_integrity

    def edit_after_check():
        check()
        with sqlite3.connect(store.path) as attacker:
            attacker.execute("UPDATE approvers SET roles='[\"finance_controller\"]' "
                             "WHERE approver_id='sam.treasury'")

    monkeypatch.setattr(store, "_require_approver_integrity", edit_after_check)
    assert store.get_approver("sam.treasury").roles == frozenset({"treasury_approver"})


def test_approver_authentication_survives_reopen_and_backup(store, tmp_path):
    store.authenticate("dana.controller", APPROVERS["dana.controller"][2])
    backup = store.backup(tmp_path / "backup.db")
    with Store(backup, audit_key=AUDIT_KEY, read_only=True) as reader:
        assert reader.verify().ok
        assert reader.get_approver("dana.controller").roles == frozenset({"finance_controller"})


def test_legacy_approvers_are_not_silently_trusted(tmp_path):
    path = tmp_path / "legacy.db"
    with Store(path, audit_key=AUDIT_KEY) as legacy:
        salt = b"legacy-salt-1234"
        legacy.conn.execute(
            "INSERT INTO approvers (approver_id,display_name,roles,kdf,salt,pin_hash,created_at,created_by) "
            "VALUES ('legacy.controller','Legacy','[\"finance_controller\"]','scrypt',?,?, 'old','old')",
            (salt, hashlib.scrypt(b"735204", salt=salt, n=16384, r=8, p=1, dklen=32)))
    with Store(path, audit_key=AUDIT_KEY) as upgraded:
        with pytest.raises(AuthError, match="integrity"):
            upgraded.authenticate("legacy.controller", "735204")
        assert not upgraded.verify().ok


@pytest.mark.parametrize("field", ["account_routing_value1", "account_routing_type1",
                                   "account_routing_value2", "account_routing_type2"])
def test_existing_beneficiary_must_match_all_routing_fields(make_agent, mock, field):
    agent = make_agent()
    spec = agent._beneficiary_spec(2)
    bank = spec["beneficiary"]["bank_details"]
    bank.update(account_routing_type1="sort_code", account_routing_value1="111111",
                account_routing_type2="bank_code", account_routing_value2="123456")
    remote = copy.deepcopy(spec)
    remote["id"] = "wrong-destination"
    remote["beneficiary"]["bank_details"][field] = "222222"
    mock.beneficiaries[remote["id"]] = remote
    assert agent._find_beneficiary(agent.records[2]) is None


def test_second_routing_details_are_bound_without_changing_existing_fingerprints():
    bank = {"iban": "DE89370400440532013000", "account_currency": "EUR"}
    expected = {"iban": "DE89370400440532013000", "account_number": "",
                "account_routing_type1": "", "account_routing_value1": "", "swift_code": "",
                "account_currency": "EUR", "bank_country_code": ""}
    assert account_fields(bank) == expected
    assert account_fields({**bank, "account_routing_value2": "123456"}) != expected


def test_cached_beneficiary_is_revalidated_before_reuse(make_agent, mock):
    agent = make_agent()
    rec = agent.records[2]
    beneficiary_id = agent._ensure_beneficiary(rec)
    assert agent._ensure_beneficiary(rec) == beneficiary_id
    mock.beneficiaries[beneficiary_id]["beneficiary"]["bank_details"]["iban"] = "GB33BUKB20201555555555"
    with pytest.raises(AgentHalted, match="beneficiary"):
        agent._ensure_beneficiary(rec)


@pytest.fixture
def dashboard(tmp_path, monkeypatch):
    monkeypatch.setenv("TREASURY_STATE_DIR", str(tmp_path / "ui"))
    monkeypatch.setenv("LLM_PROVIDER", "rules")
    module = importlib.import_module("webui")
    session = module.DemoSession()
    server = HTTPServer(("127.0.0.1", 0), module.Handler)
    server.session = session
    server.sessions = module.Sessions()
    server.timeout = 5
    yield module, session, server
    session.agent.store.close()
    session.mock.stop()
    server.server_close()


def ui_request(server, path, *, method="POST", headers=None, body=None):
    payload = json.dumps(body).encode() if body is not None else None
    result = {}

    def send():
        try:
            conn = http.client.HTTPConnection(*server.server_address, timeout=5)
            conn.request(method, path, body=payload, headers=headers or {})
            response = conn.getresponse()
            result.update(status=response.status, body=response.read(), headers=response.headers)
            conn.close()
        except Exception as exc:
            result["error"] = exc

    worker = threading.Thread(target=send, daemon=True)
    worker.start()
    server.handle_request()  # SQLite stays on its owning thread.
    worker.join(timeout=6)
    assert "error" not in result, result
    return result


def issued_cookie(response):
    """The whole `name=value` pair the server handed out, ready to be sent straight back."""
    raw = response["headers"].get("Set-Cookie")
    return raw.split(";")[0] if raw else None


class Browser:
    """The dashboard's own client: a cookie jar plus the CSRF token read out of the page it came with."""

    def __init__(self, server):
        self.server = server
        self.cookie = None
        self.csrf = None

    def headers(self):
        head = {"Host": f"127.0.0.1:{self.server.server_port}",
                "Origin": f"http://127.0.0.1:{self.server.server_port}",
                "Content-Type": "application/json"}
        if self.csrf is not None:
            head["X-CSRF-Token"] = self.csrf
        if self.cookie is not None:
            head["Cookie"] = self.cookie
        return head

    def get(self, path):
        return ui_request(self.server, path, method="GET", headers=self.headers())

    def post(self, path, body):
        return ui_request(self.server, path, headers=self.headers(), body=body)

    def json(self, response):
        return json.loads(response["body"])

    def load(self):
        response = self.get("/")
        token = issued_cookie(response)
        if token:
            self.cookie = token
        self.csrf = re.search(rb'<meta name="csrf" content="([0-9a-f]+)"', response["body"]).group(1).decode()
        return response

    def sign_in(self, approver_id, pin):
        if self.csrf is None:
            self.load()
        response = self.post("/api/login", {"approver_id": approver_id, "pin": pin})
        if response["status"] == 200:
            self.cookie = issued_cookie(response)
            self.load()  # the signed-in session carries a different CSRF token
        return response

    def run(self, act):
        return self.post(f"/api/act{act}", {})

    def cards(self):
        return {card["kind"]: card for card in self.json(self.get("/api/state"))["pending_approvals"]}


def sign_body(card, approver_id, pin, decision="approve", **changes):
    return {"approval_id": card["id"], "approver_id": approver_id, "pin": pin, "decision": decision,
            "confirm_code": card["code"], **changes}


def test_dashboard_script_is_external_and_parses(dashboard):
    module, _, server = dashboard
    served = ui_request(server, "/static/app.js", method="GET")
    assert served["status"] == 200 and served["body"].decode() == module.APP_JS
    assert "<script>" not in module.PAGE and "onclick=" not in module.PAGE
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js required for the dashboard JavaScript parser check")
    parsed = subprocess.run([node, "-e", "new (require('vm').Script)(require('fs').readFileSync(0,'utf8'))"],
                            input=module.APP_JS, text=True, capture_output=True)
    assert parsed.returncode == 0, parsed.stderr


def test_dashboard_page_carries_no_authority_to_the_browser(dashboard):
    _, _, server = dashboard
    page = ui_request(server, "/", method="GET")
    csp = page["headers"]["Content-Security-Policy"]
    assert "default-src 'none'" in csp and "script-src 'self';" in csp
    assert page["headers"]["X-Frame-Options"] == "DENY"
    assert page["headers"]["X-Content-Type-Options"] == "nosniff"
    assert page["headers"]["Cache-Control"] == "no-store"
    cookie = page["headers"]["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie and "Path=/" in cookie


def test_dashboard_reports_actual_balances_and_commitments(dashboard):
    _, session, _ = dashboard
    session.run_act1()
    snap = session.snapshot()
    assert snap["balances"] == {"USD": 37500.0, "EUR": 500.0, "GBP": 0.0}
    assert snap["committed"]["USD"] == 26991.45
    assert snap["committed"]["EUR"] == 500.0
    assert snap["opening_coverage"] == 0.587
    session.agent.confidence = Decimal("0.60")
    assert session.snapshot()["autonomous_limit"] == 5000.0


@pytest.mark.parametrize("flaw", ["missing-csrf", "wrong-csrf", "csrf-of-another-browser", "no-cookie",
                                  "unknown-cookie", "foreign-origin", "null-origin", "attacker-host"])
def test_dashboard_rejects_forged_requests_without_mutation(dashboard, flaw):
    _, session, server = dashboard
    browser = Browser(server)
    assert browser.sign_in("sam.treasury", DEMO_APPROVERS["sam.treasury"][2])["status"] == 200
    assert browser.run(1)["status"] == 200
    forged = browser.headers()
    if flaw == "missing-csrf":
        forged.pop("X-CSRF-Token")
    elif flaw == "wrong-csrf":
        forged["X-CSRF-Token"] = "f" * 64
    elif flaw == "csrf-of-another-browser":
        other = Browser(server)
        other.load()
        forged["X-CSRF-Token"] = other.csrf
    elif flaw == "no-cookie":
        forged.pop("Cookie")
    elif flaw == "unknown-cookie":
        forged["Cookie"] = browser.cookie.split("=")[0] + "=" + "0" * 64
    elif flaw == "foreign-origin":
        forged["Origin"] = "http://unrelated.local:9876"
    elif flaw == "null-origin":
        forged["Origin"] = "null"
    else:
        forged["Host"] = f"attacker.example:{server.server_port}"
        forged["Origin"] = f"http://attacker.example:{server.server_port}"
    before = session.agent.confidence
    response = ui_request(server, "/api/act2", headers=forged, body={})
    assert response["status"] == 403
    assert session.act == 1 and session.agent.confidence == before


def test_dashboard_holds_every_act_behind_a_signed_in_approver(dashboard):
    _, session, server = dashboard
    anonymous = Browser(server)
    anonymous.load()  # the page hands a CSRF token to anyone, and that is all it hands out
    assert anonymous.post("/api/act1", {})["status"] == 401
    assert anonymous.get("/api/state")["status"] == 401
    assert session.act == 0
    assert anonymous.post("/api/login", {"approver_id": "sam.treasury", "pin": "000000"})["status"] == 403
    assert session.act == 0
    assert anonymous.post("/api/act1", {})["status"] == 401


def test_dashboard_act4_stays_locked_until_a_human_signs_each_card(dashboard):
    _, session, server = dashboard
    treasury = Browser(server)
    assert treasury.sign_in("sam.treasury", DEMO_APPROVERS["sam.treasury"][2])["status"] == 200
    wire = []
    for act in (1, 2, 3):
        response = treasury.run(act)
        assert response["status"] == 200 and treasury.json(response)["ok"], response["body"]
        wire.append(response["body"].decode())
    assert session.act == 3

    locked = treasury.run(4)
    assert locked["status"] == 409 and session.act == 3
    assert "await a signature" in treasury.json(locked)["error"]
    assert treasury.json(treasury.get("/api/state"))["balances"]["USD"] == 62500.0

    cards = treasury.cards()
    assert set(cards) == {"FX_CONVERSION", "POLICY_EXCEPTION"}
    binding = {value for req in session.agent.pending_approvals() for value in (req.digest, req.destination_fp) if value}
    served = treasury.get("/api/state")["body"].decode()
    # nothing the acts returned may carry the binding record: the code an approver types is a
    # prefix of the digest, and the fingerprint is the payee's real account
    assert not any(secret in "".join(wire + [served]) for secret in binding)
    assert "digest" not in served and "destination_fp" not in served

    # a signed-in approver cannot borrow another approver's identity, even holding their PIN
    hijack = treasury.post("/api/sign", sign_body(cards["POLICY_EXCEPTION"], "dana.controller",
                                                  DEMO_APPROVERS["dana.controller"][2]))
    assert hijack["status"] == 403 and len(session.agent.pending_approvals()) == 2
    # and her own role does not cover the controller's card
    overreach = treasury.post("/api/sign", sign_body(cards["POLICY_EXCEPTION"], "sam.treasury",
                                                     DEMO_APPROVERS["sam.treasury"][2]))
    assert overreach["status"] == 409 and len(session.agent.pending_approvals()) == 2

    controller = Browser(server)
    assert controller.sign_in("dana.controller", DEMO_APPROVERS["dana.controller"][2])["status"] == 200
    signed = controller.post("/api/sign", sign_body(controller.cards()["POLICY_EXCEPTION"], "dana.controller",
                                                    DEMO_APPROVERS["dana.controller"][2]))
    assert signed["status"] == 200 and treasury.json(signed)["pending"] == 1
    assert treasury.run(4)["status"] == 409 and session.act == 3

    signed = treasury.post("/api/sign", sign_body(treasury.cards()["FX_CONVERSION"], "sam.treasury",
                                                 DEMO_APPROVERS["sam.treasury"][2]))
    assert signed["status"] == 200 and treasury.json(signed)["pending"] == 0

    executed = treasury.run(4)
    assert executed["status"] == 200, executed["body"]
    assert session.act == 4
    assert treasury.json(executed)["audit"]["verified"] is True
    assert treasury.json(executed)["audit"]["problems"] == []
    assert treasury.json(treasury.get("/api/state"))["balances"]["USD"] == 34308.56


def test_dashboard_signature_needs_the_card_own_code_and_a_real_pin(dashboard):
    _, session, server = dashboard
    browser = Browser(server)
    browser.sign_in("sam.treasury", DEMO_APPROVERS["sam.treasury"][2])
    for act in (1, 2, 3):
        browser.run(act)
    card = browser.cards()["FX_CONVERSION"]
    pin = DEMO_APPROVERS["sam.treasury"][2]

    assert browser.post("/api/sign", sign_body(card, "sam.treasury", "000000"))["status"] == 409
    assert browser.post("/api/sign", sign_body(card, "sam.treasury", pin, confirm_code="AAAAAAAA"))["status"] == 409
    incomplete = sign_body(card, "sam.treasury", pin)
    incomplete.pop("confirm_code")
    assert browser.post("/api/sign", incomplete)["status"] == 400
    assert len(session.agent.pending_approvals()) == 2 and session.act == 3

    rejected = browser.post("/api/sign", sign_body(card, "sam.treasury", pin, decision="reject",
                                                  reason="conversion would breach the reserve floor"))
    assert rejected["status"] == 200 and len(session.agent.pending_approvals()) == 1
    assert "FX_CONVERSION" not in browser.cards()


def test_dashboard_reset_needs_an_explicit_confirm_and_ends_the_session(dashboard):
    _, session, server = dashboard
    browser = Browser(server)
    browser.sign_in("dana.controller", DEMO_APPROVERS["dana.controller"][2])
    assert browser.run(1)["status"] == 200
    assert browser.post("/api/reset", {})["status"] == 400 and session.act == 1
    cleared = browser.post("/api/reset", {"confirm": True})
    assert cleared["status"] == 200 and issued_cookie(cleared).endswith("=x")  # the session is invalidated
    assert session.act == 0 and session.snapshot()["opening_coverage"] is None
    assert browser.post("/api/act1", {})["status"] == 403  # the revoked cookie is no longer a session


JS_RENDER_HARNESS = """
const vm=require('vm'),fs=require('fs');const input=JSON.parse(fs.readFileSync(0,'utf8'));
const elements={};
if(input.focusedCard)elements.apprList={style:{},innerHTML:"SENTINEL",contains(){return true},querySelectorAll(){return []}};
const document={getElementById(id){return elements[id]??=(id==='toast'?{style:{}}:{style:{}})},
addEventListener(){},querySelector(){return null},querySelectorAll(){return []}};
const context={document,fetch:()=>new Promise(()=>{}),setInterval:()=>{},setTimeout:()=>0,clearTimeout:()=>{},
location:{},console};
vm.createContext(context);vm.runInContext(input.script,context);
const frames=[];
for(const state of input.states){vm.runInContext('render('+JSON.stringify(state)+')',context);
frames.push(JSON.parse(JSON.stringify(Object.fromEntries(Object.entries(elements)
.map(([k,v])=>[k,{textContent:v.textContent,innerHTML:v.innerHTML,hidden:v.hidden,disabled:v.disabled}])))));}
console.log(JSON.stringify(frames));
"""


def test_dashboard_reset_clears_rendered_confidence(dashboard):
    module, session, _ = dashboard
    session.run_act1()
    session.run_act2()
    before = session.snapshot()
    session.reset()
    ready = session.snapshot()
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js required for the dashboard render check")
    rendered = subprocess.run([node, "-e", JS_RENDER_HARNESS],
                              input=json.dumps({"script": module.APP_JS, "states": [before, ready]}),
                              text=True, capture_output=True)
    assert rendered.returncode == 0, rendered.stderr
    frames = json.loads(rendered.stdout)
    assert frames[0]["kConf"]["textContent"] != "—" and frames[0]["apprList"]["innerHTML"].count("appr-card") == 2
    card_html = frames[0]["apprList"]["innerHTML"]
    for fact in ("Destination", "Pay with", "Evidence", "Why", "Expires"):
        assert fact in card_html
    assert frames[1]["kConf"]["textContent"] == "—"
    assert frames[1]["kCov"]["textContent"] == "—"
    assert "appr-card" not in frames[1]["apprList"]["innerHTML"]


def test_dashboard_renders_a_halt_and_does_not_replace_a_focused_card(dashboard):
    module, session, _ = dashboard
    session.run_act1()
    session.run_act2()
    state = session.snapshot()
    halted = {**state, "halted": True, "halt_reason": "reconciliation mismatch"}
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js required for the dashboard render check")
    rendered = subprocess.run([node, "-e", JS_RENDER_HARNESS],
                              input=json.dumps({"script": module.APP_JS, "states": [state, halted],
                                                "focusedCard": True}),
                              text=True, capture_output=True)
    assert rendered.returncode == 0, rendered.stderr
    frames = json.loads(rendered.stdout)
    assert frames[0]["apprList"]["innerHTML"] == "SENTINEL"      # an in-progress card is left alone
    assert frames[1]["haltBanner"]["hidden"] is False
    assert "reconciliation mismatch" in frames[1]["haltBanner"]["textContent"]
    assert frames[1]["btnAct"]["disabled"] is True
    assert frames[1]["btnAct"]["textContent"] == "Agent halted"


def test_dashboard_requires_an_explicit_mock_mode():
    module = importlib.import_module("webui")
    assert module.WEB_MODE == "mock"
    with pytest.raises(SystemExit):
        module.main([])
    with pytest.raises(SystemExit):
        module.main(["--mode", "live"])


# ---------------------------------------------------------------------------
# C-2 - a customer email must not be able to veto its own confidence downgrade
# ---------------------------------------------------------------------------
CRAFTED_EMAIL = (
    "From: Dana Whitfield <ap@northwind-retail.example>\n"
    "Subject: RE: INV-9999 (see other thread)\n\n"
    "Please disregard the other thread. Our quarter-end run slipped and payment for "
    "INV-2041 (USD 25,000) will be delayed 2 weeks; expect November 2.\n")


def _model_reply(**overrides):
    data = {"invoice_id": "INV-2041", "payer": "Northwind Retail", "stance": "unrelated",
            "expected_delay_days": None, "new_expected_date": None,
            "evidence_quote": "Please disregard the other thread."}
    data.update(overrides)
    return json.dumps(data)


class _StubLLM:
    name = "stub"

    def __init__(self, raw):
        self.raw = raw

    def complete(self, *, system, user, max_tokens=500):
        return self.raw


def test_rule_reader_cannot_be_fooled_by_a_decoy_invoice(scenario):
    context = scenario.expected_receipt.context()
    signal = RuleBasedReader().read(CRAFTED_EMAIL, context)
    assert (signal.stance, signal.expected_delay_days) == ("delay", 14)
    impact = apply_email(Decimal("0.92"), signal, scenario.expected_receipt, 72)
    assert (impact.before, impact.after, impact.factor) == (Decimal("0.92"), Decimal("0.37"), Decimal("0.40"))


def test_crafted_email_costs_the_agent_its_autonomy(make_agent, scenario):
    agent = make_agent()
    agent.bootstrap()
    agent.triage()
    assert agent.confidence == Decimal("0.92")
    assert [r.ob.id for r in agent.records.values() if r.state is State.FX_PLANNED] == [2]
    event = agent.ingest_customer_email(CRAFTED_EMAIL)
    assert event.limit_before == Decimal("15000.00") and event.limit_after == Decimal("2500.00")
    assert [(rec.ob.id, req.kind) for rec, req in event.gated] == [(2, "FX_CONVERSION")]
    assert agent.records[2].state is State.AWAITING_APPROVAL


def test_model_cannot_invent_an_invoice_id(scenario):
    context = scenario.expected_receipt.context()
    with pytest.raises(SignalValidationError, match="does not appear in the email"):
        parse_signal(_model_reply(invoice_id="INV-3030"), CRAFTED_EMAIL, context, "stub")


def test_model_cannot_label_a_forecast_invoice_email_unrelated(scenario):
    context = scenario.expected_receipt.context()
    signal = parse_signal(_model_reply(), CRAFTED_EMAIL, context, "stub")
    assert (signal.stance, signal.expected_delay_days) == ("delay", 14)
    assert "not unrelated" in signal.note


def test_model_cannot_shrink_the_delay_the_email_states(scenario):
    context = scenario.expected_receipt.context()
    signal = parse_signal(_model_reply(stance="delay", expected_delay_days=1), CRAFTED_EMAIL, context, "stub")
    assert signal.expected_delay_days == 14
    assert apply_email(Decimal("0.92"), signal, scenario.expected_receipt, 72).after == Decimal("0.37")


def test_model_and_rule_readers_reach_the_same_verdict(scenario):
    context = scenario.expected_receipt.context()
    llm_signal = LLMEmailReader(_StubLLM(_model_reply())).read(CRAFTED_EMAIL, context)
    rule_signal = RuleBasedReader().read(CRAFTED_EMAIL, context)
    assert (llm_signal.stance, llm_signal.expected_delay_days) == ("delay", 14)
    assert (llm_signal.stance, llm_signal.expected_delay_days, apply_email(
        Decimal("0.92"), llm_signal, scenario.expected_receipt, 72).after) == (
        rule_signal.stance, rule_signal.expected_delay_days, apply_email(
        Decimal("0.92"), rule_signal, scenario.expected_receipt, 72).after)


def test_the_longest_stated_delay_is_the_one_used(scenario):
    context = scenario.expected_receipt.context()
    signal = RuleBasedReader().read("Payment for INV-2041 is late: three days, maybe a week.", context)
    assert (signal.stance, signal.expected_delay_days) == ("delay", 7)


def test_an_email_that_really_is_unrelated_still_escapes(scenario):
    context = scenario.expected_receipt.context()
    text = ("From: ops@northwind-retail.example\nSubject: INV-9999 stock count\n\n"
            "Our quarterly stock count moved to a warehouse two hours away; nothing to do with billing.\n")
    signal = RuleBasedReader().read(text, context)
    assert signal.stance == "unrelated"
    assert apply_email(Decimal("0.92"), signal, scenario.expected_receipt, 72).after == Decimal("0.92")


# ---------------------------------------------------------------------------
# M-6 / M-7 - what the reader claims must be in the email, and the email's own
#             words must not be recycled into the prompt that writes the note
# ---------------------------------------------------------------------------
def test_reader_cannot_add_facts_the_email_never_stated(scenario):
    context = scenario.expected_receipt.context()
    signal = parse_signal(_model_reply(payer="Globex Shipping International", new_expected_date="December 31"),
                          CRAFTED_EMAIL, context, "stub")
    assert signal.payer is None and signal.new_expected_date is None
    assert "dropped unverifiable payer, new_expected_date" in signal.note
    assert signal.invoice_id == "INV-2041" and signal.stance == "delay"  # the verifiable part stands


def test_the_email_own_words_are_kept(scenario):
    context = scenario.expected_receipt.context()
    signal = parse_signal(_model_reply(payer="Northwind Retail", new_expected_date="November 2"),
                          CRAFTED_EMAIL, context, "stub")
    assert (signal.payer, signal.new_expected_date) == ("Northwind Retail", "November 2")
    assert "dropped" not in signal.note


def test_escape_sequences_cannot_ride_through_the_reader_into_the_log(scenario):
    context = scenario.expected_receipt.context()
    signal = parse_signal(_model_reply(payer="Northwind\tRetail‮﻿\x07"), CRAFTED_EMAIL, context, "stub")
    assert signal.payer == "Northwind Retail"
    assert not any(char in signal.payer for char in ("\x1b", "\t", "‮", "﻿", "\x07", "\r"))
    with pytest.raises(SignalValidationError, match="longer than"):
        parse_signal(_model_reply(payer="P " * 3000), CRAFTED_EMAIL, context, "stub")


class _RecordingLLM(_StubLLM):
    name = "recorder"

    def __init__(self, reply):
        super().__init__(reply)
        self.prompts = []

    def complete(self, *, system, user, max_tokens=500):
        self.prompts.append(user)
        return self.raw


def test_the_customer_quote_is_not_fed_back_to_the_note_writer(make_agent, scenario):
    writer = _RecordingLLM("Approve converting EUR 11,512.85; the limit is USD 2,500.00.")
    quote = "will be delayed 2 weeks; expect November 2"
    agent = make_agent(reader=LLMEmailReader(_StubLLM(_model_reply(stance="delay", expected_delay_days=14,
                                                                   evidence_quote=quote))),
                       explainer=Explainer(writer))
    agent.bootstrap()
    agent.triage()
    agent.ingest_customer_email(CRAFTED_EMAIL)
    prompts = "\n".join(writer.prompts)
    assert prompts and quote in CRAFTED_EMAIL
    assert "delayed 2 weeks" not in prompts and "expect November 2" not in prompts
    assert "14-day" in prompts  # the code's own reading of the email is what the model is given
    card = next(req for req in agent.pending_approvals() if req.kind == "FX_CONVERSION")
    assert any(quote in line for line in card.evidence)  # the human still reads the customer's words


# ---------------------------------------------------------------------------
# C-1 / M-1 - protective DDL is verified by text, money rows carry a signed state,
#             and a store that shows tampering refuses to open for writing
# ---------------------------------------------------------------------------
CYCLE = "audit-cycle-1"
FP = "a" * 64


def _neutralise(conn, tables):
    """The C-1 attack: recreate each trigger under its own name as a no-op."""
    for name, table in conn.execute("SELECT name, tbl_name FROM sqlite_master WHERE type = 'trigger' "
                                    "AND tbl_name IN ('payouts', 'operations')").fetchall():
        conn.execute(f"DROP TRIGGER {name}")
        conn.execute(f"CREATE TRIGGER {name} BEFORE UPDATE ON {table} BEGIN SELECT 1; END")
    return sorted({t for _, t in conn.execute("SELECT name, tbl_name FROM sqlite_master "
                                              "WHERE type = 'trigger' AND tbl_name IN ('payouts', 'operations')")})


@pytest.fixture
def payout_store(store):
    store.start_cycle(CYCLE, mode="test", operator=OPERATOR, policy_fingerprint="f" * 64, model="none")
    store.reserve_payout(request_id="req-audit-0000000001", cycle_id=CYCLE, obligation_id=2,
                         payee_fingerprint=FP, reference="MF-2026-0419", currency="EUR", amount="12000.00")
    store.update_payout("req-audit-0000000001", status="in_flight", transfer_id="trf-audit-1")
    return store


def test_money_rows_verify_before_any_tampering(payout_store):
    assert payout_store.verify().ok


def test_no_op_triggers_recreated_under_familiar_names_are_reported(payout_store):
    with sqlite3.connect(payout_store.path) as attacker:
        _neutralise(attacker, ("payouts", "operations"))
        attacker.execute("UPDATE payouts SET amount = '1.00' WHERE request_id = 'req-audit-0000000001'")
    report = payout_store.verify()
    assert not report.ok
    assert "protective schema rewritten" in " ".join(report.problems)
    assert "payouts req-audit-0000000001: row state integrity mismatch" in " ".join(report.problems)


def test_operations_row_rewrite_is_reported(payout_store):
    payout_store.create_operation(CYCLE, "fx:2", "req-audit-operation1")
    with sqlite3.connect(payout_store.path) as attacker:
        _neutralise(attacker, ("payouts", "operations"))
        attacker.execute(f"UPDATE operations SET status = 'succeeded', result = '{{}}' WHERE cycle_id = '{CYCLE}'")
    report = payout_store.verify()
    assert not report.ok
    assert any(f"operations {CYCLE}|fx:2: row state integrity mismatch" in p for p in report.problems)


def test_tampered_ledger_refuses_a_writer_but_still_opens_for_inspection(payout_store):
    payout_store.close()
    with sqlite3.connect(payout_store.path) as attacker:
        _neutralise(attacker, ("payouts", "operations"))
    with pytest.raises(ChainIntegrityError, match="tampering"):
        Store(payout_store.path, audit_key=AUDIT_KEY)
    with Store(payout_store.path, audit_key=AUDIT_KEY, read_only=True) as inspector:
        assert not inspector.verify().ok


def test_money_rows_written_before_state_signing_are_seeded_on_open(tmp_path):
    path = tmp_path / "legacy-money.db"
    with Store(path, audit_key=AUDIT_KEY) as store:
        store.start_cycle(CYCLE, mode="test", operator=OPERATOR, policy_fingerprint="f" * 64, model="none")
    with sqlite3.connect(path) as legacy:
        ts = "2025-01-01T00:00:00+00:00"
        legacy.execute("INSERT INTO payouts (request_id, cycle_id, obligation_id, payee_fingerprint, reference,"
                       " currency, amount, transfer_id, status, created_at, updated_at)"
                       " VALUES ('req-legacy-00000001', ?, 2, ?, 'MF-OLD', 'EUR', '900.00', NULL, 'paid', ?, ?)",
                       (CYCLE, FP, ts, ts))
    with Store(path, audit_key=AUDIT_KEY, read_only=True) as before:
        assert before.verify().pending == ["payouts req-legacy-00000001: no authenticated state"]
    with Store(path, audit_key=AUDIT_KEY) as upgraded:
        assert upgraded.verify().entries == 1  # exactly one entry: the seeded state
        assert upgraded.verify().ok
        events = [e["event"] for e in upgraded.audit_entries()]
        assert events == ["payouts_state"]


# ---------------------------------------------------------------------------
# H-3 - the invoice, not its figure, is what may only be paid once
# ---------------------------------------------------------------------------
def test_a_changed_amount_is_a_second_attempt_not_a_new_invoice(payout_store):
    with pytest.raises(DuplicatePayout):
        payout_store.reserve_payout(request_id="req-audit-0000000002", cycle_id=CYCLE, obligation_id=2,
                                    payee_fingerprint=FP, reference="MF-2026-0419", currency="EUR",
                                    amount="11999.99")
    assert payout_store.live_payout(payee_fingerprint=FP, reference="MF-2026-0419",
                                    currency="EUR")["request_id"] == "req-audit-0000000001"


def test_an_older_ledger_is_upgraded_to_the_invoice_keyed_guard(tmp_path):
    path = tmp_path / "legacy-guard.db"
    with Store(path, audit_key=AUDIT_KEY) as store:
        store.start_cycle(CYCLE, mode="test", operator=OPERATOR, policy_fingerprint="f" * 64, model="none")
    with sqlite3.connect(path) as old_version:
        old_version.execute("DROP INDEX one_live_payout_per_invoice")
        old_version.execute(LEGACY_SCHEMA[PAYOUT_INDEX])
    with Store(path, audit_key=AUDIT_KEY) as upgraded:
        report = upgraded.verify()
        assert report.ok and report.problems == []
        assert upgraded.payouts() == []
        with pytest.raises(DuplicatePayout):
            for cents in ("12000.00", "11999.99"):
                upgraded.reserve_payout(request_id=f"req-upgrade-{cents[-2:]}00000", cycle_id=CYCLE,
                                        obligation_id=2, payee_fingerprint=FP, reference="MF-2026-0419",
                                        currency="EUR", amount=cents)


def test_an_unrecognised_guard_is_tampering_rather_than_something_to_upgrade(tmp_path):
    path = tmp_path / "forgiven-guard.db"
    with Store(path, audit_key=AUDIT_KEY) as store:
        store.start_cycle(CYCLE, mode="test", operator=OPERATOR, policy_fingerprint="f" * 64, model="none")
    with sqlite3.connect(path) as attacker:
        attacker.execute("DROP INDEX one_live_payout_per_invoice")
        attacker.execute("CREATE UNIQUE INDEX one_live_payout_per_invoice ON payouts (reference)")
    with pytest.raises(ChainIntegrityError, match="tampering"):
        Store(path, audit_key=AUDIT_KEY)


def test_a_run_told_to_pay_less_for_a_paid_invoice_is_refused_by_the_bank(make_agent, scenario, simulator, mock):
    first = make_agent(obligations=[scenario.obligation(2)])
    run_acts_1_to_3(first, scenario, simulator)
    approve_fx(first)
    first.execute()
    assert len(mock.conversions) == 1 and len(mock.transfers) == 1
    mock.balances.update({"USD": D("37500.00"), "EUR": D("500.00")})  # a wallet refilled for the next run
    second = make_agent(obligations=[replace(scenario.obligation(2), amount=D("11999.99"))])
    second.bootstrap()
    second.triage()
    [result] = second.execute()
    assert result.status == "blocked" and "already paid" in result.detail
    assert "EUR 12,000.00" in result.detail and "EUR 11,999.99" in result.detail
    assert len(mock.conversions) == 1 and len(mock.transfers) == 1


def test_a_run_that_cannot_see_the_transfer_is_still_refused_by_the_database(make_agent, scenario, simulator, mock):
    first = make_agent(obligations=[scenario.obligation(2)])
    run_acts_1_to_3(first, scenario, simulator)
    approve_fx(first)
    first.execute()
    mock.balances.update({"USD": D("37500.00"), "EUR": D("500.00")})
    second = make_agent(obligations=[replace(scenario.obligation(2), amount=D("11999.99"))])
    second._prior_payment = lambda rec: None  # pretend the remote listing missed it
    second.bootstrap()
    second.triage()
    [result] = second.execute()
    assert result.status == "blocked" and "live payout recorded" in result.detail
    assert "12000.00 EUR" in result.detail
    assert len(mock.conversions) == 1 and len(mock.transfers) == 1


# ---------------------------------------------------------------------------
# H-5 - the book takes exactly the deposit that was notified, never the rest
# ---------------------------------------------------------------------------
def test_a_smaller_arrival_than_notified_is_never_booked_as_the_deposit(make_agent, scenario, simulator, mock):
    agent = make_agent()
    agent.bootstrap()
    agent.triage()
    dep = scenario.deposit
    simulator.deposit(amount=dep.amount - Decimal("5000"), currency=dep.currency,
                      payer_name=dep.payer_name, reference=dep.reference)
    with pytest.raises(AgentHalted, match=f"shows only {dep.currency}"):
        agent.on_balance_event(currency=dep.currency, amount=dep.amount, reference=dep.reference, wait_seconds=0)
    assert agent.ledger.balance(dep.currency) == agent.ledger.opening[dep.currency]
    assert not any(e.event == "deposit_confirmed" for e in agent.audit.entries)


def test_movement_beside_the_notified_deposit_halts_before_the_plan_resumes(make_agent, scenario, simulator, mock):
    agent = make_agent()
    agent.bootstrap()
    agent.triage()
    dep = scenario.deposit
    simulator.deposit(amount=dep.amount + Decimal("5000"), currency=dep.currency,
                      payer_name=dep.payer_name, reference=dep.reference)
    with pytest.raises(AgentHalted, match="unexpected movement during deposit"):
        agent.on_balance_event(currency=dep.currency, amount=dep.amount, reference=dep.reference, wait_seconds=0)
    assert not any(e.event == "deposit_confirmed" for e in agent.audit.entries)
    assert agent.records[3].state is not State.FUNDED  # nothing was recalculated on unidentified cash


# ---------------------------------------------------------------------------
# H-6 - what a person approved was a maximum cost, so the settled figure is measured again
# ---------------------------------------------------------------------------
class _SettlesDearer:
    """The bank settles the locked quote for more than it said selling would cost."""

    def __init__(self, client, *, factor):
        self.__dict__["_client"], self.__dict__["factor"] = client, Decimal(factor)

    def __getattr__(self, name):
        return getattr(self._client, name)

    def create_conversion(self, *args, **kwargs):
        conv = self._client.create_conversion(*args, **kwargs)
        return {**conv, "sell_amount": q2(conv["sell_amount"] * self.factor)}


def _plan_an_fx_conversion(agent, scenario):
    agent.bootstrap()
    agent.triage()
    agent.ingest_customer_email(scenario.customer_email)
    return next(req for req in agent.pending_approvals() if req.kind == "FX_CONVERSION")


def test_a_conversion_that_settles_above_the_approved_ceiling_never_reaches_the_book(make_agent, scenario, client):
    agent = make_agent(obligations=[scenario.obligation(2)], client_override=_SettlesDearer(client, factor="1.05"))
    card = _plan_an_fx_conversion(agent, scenario)
    agent.approve(card.id, approver_id="sam.treasury", pin=APPROVERS["sam.treasury"][2], confirm_code=card.code)
    with pytest.raises(AgentHalted, match="ceiling bound into approval"):
        agent.execute()
    assert agent.ledger.balance("EUR") == agent.ledger.opening["EUR"]  # the dearer cost was never accepted
    assert agent.ledger.balance("USD") == agent.ledger.opening["USD"]
    assert not agent.autonomous_executed


def test_a_conversion_that_settles_beyond_the_autonomous_tier_halts_the_run(make_agent, scenario, client):
    agent = make_agent(obligations=[scenario.obligation(2)], client_override=_SettlesDearer(client, factor="1.30"))
    agent.bootstrap()
    agent.triage()
    assert agent.records[2].state is State.FX_PLANNED  # no human was asked, because the quote was inside the tier
    with pytest.raises(AgentHalted, match="autonomous limit"):
        agent.execute()
    assert agent.autonomous_executed == D("0.00")
    assert agent.ledger.balance("EUR") == agent.ledger.opening["EUR"]


# ---------------------------------------------------------------------------
# H-7 - an id the bank cannot be asked about stays locked; it is never retired for a fresh try
# ---------------------------------------------------------------------------
def _journal(store):
    store.start_cycle(CYCLE, mode="test", operator=OPERATOR, policy_fingerprint="f" * 64, model="none")
    return OperationStore(store, CYCLE)


def test_a_lookup_that_fails_leaves_the_request_id_locked(store):
    ops = _journal(store)
    rid = ops.request_id("fx:2")
    calls = []

    def create(_):
        calls.append(1)
        raise AmbiguousResultError("processed, connection dropped before the reply")

    def lookup(_):
        raise OSError("the bank is not answering")

    with pytest.raises(AmbiguousResultError, match="could not be asked"):
        ops.run("fx:2", create, lookup)
    assert ops.request_id("fx:2") == rid
    assert store.get_operation(CYCLE, "fx:2")["status"] == "unresolved"
    assert calls == [1]  # one request, then the id is locked pending a human


def test_a_duplicate_reply_plus_a_failing_lookup_stays_unresolved(store):
    ops = _journal(store)
    rid = ops.request_id("transfer:ob2")

    def create(_):
        raise AirwallexError("duplicate", code="duplicate_request_id")

    def lookup(_):
        raise OSError("the bank is not answering")

    with pytest.raises(AmbiguousResultError, match="stays unresolved"):
        ops.run("transfer:ob2", create, lookup)
    assert ops.request_id("transfer:ob2") == rid
    assert store.get_operation(CYCLE, "transfer:ob2")["status"] == "unresolved"


def test_a_lookup_that_works_still_resolves_the_ambiguous_call(store):
    ops = _journal(store)
    rid = ops.request_id("fx:2")

    def create(_):
        raise AmbiguousResultError("processed, connection dropped before the reply")

    assert ops.run("fx:2", create, lambda seen: {"request_id": seen, "id": "trf-1"})[0] == \
        {"request_id": rid, "id": "trf-1"}
    assert store.get_operation(CYCLE, "fx:2")["status"] == "succeeded"


# ---------------------------------------------------------------------------
# H-2 - the production guard reads the host as DNS does, and no other host gets the credentials
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("url", ["https://api.airwallex.com", "https://api.airwallex.com.",
                                 "https://API.AIRWALLEX.COM.", "https://api.airwallex.com:443",
                                 "https://api.airwallex.com/money"])
def test_every_spelling_of_the_production_host_is_refused(url):
    with pytest.raises(ConfigError, match="production"):
        load_settings({"AWX_BASE_URL": url, "AWX_CLIENT_ID": "id", "AWX_API_KEY": "key"})


@pytest.mark.parametrize("url", ["https://attacker.example", "https://airwallex.com.evil.test.",
                                 "https://api.airwallex.com.evil.test"])
def test_an_unfamiliar_host_never_sees_the_credentials(url):
    with pytest.raises(ConfigError, match="not a known Airwallex host"):
        load_settings({"AWX_BASE_URL": url, "AWX_CLIENT_ID": "id", "AWX_API_KEY": "key",
                       "TREASURY_ALLOW_PRODUCTION": "1"})


def test_a_host_a_person_named_exactly_is_accepted_exactly():
    assert load_settings({"AWX_BASE_URL": "https://proxy.corp.example", "TREASURY_ALLOW_HOST": "proxy.corp.example",
                          "AWX_CLIENT_ID": "id", "AWX_API_KEY": "key"}).base_url == "https://proxy.corp.example"
    with pytest.raises(Exception, match="not a known Airwallex host"):
        load_settings({"AWX_BASE_URL": "https://proxy.corp.example", "TREASURY_ALLOW_HOST": "other.corp.example",
                       "AWX_CLIENT_ID": "id", "AWX_API_KEY": "key"})


def test_unattended_approval_is_refused_on_a_trailing_dot_production_host(tmp_path, monkeypatch):
    monkeypatch.setenv("TREASURY_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AWX_CLIENT_ID", "id")
    monkeypatch.setenv("AWX_API_KEY", "key")
    monkeypatch.setenv("TREASURY_ALLOW_PRODUCTION", "1")
    monkeypatch.setenv("AWX_BASE_URL", "https://api.airwallex.com.")
    assert demo.main(["--live", "--yes"]) == 2


# ---------------------------------------------------------------------------
# M-4 - guessing a passcode is met with a longer wait each time, never a forgiven counter
# ---------------------------------------------------------------------------
def _approver_row(store, approver_id):
    return store.conn.execute("SELECT failed_attempts, locked_until FROM approvers WHERE approver_id = ?",
                              (approver_id,)).fetchone()


def test_each_batch_of_guesses_locks_the_account_for_longer(store, monkeypatch):
    class _Clock(datetime):
        """The store's own clock, wound forward by the test, so a lockout can expire without editing a
        row (which the signed approver state would refuse anyway)."""
        shift = timedelta(0)

        @classmethod
        def now(cls, tz=None):
            return datetime.now(tz) + cls.shift

    monkeypatch.setattr(store_module, "datetime", _Clock)

    def guess(times):
        for _ in range(times):
            with pytest.raises(AuthError, match="incorrect"):
                store.authenticate("sam.treasury", "wrong-passcode-1")

    guess(4)
    assert (_approver_row(store, "sam.treasury")["failed_attempts"],
            _approver_row(store, "sam.treasury")["locked_until"]) == (4, None)
    guess(1)                                          # the fifth closes the first batch
    row = _approver_row(store, "sam.treasury")
    assert row["failed_attempts"] == 5                # the lock does not wipe the count
    assert row["locked_until"] is not None
    with pytest.raises(AuthError, match="locked"):
        store.authenticate("sam.treasury", APPROVERS["sam.treasury"][2])  # even the right code waits
    _Clock.shift += timedelta(minutes=16)
    guess(5)                                          # guessing resumes; the tenth closes batch two
    row = _approver_row(store, "sam.treasury")
    assert row["failed_attempts"] == 10
    assert _Clock.fromisoformat(row["locked_until"]) - _Clock.now(timezone.utc) > timedelta(minutes=25)


def test_a_passcode_of_digits_only_is_not_enough_to_enrol(store):
    for weak in ("12345678", "000000000012", "42-42-42"):
        if weak.isdigit():
            with pytest.raises(AuthError, match="digits only"):
                store.enroll_approver(f"weak.{weak[:4]}", "Weak", ["treasury_approver"], weak, created_by="t")
    with pytest.raises(AuthError, match="8 characters"):
        store.enroll_approver("weak.short", "Weak", ["treasury_approver"], "fx-42", created_by="t")
    store.enroll_approver("fit.approver", "Fit", ["treasury_approver"], "approve-fx-2026", created_by="t")
    assert store.authenticate("fit.approver", "approve-fx-2026").approver_id == "fit.approver"


# ---------------------------------------------------------------------------
# M-5 - reading or copying the ledger is an audited action with a name on it
# ---------------------------------------------------------------------------
def _admin_cli(tmp_path, monkeypatch):
    monkeypatch.setenv("TREASURY_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("TREASURY_AUDIT_KEY", AUDIT_KEY.hex())
    monkeypatch.setenv("TREASURY_ADMIN_PIN", "release-funds-7")
    monkeypatch.setenv("TREASURY_NEW_PIN", "release-funds-7")
    import manage
    assert manage.main(["add-approver", "--bootstrap", "--id", "dana.controller", "--name", "Dana",
                        "--roles", "finance_controller"]) == 0
    return manage


def _events(path):
    with Store(path, audit_key=AUDIT_KEY, read_only=True) as store:
        return [e["event"] for e in store.audit_entries()]


def test_admin_reads_and_copies_are_signed_in_and_written_to_the_chain(tmp_path, monkeypatch):
    manage = _admin_cli(tmp_path, monkeypatch)
    assert manage.main(["list-payouts"]) == 2               # nobody signed in
    assert manage.main(["export-audit", "--out", str(tmp_path / "export")]) == 2
    assert manage.main(["list-approvers", "--by", "dana.controller"]) == 0
    assert manage.main(["list-payouts", "--by", "dana.controller"]) == 0
    assert manage.main(["backup", "--by", "dana.controller", "--out", str(tmp_path / "bk" / "t.db")]) == 0
    events = _events(tmp_path / "treasury.db")
    assert "roster_read" in events and "payouts_read" in events and "backup_taken" in events
    assert "audit_exported" not in events                   # the refused export wrote nothing
    assert "admin_auth_failed" not in events


def test_an_export_records_whose_hands_the_ledger_passed_through(tmp_path, monkeypatch):
    manage = _admin_cli(tmp_path, monkeypatch)
    out = tmp_path / "export"
    assert manage.main(["export-audit", "--by", "dana.controller", "--out", str(out)]) == 0
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["exported_by"] == "approver:dana.controller"
    exported = [json.loads(line)["event"] for line in (out / "audit_log.jsonl").read_text().splitlines()]
    assert "approver_enrolled" in exported and "audit_exported" not in exported
    assert "audit_exported" in _events(tmp_path / "treasury.db")  # written after the snapshot was taken


def test_verify_audit_stays_open_to_a_suspected_forgery_without_a_pin(tmp_path, monkeypatch):
    """The inspection path is the command that must keep working on a ledger a writer is refused."""
    manage = _admin_cli(tmp_path, monkeypatch)
    path = tmp_path / "treasury.db"
    with sqlite3.connect(path) as attacker:
        _neutralise(attacker, ("payouts", "operations"))
    assert manage.main(["verify-audit"]) == 1               # no --by: it only reports integrity facts
    with pytest.raises(ChainIntegrityError, match="tampering"):
        Store(path, audit_key=AUDIT_KEY)                     # a writer is refused...
    assert manage.main(["export-audit", "--by", "dana.controller",
                        "--out", str(tmp_path / "x")]) == 2  # ...and so is the export of a copy


# ---------------------------------------------------------------------------
# M-2 - a card belongs to the ledger, not to the process that wrote it
# ---------------------------------------------------------------------------
def _stranded_card(make_agent, *, cycle_id, ttl_hours):
    """A run that died after asking a human. An unpinned first payment always needs a signature,
    whatever the forecast says, so the ask is the same in every one of these tests."""
    agent = make_agent(pin=False, cycle_id=cycle_id,
                       policy=replace(DEFAULT_POLICY, approval_ttl_hours=ttl_hours))
    agent.bootstrap()
    agent.triage()
    return agent, agent.approvals.get(agent.records[2].approval_id)


def test_a_card_outliving_its_run_is_expired_when_the_cycle_reopens(make_agent, store):
    _, card = _stranded_card(make_agent, cycle_id="cycle-dead", ttl_hours=0)
    left = [r["id"] for r in store.approval_rows("cycle-dead") if r["status"] == "pending"]
    assert card.id in left                        # nothing closed them when the process stopped
    revived = make_agent(pin=False, cycle_id="cycle-dead")
    assert revived.approvals.get(card.id).status is ApprovalStatus.EXPIRED
    assert not [r for r in store.approval_rows("cycle-dead") if r["status"] == "pending"]
    assert [e.event for e in revived.audit.entries].count("approval_expired") == len(left)
    with pytest.raises(ApprovalError, match="expired"):
        approve(revived, card)


def test_a_reopened_run_supersedes_the_card_an_earlier_run_left_open(make_agent, store):
    _, card = _stranded_card(make_agent, cycle_id="cycle-twice", ttl_hours=24)
    asked_before = len([r for r in store.approval_rows("cycle-twice") if r["status"] == "pending"])
    revived = make_agent(pin=False, cycle_id="cycle-twice")
    revived.bootstrap()
    revived.triage()
    assert store.conn.execute("SELECT status FROM approvals WHERE id = ?", (card.id,)).fetchone()[0] == "superseded"
    open_now = [r for r in store.approval_rows("cycle-twice") if r["status"] == "pending"]
    assert len(open_now) == asked_before          # it asks again for the same obligations, not for new ones
    obligations = [r["obligation_id"] for r in open_now]
    assert len(obligations) == len(set(obligations))  # and never two live asks for one obligation


# ---------------------------------------------------------------------------
# M-3 - a destination never moves without its record
# ---------------------------------------------------------------------------
def test_a_payee_change_is_refused_without_its_audit_event(store):
    pin_cycle(store)
    with pytest.raises(StoreError, match="audit event"):
        store.repin_payee("acme", "a" * 64, "IBAN ****0001 · EUR", changed_by="dana.controller",
                          reason="IBAN confirmed by call-back with the registered officer", audit=None)
    assert store.get_payee("acme") is None


def test_a_payee_change_rolls_back_when_its_record_cannot_be_written(store):
    with pytest.raises(sqlite3.IntegrityError):
        store.repin_payee("acme", "a" * 64, "IBAN ****0001 · EUR", changed_by="dana.controller",
                          reason="IBAN confirmed by call-back with the registered officer",
                          audit=pin_draft("acme", "IBAN ****0001 · EUR", cycle_id="cycle-never-started"))
    assert store.get_payee("acme") is None
    assert store.conn.execute("SELECT count(*) FROM payee_history").fetchone()[0] == 0


def test_the_pinned_destination_and_its_record_are_written_as_one_act(make_agent, scenario, store):
    agent = make_agent(pin=False)
    agent.bootstrap()
    agent.triage()
    approve(agent, agent.approvals.get(agent.records[2].approval_id))
    agent.execute()
    assert [e.event for e in agent.audit.entries].count("payee_pinned") == 1     # what the run shows
    assert [e["event"] for e in store.audit_entries()].count("payee_pinned") == 1  # what the chain holds
    assert store.verify().ok and store.get_payee(payee_key(scenario.obligation(2))) is not None


# ---------------------------------------------------------------------------
# M-9 - a designated name wearing extra words is still the designated name
# ---------------------------------------------------------------------------
def _screener(tmp_path, *names):
    listed = tmp_path / "list.json"
    listed.write_text(json.dumps({"version": "v", "entries": [{"name": name} for name in names]}),
                      encoding="utf-8")
    return ListScreener(listed)


def test_extra_words_on_a_designated_name_do_not_clear_the_hit(tmp_path):
    s = _screener(tmp_path, "Blackwater Shell Trading Ltd")
    assert s.screen(["Blackwater Shell Trading Ltd Consultants"]).hit
    assert s.screen(["Blackwater Shell Trading Holdings (International)"]).hit
    assert s.screen(["Blackwater Shell Trading"]).hit


def test_a_shorter_form_of_a_designated_name_is_screened_too(tmp_path):
    assert _screener(tmp_path, "Orion Front Holdings Group Ltd").screen(["Orion Front Holdings"]).hit


def test_one_shared_word_is_not_the_same_counterparty(tmp_path):
    s = _screener(tmp_path, "Meridian Freight")
    assert s.screen(["Meridian Freight"]).hit
    assert not s.screen(["Meridian Coffee House"]).hit
    assert not s.screen(["Freight Systems"]).hit


def test_a_one_word_list_entry_does_not_swallow_every_name(tmp_path):
    s = _screener(tmp_path, "Alpha Ltd")
    assert s.screen(["Alpha"]).hit
    assert not s.screen(["Alpha Shipping Ltd"]).hit
