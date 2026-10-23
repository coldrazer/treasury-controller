"""Security and regulatory controls: one test (at least) per control in AUDIT_REPORT.md."""
import hashlib
import json
import os
import sqlite3
import stat
from dataclasses import replace
from decimal import Decimal

import pytest

import policy as P
from approvals import ApprovalError, ApprovalStatus
from conftest import APPROVERS, AUDIT_KEY, OPERATOR, approve, pin_cycle, pin_draft
from config import DEFAULT_POLICY, ConfigError, load_dotenv, load_settings
from models import Obligation, State
from screening import ListScreener
from simulation import ScenarioError, load_scenario
from store import (GENESIS, AuthError, DuplicatePayout, Store, StoreError, StoreLocked, _split_sql, SCHEMA,
                   canonical, redact)

D = Decimal
IBAN = "DE89370400440532013000"


def run_full(agent, scenario, simulator):
    agent.bootstrap()
    agent.triage()
    agent.ingest_customer_email(scenario.customer_email)
    dep = scenario.deposit
    simulator.deposit(amount=dep.amount, currency=dep.currency, payer_name=dep.payer_name, reference=dep.reference)
    agent.on_balance_event(currency=dep.currency, amount=dep.amount, reference=dep.reference, wait_seconds=0)
    approve(agent, next(r for r in agent.pending_approvals() if r.kind == "FX_CONVERSION"))
    results = agent.execute()
    res = next(r for r in results if r.obligation_id == 2)
    simulator.advance_transfer(res.transfer["id"], "SENT")
    simulator.advance_transfer(res.transfer["id"], "PAID")
    agent.refresh_payouts()
    agent.checkpoint("final")
    return res


def drop_triggers(store):
    for (name,) in store.conn.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'").fetchall():
        store.conn.execute(f'DROP TRIGGER "{name}"')


def restore_triggers(store):
    for statement in _split_sql(SCHEMA):
        if statement.lstrip().startswith("CREATE TRIGGER"):
            store.conn.execute(statement)


# =============================================================================
# Database: append-only, immutable terms, enforced transitions
# =============================================================================
FORBIDDEN = [
    "UPDATE audit_log SET reason = 'edited'",
    "DELETE FROM audit_log WHERE seq = 1",
    "UPDATE approvals SET amount = '1.00'",
    "UPDATE approvals SET evidence = '[\"nothing\"]'",
    "DELETE FROM approvals",
    "UPDATE approvals SET status = 'approved' WHERE status = 'consumed'",
    "UPDATE approvals SET status = 'pending' WHERE status = 'superseded'",
    "UPDATE payouts SET amount = '1.00'",
    "UPDATE payouts SET status = 'initiated' WHERE status = 'paid'",
    "UPDATE payouts SET note = 'rewritten' WHERE status = 'paid'",
    "DELETE FROM payouts",
    "UPDATE operations SET result = '{}' WHERE status = 'succeeded'",
    "DELETE FROM operations",
    "UPDATE cycles SET operator = 'someone-else'",
    "DELETE FROM cycles",
    "UPDATE payees SET fingerprint = '" + "a" * 64 + "'",
    "DELETE FROM payees",
    "DELETE FROM payee_history",
    "UPDATE meta SET value = 'sha256' WHERE key = 'audit_chain'",
    "DELETE FROM snapshots",
    "DELETE FROM approvers",
    "UPDATE approvers SET approver_id = 'renamed' WHERE approver_id = 'sam.treasury'",
    "INSERT INTO audit_log (cycle_id, ts, act, actor, event, reason, data, prev_hash, entry_hash) "
    "SELECT cycle_id, ts, act, actor, 'forged', 'forged', '{}', '" + GENESIS + "', '" + "b" * 64 + "' FROM cycles LIMIT 1",
]


@pytest.mark.parametrize("sql", FORBIDDEN)
def test_database_refuses_tampering(make_agent, scenario, simulator, store, sql):
    run_full(make_agent(), scenario, simulator)
    before = store.conn.total_changes
    with pytest.raises(sqlite3.DatabaseError):
        store.conn.execute(sql)
    assert store.conn.total_changes == before
    assert store.verify().ok


def test_retired_request_id_can_never_be_reused(store):
    store.start_cycle("cycle-r", mode="test", operator="t", policy_fingerprint="0" * 64, model="none")
    store.create_operation("cycle-r", "conv", "rid-0000000001")
    store.rotate_request_id("cycle-r", "conv", "rid-0000000002", "expired quote")
    with pytest.raises(sqlite3.DatabaseError):
        store.create_operation("cycle-r", "other", "rid-0000000001")
    with pytest.raises(sqlite3.DatabaseError):  # rotating back onto a retired id
        store.rotate_request_id("cycle-r", "conv", "rid-0000000001", "x")
    with pytest.raises(sqlite3.DatabaseError):  # request ids are unique across all operations
        store.create_operation("cycle-r", "third", "rid-0000000002")


def test_one_live_payout_per_invoice_is_a_database_rule(store):
    store.start_cycle("cycle-p", mode="test", operator="t", policy_fingerprint="0" * 64, model="none")
    terms = dict(cycle_id="cycle-p", obligation_id=2, payee_fingerprint="c" * 64, reference="MF-1", currency="EUR",
                 amount=D("12000.00"))
    store.reserve_payout(request_id="rid-aaaaaaaaaa", **terms)
    store.reserve_payout(request_id="rid-aaaaaaaaaa", **terms)          # idempotent for the same request
    with pytest.raises(DuplicatePayout):
        store.reserve_payout(request_id="rid-bbbbbbbbbb", **terms)
    store.update_payout("rid-aaaaaaaaaa", status="failed")              # a failed payout frees the invoice
    store.reserve_payout(request_id="rid-cccccccccc", **terms)
    with pytest.raises(sqlite3.DatabaseError):
        store.update_payout("rid-aaaaaaaaaa", status="paid")            # failed is terminal


# =============================================================================
# Audit chain: tamper evidence
# =============================================================================
def test_chain_verifies_after_a_full_cycle(make_agent, scenario, simulator, store):
    run_full(make_agent(), scenario, simulator)
    report = store.verify()
    assert report.ok and report.chain == "hmac-sha256" and report.entries > 30


def test_edited_entry_is_detected_even_if_triggers_are_restored(make_agent, scenario, simulator, store):
    run_full(make_agent(), scenario, simulator)
    drop_triggers(store)
    store.conn.execute("UPDATE audit_log SET reason = 'nothing to see' WHERE event = 'approval_granted'")
    assert any("protective triggers missing" in p for p in store.verify().problems)
    restore_triggers(store)
    problems = store.verify().problems
    assert len(problems) == 1 and "entry hash mismatch" in problems[0]


def test_forger_without_the_key_cannot_rebuild_the_chain(make_agent, scenario, simulator, store):
    run_full(make_agent(), scenario, simulator)
    drop_triggers(store)
    rows = store.conn.execute("SELECT * FROM audit_log ORDER BY seq").fetchall()
    prev = GENESIS
    for row in rows:  # rewrite one entry and recompute every hash with plain SHA-256
        reason = "approved by nobody" if row["event"] == "approval_granted" else row["reason"]
        entry = {"cycle_id": row["cycle_id"], "ts": row["ts"], "act": row["act"], "actor": row["actor"],
                 "event": row["event"], "reason": reason, "obligation_id": row["obligation_id"],
                 "data": json.loads(row["data"]), "prev_hash": prev}
        new_hash = hashlib.sha256(canonical(entry).encode()).hexdigest()
        store.conn.execute("UPDATE audit_log SET reason = ?, prev_hash = ?, entry_hash = ? WHERE seq = ?",
                           (reason, prev, new_hash, row["seq"]))
        prev = new_hash
    restore_triggers(store)
    report = store.verify()
    assert not report.ok and sum("entry hash mismatch" in p for p in report.problems) == len(rows)


def test_deleted_rows_are_detected(make_agent, scenario, simulator, store):
    run_full(make_agent(), scenario, simulator)
    drop_triggers(store)
    store.conn.execute("DELETE FROM audit_log WHERE seq = 5")
    problems = store.verify().problems
    assert any("gap" in p for p in problems) and any("does not link" in p for p in problems)


def test_truncated_tail_is_detected_by_the_sequence_and_by_anchors(make_agent, scenario, simulator, store):
    run_full(make_agent(), scenario, simulator)
    anchor = store.head()
    drop_triggers(store)
    store.conn.execute("DELETE FROM audit_log WHERE seq = ?", (anchor["seq"],))
    assert any("truncated" in p for p in store.verify().problems)
    # A careful attacker also rewinds the sequence counter; only an external anchor catches that.
    store.conn.execute("UPDATE sqlite_sequence SET seq = seq - 1 WHERE name = 'audit_log'")
    restore_triggers(store)
    assert store.verify().ok
    report = store.verify(anchors=[anchor])
    assert not report.ok and "anchored entry" in report.problems[0]


def test_edited_approval_terms_break_their_digest(make_agent, scenario, simulator, store):
    run_full(make_agent(), scenario, simulator)
    drop_triggers(store)
    store.conn.execute("UPDATE approvals SET amount = '99999.00' WHERE kind = 'FX_CONVERSION' AND status = 'consumed'")
    restore_triggers(store)
    assert any("no longer match the digest" in p for p in store.verify().problems)


def test_audit_key_is_required_and_checked(tmp_path):
    path = tmp_path / "keyed.db"
    Store(path, audit_key=AUDIT_KEY).close()
    with pytest.raises(StoreError, match="TREASURY_AUDIT_KEY"):
        Store(path)
    with pytest.raises(StoreError, match="does not match"):
        Store(path, audit_key=bytes(32))
    Store(tmp_path / "plain.db").close()
    with pytest.raises(StoreError, match="re-keyed"):
        Store(tmp_path / "plain.db", audit_key=AUDIT_KEY)


def test_short_audit_keys_are_refused():
    from store import load_audit_key
    with pytest.raises(StoreError):
        load_audit_key("00" * 16)
    assert load_audit_key("ab" * 32) == bytes.fromhex("ab" * 32)


def test_live_mode_fails_closed_without_a_key(tmp_path):
    from runtime import open_store
    settings = load_settings({"TREASURY_STATE_DIR": str(tmp_path)})
    with pytest.raises(StoreError, match="TREASURY_AUDIT_KEY is required"):
        open_store(settings, mode="live")
    store = open_store(settings, mode="mock", cycle_id="mock-cycle")       # mock gets a demo key
    assert store.keyed
    store.close()


# =============================================================================
# Files: permissions and single writer
# =============================================================================
def test_database_files_are_owner_only_and_single_writer(make_agent, scenario, simulator, store, tmp_path):
    run_full(make_agent(), scenario, simulator)
    for suffix in ("", "-wal", "-shm"):
        p = tmp_path / ("treasury.db" + suffix)
        if p.exists():
            assert stat.S_IMODE(p.stat().st_mode) == 0o600, p
    assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700
    with pytest.raises(StoreLocked):
        Store(tmp_path / "treasury.db", audit_key=AUDIT_KEY)
    reader = Store(tmp_path / "treasury.db", audit_key=AUDIT_KEY, read_only=True)   # auditors can still read
    assert reader.verify().ok
    with pytest.raises(sqlite3.OperationalError):
        reader.conn.execute("INSERT INTO meta VALUES ('x', 'y')")
    reader.close()


# =============================================================================
# Data minimisation: no full bank identifiers at rest
# =============================================================================
def test_no_full_account_numbers_are_stored(make_agent, scenario, simulator, store, tmp_path):
    run_full(make_agent(), scenario, simulator)
    store.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    blob = b"".join((tmp_path / n).read_bytes() for n in ("treasury.db", "treasury.db-wal")
                    if (tmp_path / n).exists())
    assert IBAN.encode() not in blob and b"0532013000" not in blob
    assert b"****3000" in blob                                     # masked form is what auditors see


def test_redaction_masks_nested_identifiers():
    out = redact({"beneficiary": {"bank_details": {"iban": IBAN, "account_name": "Mueller"}},
                  "items": [{"account_number": "12345678"}], "authorization": "Bearer abc.def"})
    assert out["beneficiary"]["bank_details"] == {"iban": "****3000", "account_name": "Mueller"}
    assert out["items"][0]["account_number"] == "****5678" and out["authorization"] == "****"


# =============================================================================
# Approvals: authentication, roles, segregation of duties
# =============================================================================
def _to_act4(agent, scenario, simulator):
    agent.bootstrap()
    agent.triage()
    agent.ingest_customer_email(scenario.customer_email)
    return next(r for r in agent.pending_approvals() if r.kind == "FX_CONVERSION")


def test_wrong_pin_is_refused_and_audited(make_agent, scenario, simulator, mock):
    agent = make_agent(obligations=[scenario.obligation(2)])
    req = _to_act4(agent, scenario, simulator)
    with pytest.raises(ApprovalError, match="incorrect"):
        agent.approve(req.id, approver_id="sam.treasury", pin="000000", confirm_code=req.code)
    with pytest.raises(ApprovalError, match="incorrect"):
        agent.approve(req.id, approver_id="nobody", pin=APPROVERS["sam.treasury"][2], confirm_code=req.code)
    failures = [e for e in agent.audit.entries if e.event == "approval_auth_failed"]
    assert [e.actor for e in failures] == ["unauthenticated:sam.treasury", "unauthenticated:nobody"]
    assert agent.approvals.get(req.id).status is ApprovalStatus.PENDING
    assert agent.execute() == [] and not mock.conversions


def test_repeated_wrong_pins_lock_the_approver(make_agent, scenario, simulator, store):
    agent = make_agent()
    req = _to_act4(agent, scenario, simulator)
    for _ in range(5):
        with pytest.raises(ApprovalError):
            agent.approve(req.id, approver_id="sam.treasury", pin="111111", confirm_code=req.code)
    with pytest.raises(ApprovalError, match="locked"):
        approve(agent, req)                                    # even the right PIN is refused now


def test_deactivated_approver_cannot_approve(make_agent, scenario, simulator, store):
    agent = make_agent()
    req = _to_act4(agent, scenario, simulator)
    store.set_approver_active("sam.treasury", False)
    with pytest.raises(ApprovalError, match="deactivated"):
        approve(agent, req)


def test_requester_cannot_approve_their_own_request(make_agent, scenario, simulator, store):
    store.enroll_approver(OPERATOR, "The operator", ["treasury_approver", "finance_controller"], "operator-2468",
                          created_by="test-setup")
    agent = make_agent()
    req = _to_act4(agent, scenario, simulator)
    with pytest.raises(ApprovalError, match="segregation of duties"):
        agent.approve(req.id, approver_id=OPERATOR, pin="operator-2468", confirm_code=req.code)
    # and the database refuses it even if the application check were bypassed
    with pytest.raises(sqlite3.DatabaseError):
        store.conn.execute("UPDATE approvals SET status = 'approved', decided_by = ? WHERE id = ?", (OPERATOR, req.id))


@pytest.mark.parametrize("kind,wrong,right", [
    ("FX_CONVERSION", "casey.compliance", "sam.treasury"),
    ("POLICY_EXCEPTION", "sam.treasury", "dana.controller"),
])
def test_only_the_right_role_can_decide(make_agent, scenario, simulator, kind, wrong, right):
    agent = make_agent()
    _to_act4(agent, scenario, simulator)
    req = next(r for r in agent.pending_approvals() if r.kind == kind)
    with pytest.raises(ApprovalError, match="lacks a role"):
        approve(agent, req, approver_id=wrong)
    assert any(e.event == "approval_refused" for e in agent.audit.entries)
    approve(agent, req, approver_id=right)


def test_wrong_confirmation_code_is_refused(make_agent, scenario, simulator):
    agent = make_agent()
    req = _to_act4(agent, scenario, simulator)
    with pytest.raises(ApprovalError, match="code"):
        approve(agent, req, code="DEADBEEF")


def test_approval_rows_record_who_requested_and_who_approved(make_agent, scenario, simulator, store):
    run_full(make_agent(), scenario, simulator)
    row = next(r for r in store.approval_rows() if r["kind"] == "FX_CONVERSION" and r["status"] == "consumed")
    assert row["requested_by"] == OPERATOR and row["decided_by"] == "sam.treasury"
    assert row["destination"].startswith("IBAN ****3000") and len(row["destination_fp"]) == 64


def test_pins_are_stored_as_scrypt_hashes(store):
    raw = store.conn.execute("SELECT kdf, salt, pin_hash FROM approvers WHERE approver_id = 'sam.treasury'").fetchone()
    assert raw["kdf"].startswith("scrypt") and len(raw["salt"]) == 16 and APPROVERS["sam.treasury"][2].encode() not in raw["pin_hash"]
    for weak in ("111111", "482916", "fx", "aaaaaaaa", "12345678"):
        with pytest.raises(AuthError):
            store.enroll_approver("weak.pin", "Weak", ["treasury_approver"], weak, created_by="t")
    with pytest.raises(AuthError):
        store.enroll_approver("Bad Id", "Bad", ["treasury_approver"], "fx-approve-42", created_by="t")
    with pytest.raises(AuthError):
        store.enroll_approver("super.user", "Root", ["admin"], "fx-approve-42", created_by="t")


# =============================================================================
# Payee controls: pinning, change detection, new payees
# =============================================================================
def _altered(scenario, iban="GB33BUKB20201555555555"):
    spec = scenario.payouts[2]["beneficiary"]
    bank = {**spec["beneficiary"]["bank_details"], "iban": iban}
    return {2: {**scenario.payouts[2], "beneficiary": {**spec, "beneficiary": {**spec["beneficiary"], "bank_details": bank}}}}


def test_changed_bank_details_block_before_any_money_moves(make_agent, scenario, simulator, mock):
    agent = make_agent(obligations=[scenario.obligation(2)], payouts=_altered(scenario))  # pinned, asked to pay another
    agent.bootstrap()
    agent.triage()
    [res] = agent.execute()                                   # confidence high: conversion would be autonomous
    assert res.status == "blocked" and "bank details changed" in res.detail
    assert not mock.quotes and not mock.conversions and not mock.transfers
    assert agent.records[2].state is State.ESCALATED and agent.ledger.committed_for(2) == 0
    card = agent.approvals.get(agent.records[2].approval_id)
    assert card.kind == "POLICY_EXCEPTION" and any("****5555" in e for e in card.evidence)


def test_approval_is_bound_to_the_destination_account(make_agent, scenario, simulator, mock, store):
    agent = make_agent(obligations=[scenario.obligation(2)], pin=False)  # unpinned: R8 needs a human for the account
    req = _to_act4(agent, scenario, simulator)
    approve(agent, req)
    agent.payouts = _altered(scenario)                        # details swapped after approval
    [res] = agent.execute()
    assert res.status == "blocked" and "destination account" in res.detail
    assert not mock.conversions and not mock.transfers and store.get_payee("mueller feinmechanik gmbh") is None


def test_new_payee_needs_approval_and_is_pinned_by_the_approver(make_agent, scenario, simulator, mock, store):
    agent = make_agent(obligations=[scenario.obligation(2)], pin=False)
    agent.bootstrap()
    agent.triage()
    rec = agent.records[2]
    assert rec.state is State.AWAITING_APPROVAL and any(n.startswith("R8") for n in rec.decision.notes)
    req = agent.approvals.get(rec.approval_id)
    assert req.destination.startswith("IBAN ****3000")
    approve(agent, req)
    [res] = agent.execute()
    assert res.status == "in_flight" and len(mock.transfers) == 1
    pin = store.get_payee("mueller feinmechanik gmbh")
    assert pin["pinned_by"] == "sam.treasury" and pin["approval_id"] == req.id


def test_repinning_requires_a_reasoned_history_row(store):
    pin_cycle(store)
    store.repin_payee("acme", "a" * 64, "IBAN ****0001 · EUR", changed_by="dana.controller", reason="initial verification",
                      audit=pin_draft("acme", "IBAN ****0001 · EUR"))
    with pytest.raises(sqlite3.DatabaseError):
        store.repin_payee("acme", "b" * 64, "IBAN ****0002 · EUR", changed_by="dana.controller", reason="short",
                          audit=pin_draft("acme", "IBAN ****0002 · EUR"))
    store.repin_payee("acme", "b" * 64, "IBAN ****0002 · EUR", changed_by="dana.controller",
                      reason="new account confirmed by signed letter and call-back",
                      audit=pin_draft("acme", "IBAN ****0002 · EUR"))
    history = store.conn.execute("SELECT old_fingerprint, new_fingerprint FROM payee_history WHERE payee_key = 'acme'"
                                 " ORDER BY id").fetchall()
    assert [tuple(h) for h in history] == [(None, "a" * 64), ("a" * 64, "b" * 64)]


# =============================================================================
# Screening
# =============================================================================
def test_screening_hit_at_triage_is_never_funded_or_paid(make_agent, scenario, mock):
    obs = tuple(replace(o, counterparty="Orion Front Holding Co.") if o.id == 4 else o for o in scenario.obligations)
    agent = make_agent(obligations=obs)
    tri = agent.triage()
    rec = agent.records[4]
    assert tri.screening_hits == [4] and rec.decision.rule == "R0_SCREENING_HIT"
    assert agent.ledger.committed_for(4) == 0
    card = agent.approvals.get(rec.approval_id)
    assert card.kind == "SCREENING_REVIEW"
    with pytest.raises(ApprovalError, match="lacks a role"):
        approve(agent, card, approver_id="dana.controller")      # finance cannot clear a compliance hit
    results = agent.execute()
    assert all(r.obligation_id != 4 for r in results)


def test_screening_hit_found_at_execution_stops_payment(make_agent, scenario, mock, tmp_path):
    agent = make_agent(obligations=[scenario.obligation(2)])
    agent.bootstrap()
    agent.triage()
    listed = tmp_path / "list.json"
    listed.write_text(json.dumps({"version": "updated", "entries": [{"name": "Mueller Feinmechanik"}]}))
    agent.screener = ListScreener(listed)                      # the list was updated mid-cycle
    [res] = agent.execute()
    assert res.status == "blocked" and "Screening hit" in res.detail
    assert not mock.quotes and not mock.conversions
    assert agent.approvals.get(agent.records[2].approval_id).kind == "SCREENING_REVIEW"


def test_screening_normalises_names(tmp_path):
    listed = tmp_path / "list.json"
    listed.write_text(json.dumps({"version": "v", "entries": [{"name": "Blackwater Shell Trading Ltd"}]}))
    s = ListScreener(listed)
    assert s.screen(["BLACKWATER  shell-trading, LIMITED"]).hit
    assert s.screen(["Blackwater Shell Tradíng GmbH"]).hit
    assert not s.screen(["Blackwater Coffee"]).hit


# =============================================================================
# Autonomy limit is cumulative (no splitting)
# =============================================================================
def test_policy_limit_counts_earlier_autonomous_conversions():
    obs = [Obligation(id=i, name=f"s{i}", counterparty=f"cp{i}", amount=D("7000"), currency="EUR", due_in_hours=48,
                      category="time_sensitive", deferrable=False, deferral_penalty_usd=D("0"), payout_method="LOCAL",
                      payout_country="DE", reference=f"R{i}") for i in (1, 2, 3)]
    ctx = P.PlanContext(headroom=D("100000"), held={"EUR": D("0")}, usd_per_unit={"EUR": D("1.085")},
                        confidence=D("0.92"))
    plan = P.plan(obs, ctx, DEFAULT_POLICY)
    gated = [i for i in (1, 2, 3) if plan[i].requires_approval]
    assert gated == [2, 3]                       # 7,595 autonomous; a second 7,595 would exceed 15,000


def test_execution_counts_conversions_already_made(make_agent, scenario, mock):
    agent = make_agent(obligations=[scenario.obligation(2)])
    agent.bootstrap()
    agent.triage()
    agent.autonomous_executed = D("10000.00")
    [res] = agent.execute()
    assert res.status == "gated" and "already converted autonomously" in res.detail
    assert not mock.conversions


# =============================================================================
# Duplicate payment: defence in depth
# =============================================================================
def test_database_blocks_repeat_payment_even_if_airwallex_lookup_misses(make_agent, scenario, simulator, mock):
    first = make_agent(obligations=[scenario.obligation(2)])
    run_full(first, scenario, simulator)
    mock.balances.update({"USD": D("37500.00"), "EUR": D("500.00")})
    second = make_agent(obligations=[scenario.obligation(2)])
    second._prior_payment = lambda rec: None                   # pretend the remote listing missed it
    second.bootstrap()
    second.triage()
    [res] = second.execute()
    assert res.status == "blocked" and "recorded in the database" in res.detail
    assert len(mock.conversions) == 1 and len(mock.transfers) == 1


def test_ambiguous_payout_keeps_the_invoice_locked(make_agent, scenario, simulator, mock, store):
    agent = make_agent()
    _to_act4(agent, scenario, simulator)
    approve(agent, next(r for r in agent.pending_approvals() if r.kind == "FX_CONVERSION"))
    from airwallex_client import AmbiguousResultError
    for _ in range(4):
        mock.inject("POST /transfers/create", "500_before")
    with pytest.raises(AmbiguousResultError):
        agent.execute()
    [row] = store.payouts()
    assert row["status"] == "initiated"                        # unknown outcome: stays locked


# =============================================================================
# Provenance: policy and code fingerprints
# =============================================================================
def test_cycle_records_policy_and_code_fingerprints(make_agent, store):
    agent = make_agent()
    cycle = store.cycle(agent.cycle_id)
    assert cycle["policy_fingerprint"] == P.policy_fingerprint(DEFAULT_POLICY)
    assert len(cycle["code_fingerprint"]) == 64 and cycle["operator"] == OPERATOR
    changed = replace(DEFAULT_POLICY, reserve_floor=D("5000.00"))
    assert P.policy_fingerprint(changed) != cycle["policy_fingerprint"]


# =============================================================================
# Input and configuration hardening
# =============================================================================
@pytest.mark.parametrize("field,value", [("reference", "MF-2026-0419; DROP"), ("currency", "eur"),
                                         ("amount", "-5"), ("amount", "1.001"), ("counterparty", "Evil\x1b[2J"),
                                         ("payout_method", "CRYPTO"), ("category", "vip")])
def test_scenario_input_is_validated(tmp_path, field, value):
    from simulation import FIXTURES
    raw = json.loads((FIXTURES / "scenario.json").read_text())
    raw["obligations"][0][field] = value
    (tmp_path / "s.json").write_text(json.dumps(raw))
    (tmp_path / raw["customer_email_file"]).write_text("hello")
    with pytest.raises((ScenarioError, ValueError)):
        load_scenario(tmp_path / "s.json")


def test_scenario_email_path_cannot_escape(tmp_path):
    from simulation import FIXTURES
    raw = json.loads((FIXTURES / "scenario.json").read_text())
    raw["customer_email_file"] = "../../etc/passwd"
    (tmp_path / "s.json").write_text(json.dumps(raw))
    with pytest.raises(ScenarioError):
        load_scenario(tmp_path / "s.json")


def test_llm_endpoint_must_be_https():
    with pytest.raises(ConfigError):
        load_settings({"OPENAI_BASE_URL": "http://evil.example/v1"})
    with pytest.raises(ConfigError):
        load_settings({"OPENAI_BASE_URL": "file:///etc/passwd"})
    assert load_settings({"OPENAI_BASE_URL": "http://localhost:11434/v1"}).openai_base_url.startswith("http://localhost")


def test_secrets_never_appear_in_settings_repr():
    s = load_settings({"AWX_CLIENT_ID": "cid", "AWX_API_KEY": "awx-secret", "ANTHROPIC_API_KEY": "sk-ant-secret",
                       "TREASURY_AUDIT_KEY": "ab" * 32, "TREASURY_APPROVER_PIN": "fx-approve-42"})
    text = repr(s)
    assert not any(secret in text for secret in ("awx-secret", "sk-ant-secret", "ab" * 32, "fx-approve-42"))


def test_world_readable_env_file_is_flagged(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("TREASURY_TEST_ONLY=1\n")
    os.chmod(env, 0o644)
    monkeypatch.setenv("TREASURY_TEST_ONLY", "x")       # registers clean-up of whatever load_dotenv sets
    monkeypatch.delenv("TREASURY_TEST_ONLY")
    assert any("chmod 600" in w for w in load_dotenv(env))
    os.chmod(env, 0o600)
    assert load_dotenv(env) == []


def test_http_redirects_are_never_followed(mock):
    from airwallex_client import AirwallexClient, AirwallexError
    from mock_sandbox import MOCK_API_KEY, MOCK_CLIENT_ID
    mock.inject("GET /balances/current", "redirect")
    client = AirwallexClient(mock.base_url, MOCK_CLIENT_ID, MOCK_API_KEY, sleep=lambda s: None)
    with pytest.raises(AirwallexError) as exc:
        client.get_balances()
    assert exc.value.status == 302
    assert not any(r["path"] == "/stolen" for r in mock.requests)
    assert len([r for r in mock.requests if r["path"] == "/balances/current"]) == 1


def test_client_refuses_non_https_base_url():
    from airwallex_client import AirwallexClient
    with pytest.raises(ConfigError):
        AirwallexClient("http://api.sandbox.airwallex.com", "id", "key")
    with pytest.raises(ConfigError):
        AirwallexClient("file:///etc/passwd", "id", "key")


# =============================================================================
# The live code path (persistent keyed DB, enrolled approvers) via demo.main
# =============================================================================
def test_live_path_end_to_end_and_rerun_is_blocked(mock, tmp_path, monkeypatch, scenario):
    import demo
    from agent import account_fields, masked_account, payee_key
    from mock_sandbox import MOCK_API_KEY, MOCK_CLIENT_ID
    key_hex = AUDIT_KEY.hex()
    env = {"AWX_BASE_URL": mock.base_url, "AWX_CLIENT_ID": MOCK_CLIENT_ID, "AWX_API_KEY": MOCK_API_KEY,
           "TREASURY_STATE_DIR": str(tmp_path), "TREASURY_AUDIT_KEY": key_hex, "LLM_PROVIDER": "rules",
           "TREASURY_OPERATOR": "ops.runner", "TREASURY_APPROVER_ID": "sam.treasury",
           "TREASURY_APPROVER_PIN": APPROVERS["sam.treasury"][2]}
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    class FastSimulator(demo.SandboxSimulator):
        def __init__(self, client, **_):
            super().__init__(client, sleep=lambda s: None)
    monkeypatch.setattr(demo, "SandboxSimulator", FastSimulator)
    # Missing key: refuse to start.
    monkeypatch.delenv("TREASURY_AUDIT_KEY")
    assert demo.main(["--live", "--yes", "--no-color"]) == 2
    monkeypatch.setenv("TREASURY_AUDIT_KEY", key_hex)
    # Administrators enrol approvers and pin the verified payee first (manage.py does the same).
    with Store(tmp_path / "treasury.db", audit_key=AUDIT_KEY) as admin:
        for approver_id, (name, roles, pin) in APPROVERS.items():
            admin.enroll_approver(approver_id, name, roles, pin, created_by="bootstrap:test")
        ob = scenario.obligation(2)
        fields = account_fields(scenario.payouts[2]["beneficiary"]["beneficiary"]["bank_details"])
        masked = masked_account(fields)
        cycle_id = pin_cycle(admin)
        admin.repin_payee(payee_key(ob), admin.fingerprint("payee-account", fields), masked,
                          changed_by="dana.controller", reason="IBAN confirmed by call-back",
                          audit=pin_draft(ob.counterparty, masked, cycle_id=cycle_id, obligation_id=ob.id,
                                          actor="test-fixture:dana.controller"))
    assert demo.main(["--live", "--yes", "--no-color"]) == 0
    assert len(mock.transfers) == 1
    # Run again against the same database and sandbox: the invoice is never paid twice.
    assert demo.main(["--live", "--yes", "--no-color"]) == 0
    assert len(mock.transfers) == 1 and len(mock.conversions) == 1
    with Store(tmp_path / "treasury.db", audit_key=AUDIT_KEY, read_only=True) as db:
        assert db.verify().ok
        assert [p["status"] for p in db.payouts()] == ["paid"]
        assert len({c["cycle_id"] for c in db.conn.execute("SELECT cycle_id FROM cycles WHERE mode = 'live'")}) == 2


# =============================================================================
# Second audit pass additions
# =============================================================================
def test_account_numbers_in_free_text_are_masked(make_agent, scenario, simulator, store, tmp_path):
    bad = "DE00370400440532013000"
    payouts = _altered(scenario, iban=bad)
    agent = make_agent(obligations=[scenario.obligation(2)], payouts=payouts, pin_from=payouts)
    _to_act4(agent, scenario, simulator)
    approve(agent, next(r for r in agent.pending_approvals() if r.kind == "FX_CONVERSION"))
    from airwallex_client import AirwallexError
    with pytest.raises(AirwallexError) as exc:
        agent.execute()
    agent.audit.record("stopped", f"{exc.value} (IBAN {bad})")      # API messages may echo the account
    store.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    blob = b"".join((tmp_path / n).read_bytes() for n in ("treasury.db", "treasury.db-wal") if (tmp_path / n).exists())
    assert bad.encode() not in blob and IBAN.encode() not in blob
    assert agent.audit.entries[-1].reason.endswith("(IBAN ****3000)")


def test_backup_is_consistent_verified_and_never_overwritten(make_agent, scenario, simulator, store, tmp_path):
    run_full(make_agent(), scenario, simulator)
    dest = store.backup(tmp_path / "backups" / "copy.db")
    assert stat.S_IMODE(dest.stat().st_mode) == 0o600
    with Store(dest, audit_key=AUDIT_KEY, read_only=True) as copy:
        report = copy.verify()
        assert report.ok and report.head_hash == store.head()["entry_hash"]
    with pytest.raises(StoreError, match="never overwritten"):
        store.backup(dest)


def test_manage_cli_enforces_roles_and_sod(tmp_path, monkeypatch, capsys):
    import manage
    monkeypatch.setenv("TREASURY_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("TREASURY_AUDIT_KEY", AUDIT_KEY.hex())
    monkeypatch.setenv("TREASURY_NEW_PIN", "release-funds-7")
    assert manage.main(["add-approver", "--bootstrap", "--id", "dana.controller", "--name", "Dana",
                        "--roles", "finance_controller"]) == 0
    assert manage.main(["add-approver", "--bootstrap", "--id", "eve", "--name", "Eve",
                        "--roles", "finance_controller"]) == 2                    # bootstrap only once
    monkeypatch.setenv("TREASURY_NEW_PIN", "fx-approve-42")
    monkeypatch.setenv("TREASURY_ADMIN_PIN", "000000")
    assert manage.main(["add-approver", "--by", "dana.controller", "--id", "sam.treasury", "--name", "Sam",
                        "--roles", "treasury_approver"]) == 2                    # wrong admin PIN
    monkeypatch.setenv("TREASURY_ADMIN_PIN", "release-funds-7")
    assert manage.main(["add-approver", "--by", "dana.controller", "--id", "sam.treasury", "--name", "Sam",
                        "--roles", "treasury_approver"]) == 0
    assert manage.main(["add-approver", "--by", "dana.controller", "--id", "dana.controller", "--name", "x",
                        "--roles", "treasury_approver"]) == 2                    # no self-enrolment
    monkeypatch.setenv("TREASURY_ADMIN_PIN", "fx-approve-42")
    assert manage.main(["pin-payee", "--by", "sam.treasury", "--obligation", "2",
                        "--reason", "call-back done"]) == 2                     # not a finance controller
    monkeypatch.setenv("TREASURY_ADMIN_PIN", "release-funds-7")
    assert manage.main(["pin-payee", "--by", "dana.controller", "--obligation", "2",
                        "--reason", "IBAN confirmed by call-back"]) == 0
    anchors = tmp_path / "anchors.jsonl"
    assert manage.main(["anchor", "--append", str(anchors)]) == 0
    assert manage.main(["verify-audit", "--anchors", str(anchors)]) == 0
    assert manage.main(["export-audit", "--out", str(tmp_path / "export")]) == 2  # --by is required
    assert manage.main(["export-audit", "--by", "dana.controller", "--out", str(tmp_path / "export")]) == 0
    assert manage.main(["backup", "--by", "dana.controller", "--out", str(tmp_path / "bk" / "t.db")]) == 0
    assert manage.main(["list-payouts", "--by", "dana.controller"]) == 0
    assert manage.main(["list-approvers", "--by", "dana.controller"]) == 0
    manifest = json.loads((tmp_path / "export" / "manifest.json").read_text())
    assert manifest["verified"] and manifest["files"]["audit_log.jsonl"]["rows"] >= 5
    events = [json.loads(line)["event"] for line in (tmp_path / "export" / "audit_log.jsonl").read_text().splitlines()]
    assert events.count("admin_auth_failed") == 1 and "admin_refused" in events and "payee_pinned" in events
    approvers = (tmp_path / "export" / "approvers.jsonl").read_text()
    assert "pin_hash" not in approvers and "salt" not in approvers


def test_live_runs_refuse_unattended_approval_on_production_and_missing_screening(tmp_path, monkeypatch):
    import demo
    monkeypatch.setenv("TREASURY_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AWX_CLIENT_ID", "id")
    monkeypatch.setenv("AWX_API_KEY", "key")
    monkeypatch.setenv("AWX_BASE_URL", "https://api.airwallex.com")
    monkeypatch.setenv("TREASURY_ALLOW_PRODUCTION", "1")
    assert demo.main(["--live", "--yes"]) == 2
    monkeypatch.setenv("AWX_BASE_URL", "https://api.sandbox.airwallex.com")
    monkeypatch.setenv("TREASURY_SCREENING_LIST", "off")
    assert demo.main(["--live"]) == 2


def test_interrupted_run_keeps_the_invoice_locked_until_a_controller_releases_it(make_agent, scenario,
                                                                               simulator, mock, store):
    first = make_agent(obligations=[scenario.obligation(2)])
    first.bootstrap()
    first.triage()                                              # high confidence: autonomous conversion
    for _ in range(3):
        mock.inject("POST /beneficiaries/create", "500_before")
    from airwallex_client import AmbiguousResultError
    with pytest.raises(AmbiguousResultError):
        first.execute()                                         # converted, then the process "dies"
    assert len(mock.conversions) == 1 and not mock.transfers
    [row] = store.payouts()
    assert row["status"] == "initiated"
    mock.balances.update({"USD": D("37500.00"), "EUR": D("500.00")})
    second = make_agent(obligations=[scenario.obligation(2)])
    second.bootstrap()
    second.triage()
    [res] = second.execute()
    assert res.status == "blocked" and "live payout recorded" in res.detail
    assert len(mock.conversions) == 1                          # no second conversion for the same invoice
    store.release_payout(row["request_id"], note="released by dana.controller: confirmed no transfer exists")
    with pytest.raises(StoreError):
        store.release_payout(row["request_id"], note="again")
    with pytest.raises(sqlite3.DatabaseError):
        store.conn.execute("UPDATE payouts SET status = 'initiated' WHERE request_id = ?", (row["request_id"],))


def test_rejected_transfer_keeps_the_invoice_locked_under_a_new_request_id(make_agent, scenario, simulator,
                                                                         mock, store):
    agent = make_agent(obligations=[scenario.obligation(2)])
    agent.bootstrap()
    agent.triage()
    original = mock._route

    def reject_first_transfer(method, path, query, body, headers, _state={"n": 0}):
        if path == "/transfers/create":
            _state["n"] += 1
            if _state["n"] == 1:
                from mock_sandbox import ApiError
                raise ApiError(400, "invalid_argument", "reference rejected")
        return original(method, path, query, body, headers)

    mock._route = reject_first_transfer
    from airwallex_client import AirwallexError
    with pytest.raises(AirwallexError):
        agent.execute()
    rows = store.payouts()
    assert [r["status"] for r in rows] == ["failed", "initiated"]
    assert rows[1]["note"] == f"replaces {rows[0]['request_id']}"
    [res] = agent.execute()                                     # same cycle resumes: pays once, new id
    assert res.transfer and len(mock.transfers) == 1 and len(mock.conversions) == 1
    assert next(iter(mock.transfers.values()))["request_id"] == rows[1]["request_id"]
