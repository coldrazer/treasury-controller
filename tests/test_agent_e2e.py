"""The four acts end to end against the local mock sandbox, plus failure paths."""
from datetime import datetime, timezone
from decimal import Decimal

import pytest

from agent import AgentHalted, check_against_schema
from approvals import ApprovalStatus
from conftest import APPROVERS, approve
from models import Action, State

D = Decimal


def run_acts_1_to_3(agent, scenario, simulator):
    agent.bootstrap()
    tri = agent.triage()
    ev = agent.ingest_customer_email(scenario.customer_email)
    dep = scenario.deposit
    simulator.deposit(amount=dep.amount, currency=dep.currency, payer_name=dep.payer_name, reference=dep.reference)
    rc = agent.on_balance_event(currency=dep.currency, amount=dep.amount, reference=dep.reference, wait_seconds=0)
    return tri, ev, rc


def approve_fx(agent):
    req = next(r for r in agent.pending_approvals() if r.kind == "FX_CONVERSION")
    approve(agent, req)
    return req


def test_full_scenario(make_agent, scenario, simulator, mock):
    agent = make_agent()
    tri, ev, rc = run_acts_1_to_3(agent, scenario, simulator)

    # Act 1: four different decisions for four different reasons
    states = {i: r.state for i, r in agent.records.items()}
    assert tri.confidence == D("0.92") and tri.limit == D("15000.00")
    assert D("0.55") < tri.coverage < D("0.65")          # "covers ~60%"

    # Act 2: confidence drop gates exactly the EUR conversion
    assert (ev.impact.before, ev.impact.after) == (D("0.92"), D("0.37"))
    assert (ev.limit_before, ev.limit_after) == (D("15000.00"), D("2500.00"))
    assert [rec.ob.id for rec, _ in ev.gated] == [2]

    # Act 3: only the deferred license and the contractor's funding are recalculated
    assert sorted(c.obligation_id for c in rc.changes) == [3, 4]
    assert sorted(rc.untouched) == [1, 2, 5]
    changes = {c.obligation_id: c for c in rc.changes}
    assert changes[3].old_state is State.DEFERRED and changes[3].new_state is State.FUNDED
    assert changes[4].new_decision.action is Action.ESCALATE and changes[4].new_decision.usd_draw == D("19050.00")
    assert changes[4].superseded_approval and changes[4].new_approval
    assert states[1] is State.FUNDED and states[5] is State.FUNDED

    # Act 4: funded bills above the autonomous payout cap are gated like the FX
    # conversion; only the small bill inside the cap pays directly.
    funded = agent.execute()
    assert {r.obligation_id for r in funded} == {1, 3, 5}
    assert len(mock.transfers) == 1 and not mock.conversions
    assert sorted(r.ob.id for r in agent.records.values()
                  if r.state is State.AWAITING_APPROVAL) == [1, 2, 5]
    for req in [r for r in agent.pending_approvals()
                if r.kind == "POLICY_EXCEPTION" and r.obligation_id in (1, 5)]:
        approve(agent, req)
    approve_fx(agent)
    results = agent.execute()
    assert {r.obligation_id for r in results} == {1, 2, 5}
    assert len(mock.conversions) == 1 and len(mock.transfers) == 4 and len(mock.quotes) == 1
    conv = mock.conversions[0]
    fx_result = next(r for r in results if r.obligation_id == 2)
    assert conv["buy_amount"] == D("11512.85") and conv["quote_id"] == fx_result.quote["quote_id"]
    transfer = next(t for t in mock.transfers.values() if t["transfer_currency"] == "EUR")
    assert transfer["transfer_amount"] == D("12000.00") and transfer["fee_amount"] == D("12.85")
    assert transfer["transfer_method"] == "SWIFT" and transfer["transfer_currency"] == "EUR"

    simulator.advance_transfer(transfer["id"], "SENT")
    agent.refresh_payouts()
    assert agent.records[2].state is State.CONVERTED          # SENT is not final
    simulator.advance_transfer(transfer["id"], "PAID")
    agent.refresh_payouts()
    assert agent.records[2].state is State.PAID

    report = agent.reserve_report()
    assert report.intact and not report.mismatches
    assert report.actual["EUR"] == D("0.00")                   # converted exactly the minimum
    assert report.actual["USD"] == D("34308.56")               # 37,500 + 25,000 - 15,700 paid - 12,491.44
    assert report.committed == D("19050.00") and report.uncommitted >= D("10000")
    assert agent.records[4].state is State.ESCALATED           # still with a human
    assert [p.obligation_id for p in agent.pending_approvals()] == [4]


def test_execute_twice_does_not_duplicate(make_agent, scenario, simulator, mock):
    agent = make_agent()
    run_acts_1_to_3(agent, scenario, simulator)
    approve_fx(agent)
    agent.execute()  # small bill pays; big bills gate on payout-cap cards
    for req in [r for r in agent.pending_approvals()
                if r.kind == "POLICY_EXCEPTION" and r.obligation_id in (1, 5)]:
        approve(agent, req)
    agent.execute()
    assert agent.execute() == []
    assert len(mock.conversions) == 1 and len(mock.transfers) == 4


def test_ambiguous_transfer_is_looked_up_not_resent(make_agent, scenario, simulator, mock):
    agent = make_agent(obligations=[scenario.obligation(2)])
    run_acts_1_to_3(agent, scenario, simulator)
    approve_fx(agent)
    mock.inject("POST /transfers/create", "drop_after")       # processed, response lost
    results = agent.execute()
    assert len(mock.transfers) == 1
    assert results[0].transfer["id"] == next(iter(mock.transfers))


def test_ambiguous_conversion_5xx_is_looked_up(make_agent, scenario, simulator, mock):
    agent = make_agent()
    run_acts_1_to_3(agent, scenario, simulator)
    approve_fx(agent)
    mock.inject("POST /fx/conversions/create", "500_after")
    agent.execute()
    assert len(mock.conversions) == 1 and agent.reserve_report().intact


def test_expired_quote_gets_fresh_quote_and_new_request_id(make_agent, scenario, simulator, mock):
    agent = make_agent()
    run_acts_1_to_3(agent, scenario, simulator)
    approve_fx(agent)
    original = mock._convert

    def expire_first(body, _state={"n": 0}):
        _state["n"] += 1
        if _state["n"] == 1:
            from mock_sandbox import ApiError
            mock._use_request_id("conversions", body.get("request_id"))
            raise ApiError(400, "expired_quote", "quote expired")
        return original(body)

    mock._convert = expire_first
    agent.execute()
    assert len(mock.quotes) == 2 and len(mock.conversions) == 1
    assert agent.records[2].state is State.CONVERTED


def test_rejected_approval_blocks_execution(make_agent, scenario, simulator, mock):
    agent = make_agent(obligations=[scenario.obligation(2)])
    run_acts_1_to_3(agent, scenario, simulator)
    req = next(r for r in agent.pending_approvals() if r.kind == "FX_CONVERSION")
    reserved = agent.ledger.committed_for(2, "USD")
    agent.reject(req.id, approver_id="sam.treasury", pin=APPROVERS["sam.treasury"][2], reason="wait for Northwind")
    assert agent.execute() == [] and not mock.conversions
    assert agent.records[2].state is State.ESCALATED and reserved > 0
    assert agent.ledger.committed_for(2) == 0            # reserved USD and held EUR released


def test_quote_above_approved_ceiling_blocks(make_agent, scenario, simulator, mock):
    agent = make_agent(obligations=[scenario.obligation(2)])
    run_acts_1_to_3(agent, scenario, simulator)
    approve_fx(agent)
    mock.rates["EUR"] = D("1.20")                               # market moved ~10% after approval
    results = agent.execute()
    assert results[0].status == "blocked" and "ceiling" in results[0].detail
    assert not mock.conversions and len(mock.quotes) == 1


def test_autonomous_path_when_confidence_holds(make_agent, scenario, mock):
    agent = make_agent()
    agent.bootstrap()
    agent.triage()
    assert agent.records[2].state is State.FX_PLANNED
    results = agent.execute()                                    # no email: within autonomy
    assert results[0].status == "in_flight" and len(mock.conversions) == 1
    assert agent.approvals.get(agent.records[4].approval_id).status is ApprovalStatus.PENDING


def test_reconciliation_mismatch_halts(make_agent, scenario, mock):
    agent = make_agent()
    agent.bootstrap()
    agent.triage()
    mock.balances["USD"] -= D("5000")                            # money moved outside the agent
    with pytest.raises(AgentHalted):
        agent.execute()
    assert agent.halted and not mock.conversions
    with pytest.raises(AgentHalted):
        agent.execute()


def test_deposit_notice_without_inflow_halts(make_agent, scenario):
    agent = make_agent()
    agent.bootstrap()
    agent.triage()
    with pytest.raises(AgentHalted):
        agent.on_balance_event(currency="USD", amount=D("25000"), wait_seconds=0)


def test_triage_is_not_rerun(make_agent):
    agent = make_agent()
    agent.bootstrap()
    agent.triage()
    with pytest.raises(AgentHalted):
        agent.triage()


def test_cash_cap_against_prefunded_sandbox(make_agent, scenario, mock, simulator):
    mock.balances.update({"USD": D("1000000"), "EUR": D("250000"), "GBP": D("80000")})
    agent = make_agent()
    tri, ev, rc = run_acts_1_to_3(agent, scenario, simulator)
    assert tri.capped and agent.ledger.balance("USD") == D("62500.00")
    assert {i: r.state for i, r in agent.records.items()}[3] is State.FUNDED
    approve_fx(agent)
    agent.execute()
    report = agent.reserve_report()
    assert report.intact and not report.mismatches


def test_schema_check_reports_missing_and_bad_fields(scenario):
    spec = scenario.payouts[2]["beneficiary"]
    schema = {"fields": [
        {"path": "beneficiary.bank_details.iban", "required": True, "rule": {"pattern": "^[A-Z]{2}[0-9]{2}.+$"}},
        {"path": "beneficiary.bank_details.bank_branch", "required": True},
        {"path": "transfer_method", "required": True, "rule": {"pattern": "LOCAL"}},
    ]}
    problems = check_against_schema(spec, schema)
    assert any("bank_branch" in p for p in problems) and any("transfer_method" in p for p in problems)
    assert not any("iban" in p for p in problems)


def test_invalid_iban_is_rejected_at_beneficiary_creation(make_agent, scenario, simulator, mock):
    payouts = {2: {**scenario.payouts[2], "beneficiary": {
        **scenario.payouts[2]["beneficiary"],
        "beneficiary": {**scenario.payouts[2]["beneficiary"]["beneficiary"],
                        "bank_details": {**scenario.payouts[2]["beneficiary"]["beneficiary"]["bank_details"],
                                         "iban": "DE00370400440532013000"}}}}}
    agent = make_agent(obligations=[scenario.obligation(2)], payouts=payouts, pin_from=payouts)
    run_acts_1_to_3(agent, scenario, simulator)
    approve_fx(agent)
    from airwallex_client import AirwallexError
    with pytest.raises(AirwallexError) as exc:
        agent.execute()
    assert exc.value.code == "083" and not mock.transfers
    [row] = agent.store.payouts()                       # currency bought, nothing paid: invoice stays locked
    assert row["status"] == "initiated" and row["transfer_id"] is None
    # Someone "fixes" the bank details: that is a change of destination, so it is blocked until a
    # finance controller re-pins it. The conversion is NOT repeated and nothing is paid.
    agent.payouts = dict(scenario.payouts)
    [res] = agent.execute()
    assert res.status == "blocked" and "bank details changed" in res.detail
    assert len(mock.conversions) == 1 and not mock.transfers
    assert agent.records[2].state is State.ESCALATED
    assert agent.ledger.committed_for(2, "EUR") == D("12012.85")      # converted funds stay ring-fenced


def test_second_run_cannot_pay_the_same_invoice_twice(make_agent, scenario, simulator, mock):
    first = make_agent(obligations=[scenario.obligation(2)])
    run_acts_1_to_3(first, scenario, simulator)
    approve_fx(first)
    first.execute()
    # A fresh cycle (new process, new request ids) against the same sandbox, topped back up:
    mock.balances.update({"USD": D("37500.00"), "EUR": D("500.00")})
    second = make_agent(obligations=[scenario.obligation(2)])  # new cycle, same database
    second.bootstrap()
    second.triage()
    results = second.execute()          # confidence still high: conversion would be autonomous
    assert results[0].status == "blocked" and "already paid" in results[0].detail
    assert len(mock.conversions) == 1 and len(mock.transfers) == 1 and len(mock.quotes) == 1


def test_request_pending_409_is_resolved_with_same_request_id(make_agent, scenario, simulator, mock):
    agent = make_agent(obligations=[scenario.obligation(2)])
    run_acts_1_to_3(agent, scenario, simulator)
    approve_fx(agent)
    mock.inject("POST /transfers/create", "409_before")
    agent.execute()
    assert len(mock.transfers) == 1
    sent = [r["body"]["request_id"] for r in mock.requests if r["path"] == "/transfers/create"]
    assert len(sent) == 2 and sent[0] == sent[1]


def test_email_with_terminal_escapes_is_sanitised(make_agent, scenario):
    agent = make_agent()
    agent.bootstrap()
    agent.triage()
    hostile = scenario.customer_email.replace("delayed 2 weeks", "delayed\x1b[2J\x1b[31m 2 weeks‮")
    ev = agent.ingest_customer_email(hostile)
    assert "\x1b" not in ev.signal.evidence_quote and "‮" not in ev.signal.evidence_quote
    assert ev.signal.expected_delay_days == 14


def test_small_deposit_keeps_deferral_and_gap(make_agent, scenario, simulator):
    agent = make_agent()
    agent.bootstrap()
    agent.triage()
    simulator.deposit(amount=D("100"), currency="USD", payer_name="x", reference="tiny")
    rc = agent.on_balance_event(currency="USD", amount=D("100"), wait_seconds=0)
    states = {c.obligation_id: c.new_state for c in rc.changes}
    assert states == {3: State.DEFERRED, 4: State.ESCALATED}
    assert agent.records[4].decision.funding_gap == D("18441.45")


def test_failed_payout_is_escalated_and_funds_ring_fenced(make_agent, scenario, simulator, mock):
    agent = make_agent(obligations=[scenario.obligation(2)])
    run_acts_1_to_3(agent, scenario, simulator)
    approve_fx(agent)
    [res] = agent.execute()
    simulator.advance_transfer(res.transfer["id"], "FAILED", failure_type="BENEFICIARY_BANK_RETURNED")
    [after] = agent.refresh_payouts()
    assert after.status == "blocked" and agent.records[2].state is State.ESCALATED
    assert agent.ledger.committed_for(2, "EUR") == D("12012.85")
    report = agent.reserve_report()
    assert report.intact and not report.mismatches and report.actual["EUR"] == D("12012.85")
    assert any(p.kind == "PAYOUT_FAILED" for p in agent.pending_approvals())
    assert agent.execute() == []                       # never auto-resends


def test_due_deferral_is_reviewed_and_rescheduled(make_agent, scenario):
    clock = [datetime(2026, 1, 1, tzinfo=timezone.utc)]
    agent = make_agent(obligations=[scenario.obligation(3)], cash_cap={"USD": D("10500")},
                       clock=lambda: clock[0])
    agent.bootstrap()
    agent.triage()
    rec = agent.records[3]
    assert rec.state is State.DEFERRED
    assert rec.deferred_until == datetime(2026, 1, 8, tzinfo=timezone.utc)

    clock[0] = datetime(2026, 1, 9, tzinfo=timezone.utc)
    [result] = agent.reschedule_deferred()
    assert result.status == "deferred" and rec.state is State.DEFERRED
    assert rec.deferred_until == datetime(2026, 1, 16, tzinfo=timezone.utc)
    assert any(e.event == "deferral_reviewed" for e in agent.audit.entries)


def test_due_deferral_funds_when_cash_is_available(make_agent, scenario):
    clock = [datetime(2026, 1, 1, tzinfo=timezone.utc)]
    agent = make_agent(obligations=[scenario.obligation(3)], cash_cap={"USD": D("10500")},
                       clock=lambda: clock[0])
    agent.bootstrap()
    agent.triage()
    rec = agent.records[3]
    assert rec.state is State.DEFERRED

    clock[0] = datetime(2026, 1, 9, tzinfo=timezone.utc)
    agent.ledger.apply_inflow("USD", D("2000"))
    assert agent.reschedule_deferred() == []
    assert rec.state is State.FUNDED and rec.deferred_until is None
    assert agent.ledger.committed_for(3, "USD") == D("1200")


def test_approved_exception_is_handed_off_not_executed(make_agent, scenario, simulator, mock):
    agent = make_agent()
    run_acts_1_to_3(agent, scenario, simulator)
    req = agent.approvals.get(agent.records[4].approval_id)
    approve(agent, req)
    results = {r.obligation_id: r for r in agent.execute()}
    assert results[4].status == "handoff" and not mock.conversions
    assert agent.execute() == []                       # handed off once


def test_retry_quote_is_reauthorised(make_agent, scenario, simulator, mock):
    agent = make_agent(obligations=[scenario.obligation(2)])
    run_acts_1_to_3(agent, scenario, simulator)
    approve_fx(agent)
    original = mock._convert

    def expire_then_move_market(body, _state={"n": 0}):
        _state["n"] += 1
        if _state["n"] == 1:
            from mock_sandbox import ApiError
            mock._use_request_id("conversions", body.get("request_id"))
            mock.rates["EUR"] = D("1.20")          # the market jumps before the fresh quote
            raise ApiError(400, "expired_quote", "quote expired")
        return original(body)

    mock._convert = expire_then_move_market
    [res] = agent.execute()
    assert res.status == "blocked" and "ceiling" in res.detail
    assert len(mock.quotes) == 2 and not mock.conversions


def test_fee_above_policy_table_is_recorded_not_crashing(make_agent, scenario, simulator, mock):
    mock.balances.update({"EUR": D("250000")})            # pre-funded wallet, capped to EUR 500 in the book
    mock.swift_fees["EUR"] = D("15.00")                   # Airwallex changed its fee
    agent = make_agent()
    run_acts_1_to_3(agent, scenario, simulator)
    approve_fx(agent)
    agent.execute()
    assert any(e.event == "fee_mismatch" for e in agent.audit.entries)
    report = agent.reserve_report()
    assert not report.mismatches and agent.ledger.balance("EUR") == D("-2.15")


def test_duplicate_guard_matches_invoice_even_if_beneficiary_lookup_fails(make_agent, scenario, simulator,
                                                                         mock):
    first = make_agent(obligations=[scenario.obligation(2)])
    run_acts_1_to_3(first, scenario, simulator)
    approve_fx(first)
    first.execute()
    mock.balances.update({"USD": D("37500.00"), "EUR": D("500.00")})
    renamed = {2: {**scenario.payouts[2], "beneficiary": {**scenario.payouts[2]["beneficiary"],
                                                          "nickname": "a different nickname"}}}
    second = make_agent(obligations=[scenario.obligation(2)], payouts=renamed)
    second.bootstrap()
    second.triage()
    [res] = second.execute()
    assert res.status == "blocked" and not len(mock.conversions) > 1
