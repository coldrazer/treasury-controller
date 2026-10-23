#!/usr/bin/env python3
"""Narrated four-act demo of the Adaptive Treasury Controller.

    python demo.py                 # offline: local mock sandbox, no credentials needed
    python demo.py --live          # Airwallex sandbox (AWX_CLIENT_ID / AWX_API_KEY)
    python demo.py --yes           # approve the bound card as the demo approver (mock), or as
                                   # TREASURY_APPROVER_ID / TREASURY_APPROVER_PIN (live)
    python demo.py --pace 1.5      # slow down for screen recording

Everything is written to a hardened SQLite database (hash-chained audit log, request ids,
approvals, payee pins, payouts, snapshots): state/treasury.db for live runs (needs
TREASURY_AUDIT_KEY), a fresh state/mock/<cycle>.db for each mock run.
Check it any time with:  python manage.py verify-audit
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import shutil
import sys
import textwrap
import time
from dataclasses import replace
from decimal import Decimal

from agent import AgentHalted, TreasuryAgent, payee_key
from airwallex_client import AirwallexClient, AirwallexError
from approvals import ApprovalError, ApprovalRequest
from config import BASE_CURRENCY, DEFAULT_POLICY, ConfigError, is_production, load_settings
from email_reader import make_reader
from explainer import Explainer
from journal import write_json
from llm import LLMError, make_llm
from mock_sandbox import MOCK_API_KEY, MOCK_CLIENT_ID, MockAirwallex
from models import State, clean_text, fmt
from runtime import make_screener, new_cycle_id, open_store
from simulation import SandboxSimulator, SimulationError, load_scenario
from store import StoreError

REPO_URL = os.environ.get("TREASURY_REPO_URL", "")

# Demo identities, enrolled ONLY into throwaway mock databases (fake money). Live approvers are
# enrolled with manage.py and authenticate with their own PIN.
DEMO_APPROVERS = {
    "sam.treasury": ("Sam Ortiz (Treasury)", ("treasury_approver",), "fx-approve-42"),
    "dana.controller": ("Dana Reyes (Finance Controller)", ("finance_controller",), "release-funds-7"),
    "casey.compliance": ("Casey Lin (Compliance)", ("compliance_officer",), "screen-names-11"),
}
DEMO_APPROVER_FOR_KIND = {"FX_CONVERSION": "sam.treasury", "POLICY_EXCEPTION": "dana.controller",
                          "PAYOUT_FAILED": "dana.controller", "SCREENING_REVIEW": "casey.compliance"}


# ---------------------------------------------------------------------------
# Console rendering
# ---------------------------------------------------------------------------
class UI:
    STYLES = {"b": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33", "blue": "34",
              "magenta": "35", "cyan": "36"}

    def __init__(self, color: bool, pace: float):
        self.color = color
        self.pace = pace
        self.width = min(110, max(80, shutil.get_terminal_size((100, 24)).columns))

    def s(self, text: str, *styles: str) -> str:
        if not self.color or not styles:
            return text
        codes = ";".join(self.STYLES[x] for x in styles)
        return f"\033[{codes}m{text}\033[0m"

    def pause(self, factor: float = 1.0) -> None:
        if self.pace:
            time.sleep(self.pace * factor)

    def out(self, text: str = "") -> None:
        print(text, flush=True)

    def wrap(self, text: str, indent: int = 4) -> None:
        for line in textwrap.wrap(text, width=self.width - indent) or [""]:
            self.out(" " * indent + line)

    def act(self, title: str, subtitle: str = "") -> None:
        self.out()
        self.out(self.s("━" * self.width, "cyan"))
        self.out(self.s(f" {title}", "b", "cyan") + (self.s(f"  ·  {subtitle}", "dim") if subtitle else ""))
        self.out(self.s("━" * self.width, "cyan"))
        self.pause()

    def section(self, text: str) -> None:
        self.out()
        self.out(self.s(text, "b"))

    def floor(self, floor: Decimal) -> None:
        label = f" RESERVE FLOOR {fmt(floor, BASE_CURRENCY)} · hard line, never planned through "
        side = max(4, (self.width - len(label)) // 2)
        self.out(self.s("═" * side + label + "═" * side, "red", "b"))

    def cash_bar(self, balance: Decimal, committed: Decimal, floor: Decimal) -> None:
        width = self.width - 12
        total = max(balance, Decimal(1))
        c = int(width * min(committed, balance) / total)
        f = int(width * min(floor, max(balance - committed, 0)) / total)
        h = max(0, width - c - f)
        self.out("    " + self.s("█" * c, "blue") + self.s("█" * f, "red") + self.s("░" * h, "green"))
        self.out("    " + self.s("■ committed ", "blue") + fmt(committed) + "   " + self.s("■ floor ", "red")
                 + fmt(floor) + "   " + self.s("■ free headroom ", "green") + fmt(balance - committed - floor))


ACTION_STYLE = {"FUND": "green", "CONVERT": "cyan", "DEFER": "yellow", "ESCALATE": "magenta"}
STATE_STYLE = {State.FUNDED: "green", State.FX_PLANNED: "cyan", State.AWAITING_APPROVAL: "yellow",
               State.CONVERTED: "cyan", State.PAID: "green", State.DEFERRED: "yellow", State.ESCALATED: "magenta"}


def show_decision(ui: UI, rec, prefix: str = "") -> None:
    d, ob = rec.decision, rec.ob
    action = ui.s(f"{d.action.value:<9}", "b", ACTION_STYLE[d.action.value])
    state = ui.s(f"[{rec.state.value}]", STATE_STYLE.get(rec.state, "dim"))
    ui.out(f"  {prefix}#{ob.id}  {action} {ob.name:<20} {fmt(ob.amount, ob.currency):>15}   {state} "
           + ui.s(d.rule, "dim"))
    ui.wrap("↳ " + d.reason, indent=8)
    for note in d.notes:
        ui.wrap("↳ " + note, indent=8)


def show_card(ui: UI, req: ApprovalRequest) -> None:
    bar = "─" * (ui.width - 8)
    ui.out("    " + ui.s("┌" + bar, "yellow"))
    ui.out("    " + ui.s("│ ", "yellow") + ui.s(f"APPROVAL REQUIRED · {req.kind} · {req.id} · code {req.code}", "b", "yellow"))
    rows = [("Action", req.action), ("Amount", fmt(req.amount, req.currency)), ("Counterparty", req.counterparty)]
    if req.destination:
        rows.append(("Destination", req.destination))
    if req.sell_currency:
        rows.append(("Pay with", f"{req.sell_currency}, at most {fmt(req.max_sell_amount, req.sell_currency)}"))
    rows.append(("Requested by", req.requested_by))
    rows.append(("Expires", req.expires_at.strftime("%Y-%m-%d %H:%M UTC") if req.expires_at else "-"))
    for key, value in rows:
        ui.out("    " + ui.s("│ ", "yellow") + f"{key:<13}{value}")
    ui.out("    " + ui.s("│ ", "yellow") + "Evidence")
    for item in req.evidence:
        for i, line in enumerate(textwrap.wrap(item, ui.width - 16)):
            ui.out("    " + ui.s("│ ", "yellow") + ("  • " if i == 0 else "    ") + line)
    if req.explanation:
        ui.out("    " + ui.s("│ ", "yellow") + "Note for approver")
        for line in textwrap.wrap(req.explanation, ui.width - 16):
            ui.out("    " + ui.s("│ ", "yellow") + "  " + ui.s(line, "dim"))
    ui.out("    " + ui.s("└" + bar, "yellow"))


def obtain_approval(ui: UI, agent: TreasuryAgent, req: ApprovalRequest, *, auto: bool,
                    credentials: tuple[str, str] | None) -> bool:
    """Ask an authenticated approver to decide the card. ``credentials`` is (approver_id, pin)
    for unattended runs; otherwise the approver signs in at the terminal."""
    show_card(ui, req)
    if auto:
        if credentials is None:
            ui.out(ui.s("    --yes needs TREASURY_APPROVER_ID and TREASURY_APPROVER_PIN outside mock mode; "
                        "leaving the approval pending.", "yellow"))
            return False
        approver_id, pin = credentials
        code = req.code
        ui.out(f"    {ui.s(approver_id, 'b')} signs in with their PIN, reviews the card and types code "
               f"{ui.s(code, 'b')} " + ui.s("(--yes: unattended approver)", "dim"))
    elif not sys.stdin.isatty():
        ui.out(ui.s("    No interactive terminal; leaving the approval pending. Re-run with --yes to approve.", "yellow"))
        return False
    else:
        approver_id = input("    Approver id (Enter to leave pending): ").strip().lower()
        if not approver_id:
            return False
        pin = getpass.getpass("    PIN: ")
        code = input("    Type the code on the card to approve it: ").strip()
    try:
        agent.approve(req.id, approver_id=approver_id, pin=pin, confirm_code=code)
    except ApprovalError as exc:
        ui.out(ui.s(f"    ✗ {exc}", "red"))
        return False
    ui.out(ui.s(f"    ✓ Approved by {approver_id}. Bound to {fmt(req.amount, req.currency)} → {req.counterparty}"
                + (f" at {req.destination}" if req.destination else "") + "; single use.", "green"))
    return True


def balances_line(balances: dict, currencies=("USD", "EUR", "GBP")) -> str:
    return "   ".join(f"{c} {fmt(balances.get(c, Decimal(0)))}" for c in currencies)


# ---------------------------------------------------------------------------
# The four acts
# ---------------------------------------------------------------------------
def act1(ui: UI, agent: TreasuryAgent, scenario) -> dict:
    ui.act("ACT 1 — INITIAL TRIAGE", "read balances, list obligations, plan with reasons")
    agent.bootstrap()
    tri = agent.triage()
    ui.section("Balances (GET /balances/current)")
    ui.out("    " + balances_line(tri.book_balances))
    if tri.capped:
        ui.out(ui.s("    Sandbox wallets are pre-funded; the agent works within the scenario's operating cash.", "dim"))
        ui.out(ui.s("    Airwallex shows " + balances_line(tri.actual_balances) + " (reconciled by deltas).", "dim"))
    ui.out("    Indicative rates (GET /fx/rates/current, planning only): "
           + ", ".join(f"1 {c} ≈ {r} {BASE_CURRENCY}" for c, r in tri.rates.items()))
    ui.section(f"Receipt forecast · {scenario.expected_receipt.customer} {scenario.expected_receipt.invoice_id} "
               f"{fmt(scenario.expected_receipt.amount, scenario.expected_receipt.currency)}, "
               f"due in {scenario.expected_receipt.due_in_hours}h")
    for line in tri.assessment.lines:
        ui.out("    " + line)
    ui.out(f"    Confidence {ui.s(str(tri.confidence), 'b')} → autonomous conversion limit "
           f"{ui.s(fmt(tri.limit, BASE_CURRENCY), 'b', 'green')}")
    ui.pause()

    ui.section("Obligations · next 72 hours")
    ui.out(ui.s(f"    {'#':<3}{'Obligation':<22}{'Counterparty':<32}{'Amount':>16}{'Due':>6}{'≈ USD':>14}", "dim"))
    for rec in sorted(agent.records.values(), key=lambda r: r.ob.id):
        ob = rec.ob
        ui.out(f"    {ob.id:<3}{ob.name:<22}{ob.counterparty:<32}{fmt(ob.amount, ob.currency):>16}"
               f"{str(ob.due_in_hours) + 'h':>6}{fmt(rec.decision.usd_equivalent):>14}")
    ui.out(f"    Needs ≈ {fmt(tri.total_need_usd, BASE_CURRENCY)} incl. payout fees; cash above the floor ≈ "
           f"{fmt(tri.cash_above_floor_usd, BASE_CURRENCY)} → covers {ui.s(f'{tri.coverage:.0%}', 'b', 'yellow')}.")
    ui.pause()

    ui.section("Plan in priority order (policy.py rules; each decision with its reason)")
    for rec in agent.records.values():
        show_decision(ui, rec)
        ui.pause(0.5)
    ui.out()
    ui.floor(DEFAULT_POLICY.reserve_floor)
    ui.cash_bar(agent.ledger.balance(BASE_CURRENCY), agent.ledger.committed(BASE_CURRENCY), DEFAULT_POLICY.reserve_floor)
    escalated = [r for r in agent.records.values() if r.state is State.ESCALATED]
    for rec in escalated:
        ui.section(f"Escalated to a human: #{rec.ob.id} {rec.ob.name}")
        show_card(ui, agent.approvals.get(rec.approval_id))
    return {"opening": tri.book_balances, "coverage": str(tri.coverage)}


def act2(ui: UI, agent: TreasuryAgent, scenario) -> None:
    ui.act("ACT 2 — CONFIDENCE DROP", "a customer email contradicts the receipt forecast")
    ui.section("Inbound email")
    for line in clean_text(scenario.customer_email).strip().splitlines():
        ui.out("    " + ui.s("│ ", "dim") + line)
    ui.pause()
    ev = agent.ingest_customer_email(scenario.customer_email)
    sig = ev.signal
    ui.section(f"Structured signal (read by {sig.reader})")
    ui.out(f"    stance={ui.s(sig.stance, 'b')}  invoice={sig.invoice_id}  delay_days={sig.expected_delay_days}  "
           f"new_date={sig.new_expected_date}")
    ui.wrap(f"evidence: \"{sig.evidence_quote}\"", indent=4)
    ui.out(ui.s("    The model only extracts this signal. Code below decides what it means.", "dim"))
    ui.section("Forecast → limit (forecast.py + policy.py)")
    ui.wrap(ev.impact.explanation, indent=4)
    ui.out(f"    {'':<22}{'before':>14}{'after':>14}")
    ui.out(f"    {'Forecast confidence':<22}{str(ev.impact.before):>14}{ui.s(f'{ev.impact.after:>14}', 'b', 'red')}")
    ui.out(f"    {'Autonomous FX limit':<22}{fmt(ev.limit_before):>14}{ui.s(f'{fmt(ev.limit_after):>14}', 'b', 'red')}")
    ui.pause()
    if not ev.gated:
        ui.out(ui.s("    No planned conversion crosses the new limit.", "dim"))
    for rec, req in ev.gated:
        ui.section(f"Approval gate: #{rec.ob.id} {rec.ob.name} — same action, now needs a human")
        show_decision(ui, rec)
        show_card(ui, req)
    ui.pause()


def act3(ui: UI, agent: TreasuryAgent, scenario, simulator: SandboxSimulator) -> None:
    dep = scenario.deposit
    ui.act("ACT 3 — DEPOSIT ARRIVES", f"{fmt(dep.amount, dep.currency)} mid-cycle")
    ui.section("Sandbox: POST /simulation/deposit/create (simulation.py)")
    resp = simulator.deposit(amount=dep.amount, currency=dep.currency, payer_name=dep.payer_name,
                             reference=dep.reference)
    ui.out(f"    {dep.payer_name} · {dep.reference} · response status {resp.get('status')} "
           + ui.s("(posts immediately; the agent re-reads balances before recalculating)", "dim"))
    ui.pause()
    rc = agent.on_balance_event(currency=dep.currency, amount=dep.amount, reference=dep.reference)
    ui.section("Recalculation event (not a rerun)")
    ui.out(f"    Headroom above the floor: {fmt(rc.headroom_before)} → {fmt(rc.headroom_after_deposit)} after the deposit")
    affected = ", ".join(f"#{c.obligation_id}" for c in sorted(rc.changes, key=lambda c: c.obligation_id)) or "none"
    untouched = ", ".join(f"#{i}" for i in sorted(rc.untouched)) or "none"
    ui.out(f"    Affected (cash-constrained): {affected}    Untouched: {untouched}")
    for change in sorted(rc.changes, key=lambda c: c.obligation_id):
        rec = agent.records[change.obligation_id]
        ui.out()
        ui.out(f"    #{rec.ob.id} {rec.ob.name}: {change.old_decision.action.value} [{change.old_state.value}] → "
               + ui.s(f"{change.new_decision.action.value} [{change.new_state.value}]", "b",
                      ACTION_STYLE[change.new_decision.action.value]))
        ui.wrap("before: " + change.old_decision.reason, indent=8)
        ui.wrap("after:  " + change.new_decision.reason, indent=8)
        if change.superseded_approval:
            ui.out(ui.s(f"        approval {change.superseded_approval} superseded: its evidence changed", "yellow"))
        if change.new_approval:
            show_card(ui, agent.approvals.get(change.new_approval))
    ui.out()
    ui.floor(DEFAULT_POLICY.reserve_floor)
    ui.cash_bar(agent.ledger.balance(BASE_CURRENCY), agent.ledger.committed(BASE_CURRENCY), DEFAULT_POLICY.reserve_floor)
    ui.pause()


def advance_to_paid(ui: UI, agent: TreasuryAgent, simulator: SandboxSimulator, obligation_id: int) -> None:
    """Sandbox only: walk the transfer to a terminal status, then let the agent observe it."""
    rec = agent.records[obligation_id]
    for target in ("SENT", "PAID"):
        status = rec.transfer.get("status")
        if status in {"PAID", "CANCELLED", "FAILED"}:
            break
        if status == target:
            continue
        try:
            if target == "SENT" and status != "PROCESSING":
                simulator.advance_transfer(rec.transfer["id"], "PROCESSING")
            simulator.advance_transfer(rec.transfer["id"], target)
        except SimulationError as exc:
            ui.out(ui.s(f"    (sandbox transition skipped: {exc})", "dim"))
            break
        agent.refresh_payouts()
        status = rec.transfer.get("status")
        note = {"SENT": "in flight, not final", "PAID": "terminal"}.get(status, "")
        ui.out(f"       transfer status → {ui.s(status, 'b')} " + ui.s(f"({note})", "dim"))
        ui.pause(0.5)


def act4(ui: UI, agent: TreasuryAgent, simulator: SandboxSimulator, *, auto: bool, credentials_for):
    ui.act("ACT 4 — EXECUTION", "bound approval → one quote → conversion (REST) → beneficiary → transfer")
    for req in agent.pending_approvals():
        if req.kind == "FX_CONVERSION":
            ui.section(f"Human approval for #{req.obligation_id}")
            obtain_approval(ui, agent, req, auto=auto, credentials=credentials_for(req.kind))
            ui.pause()
    results = agent.execute()
    if not results:
        ui.out(ui.s("    Nothing is authorised to execute (approval still pending).", "yellow"))
    for res in results:
        rec = agent.records[res.obligation_id]
        ui.section(f"#{rec.ob.id} {rec.ob.name}")
        if res.quote:
            ui.out(f"    1. Quote   POST /fx/quotes/create  → {res.quote['quote_id']}  buy "
                   f"{fmt(res.quote['buy_amount'], res.quote['buy_currency'])} for "
                   f"{fmt(res.quote['sell_amount'], res.quote['sell_currency'])} (single use, no x-api-version)")
        if res.conversion:
            c = res.conversion
            ui.out(f"    2. Convert POST /fx/conversions/create → {c.get('conversion_id')}  status {c.get('status')}  "
                   f"rate {c.get('client_rate')}")
        if res.beneficiary_id:
            ui.out(f"    3. Payee   POST /beneficiaries/create   → {res.beneficiary_id} (schema-checked: "
                   f"{rec.ob.payout_country} · {rec.ob.currency} · {rec.ob.payout_method})")
        if res.transfer:
            t = res.transfer
            ui.out(f"    4. Pay     POST /transfers/create       → {t.get('id')}  {fmt(t.get('transfer_amount'), t.get('transfer_currency'))}"
                   f" + fee {fmt(t.get('fee_amount') or 0, t.get('transfer_currency'))}  status {t.get('status')}")
        if res.status in {"gated", "blocked"}:
            ui.out(ui.s(f"    ✗ {res.status}: {res.detail}", "red"))
        elif res.status == "handoff":
            ui.out(ui.s(f"    → {res.detail}", "yellow"))
        ui.pause()
        if res.transfer and res.status == "in_flight":
            advance_to_paid(ui, agent, simulator, res.obligation_id)
    ui.section("Reserve confirmation (balances re-read and reconciled)")
    report = agent.reserve_report()
    ui.out("    Airwallex now: " + balances_line(report.actual))
    ui.out("    Ledger book:   " + balances_line(report.book))
    kinds = ", ".join(f"{k} {fmt(v)}" for k, v in sorted(report.committed_by_kind.items()))
    ui.out(f"    {BASE_CURRENCY} committed {fmt(report.committed)} ({kinds})")
    ui.out(f"    {BASE_CURRENCY} uncommitted {fmt(report.uncommitted)} vs floor {fmt(report.floor)} → "
           + (ui.s(f"FLOOR INTACT · headroom {fmt(report.headroom)}", "b", "green") if report.intact
              else ui.s("RESERVE AT RISK", "b", "red")))
    ui.floor(report.floor)
    ui.cash_bar(agent.ledger.balance(BASE_CURRENCY), report.committed, report.floor)
    return report


def close(ui: UI, agent: TreasuryAgent, scenario, opening: dict, report) -> dict:
    ui.act("CLOSE", "starting balance → decisions → deposit → final balance")
    ui.out(f"  Start      {balances_line(opening)}")
    ui.out("  Decisions")
    for rec in agent.records.values():
        last_rule = rec.history[-1]["rule"] if rec.history else "-"
        path = " → ".join([rec.history[0]["from"]] + [h["to"] for h in rec.history]) if rec.history else rec.state.value
        ui.out(f"    #{rec.ob.id} {rec.ob.name:<20} {fmt(rec.ob.amount, rec.ob.currency):>15}  "
               + ui.s(f"{path}", STATE_STYLE.get(rec.state, "dim")) + ui.s(f"   ({last_rule})", "dim"))
    dep = scenario.deposit
    ui.out(f"  Deposit    +{fmt(dep.amount, dep.currency)} from {dep.payer_name} → recalculated only the "
           "cash-constrained decisions")
    ui.out(f"  Final      {balances_line(report.actual)}")
    ui.out(f"  Reserve    {BASE_CURRENCY} {fmt(report.uncommitted)} uncommitted ≥ floor {fmt(report.floor)}: "
           + (ui.s("INTACT", "b", "green") if report.intact else ui.s("AT RISK", "b", "red"))
           + f"   (ledger reconciled with Airwallex: {'yes' if not report.mismatches else 'NO'})")
    pending = agent.pending_approvals()
    if pending:
        ui.out("  Waiting on a human: " + "; ".join(
            f"#{p.obligation_id} {fmt(p.amount, p.currency)} → {p.counterparty} (code {p.code})" for p in pending))
    ui.section("Audit log · every action with its reason")
    shown = {"state", "approval_requested", "approval_granted", "approval_refused", "approval_auth_failed",
             "fx_quote", "payout_sent", "payout_status", "deposit_confirmed", "recalculated", "confidence",
             "email_read", "reserve_confirmed", "reserve_alert", "blocked", "halted", "fee_mismatch",
             "beneficiary_created", "beneficiary_reused", "payee_pinned", "duplicate_invoice", "handoff"}
    for e in agent.audit.entries:
        if e.event not in shown:
            continue
        tag = f"#{e.obligation_id}" if e.obligation_id else "  "
        who = e.actor if e.actor != "agent" else ""
        ui.out(ui.s(f"  {e.act:<6} {tag:<3} {e.event:<19}", "dim") + " "
               + textwrap.shorten((f"[{who}] " if who else "") + e.reason, ui.width - 34))
    verify = agent.store.verify()
    ui.section("Audit database")
    ui.out(f"    {agent.store.path}  ·  {verify.entries} entries  ·  chain {verify.chain}  ·  "
           + (ui.s("VERIFIED", "b", "green") if verify.ok else ui.s("PROBLEMS: " + "; ".join(verify.problems), "b", "red")))
    ui.out(ui.s(f"    head {verify.head_hash[:16]}…  (append-only: triggers refuse UPDATE/DELETE; "
                "re-check with: python manage.py verify-audit)", "dim"))
    anchor_file = os.environ.get("TREASURY_ANCHOR_FILE")
    if anchor_file:  # record the head somewhere the database's owner cannot rewrite
        with open(anchor_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({**agent.store.head(), "db": str(agent.store.path)}, sort_keys=True) + "\n")
        ui.out(ui.s(f"    head anchored to {anchor_file}", "dim"))
    if REPO_URL:
        ui.out(f"  Repo: {REPO_URL}")
    return {
        "opening": opening, "final_actual": report.actual, "final_book": report.book,
        "reserve": {"uncommitted": report.uncommitted, "floor": report.floor, "intact": report.intact,
                    "headroom": report.headroom, "committed_by_kind": report.committed_by_kind},
        "obligations": {r.ob.id: r.state.value for r in agent.records.values()},
        "pending_approvals": [p.id for p in pending],
        "audit": {"db": str(agent.store.path), "entries": verify.entries, "head": verify.head_hash,
                  "verified": verify.ok},
    }


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------
def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--mock", action="store_true", help="use the local mock sandbox (default without credentials)")
    mode.add_argument("--live", action="store_true", help="use the Airwallex sandbox (needs AWX_CLIENT_ID/AWX_API_KEY)")
    p.add_argument("--yes", action="store_true",
                   help="approve the FX card unattended (mock: demo approver; live: TREASURY_APPROVER_ID/PIN)")
    p.add_argument("--pace", type=float, default=0.0, help="seconds to pause between beats (for recording)")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--no-cap", action="store_true", help="plan with full sandbox balances instead of the scenario's operating cash")
    p.add_argument("--llm", choices=["auto", "anthropic", "openai", "rules"], help="override LLM_PROVIDER")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.llm:
        os.environ["LLM_PROVIDER"] = args.llm
    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    ui = UI(color=not args.no_color and sys.stdout.isatty() and not os.environ.get("NO_COLOR"), pace=args.pace)
    scenario = load_scenario()
    suffix = os.environ.get("TREASURY_REFERENCE_SUFFIX", "")
    if suffix:  # only to re-run the live demo: the duplicate-invoice guard blocks re-paying the same reference
        scenario = replace(scenario, obligations=tuple(replace(o, reference=o.reference + suffix)
                                                       for o in scenario.obligations))
    use_mock = args.mock or (not args.live and not settings.has_airwallex_credentials)
    if args.yes and not use_mock and is_production(settings.base_url):
        print("--yes (unattended approval) is refused against production: approvers sign in at the terminal",
              file=sys.stderr)
        return 2
    if not use_mock and settings.screening_list is None and os.environ.get("TREASURY_ALLOW_NO_SCREENING") != "1":
        print("counterparty screening is required outside mock mode (set TREASURY_SCREENING_LIST, or "
              "TREASURY_ALLOW_NO_SCREENING=1 to run without it, which is recorded in the audit log)", file=sys.stderr)
        return 2
    if args.live and not settings.has_airwallex_credentials:
        print("--live needs AWX_CLIENT_ID and AWX_API_KEY in the environment or .env", file=sys.stderr)
        return 2

    mock = None
    if use_mock:
        mock = MockAirwallex(balances=scenario.operating_cash, rates_usd_per_unit=scenario.mock_rates,
                             swift_fees=dict(DEFAULT_POLICY.swift_fees))
        base_url = mock.start()
        client = AirwallexClient(base_url, MOCK_CLIENT_ID, MOCK_API_KEY, api_version=settings.api_version)
        where = f"offline mock sandbox at {base_url}"
    else:
        client = AirwallexClient(settings.base_url, settings.client_id, settings.api_key,
                                 api_version=settings.api_version)
        where = f"Airwallex sandbox {settings.base_url}"

    try:
        llm = make_llm(settings)
    except LLMError as exc:
        print(f"LLM config error: {exc}", file=sys.stderr)
        return 2

    cycle = new_cycle_id()
    mode = "mock" if use_mock else "live"
    for warning in settings.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    try:
        store = open_store(settings, mode=mode, cycle_id=cycle)
        screener = make_screener(settings)
    except StoreError as exc:
        print(f"database error: {exc}", file=sys.stderr)
        if mock:
            mock.stop()
        return 2
    operator = "demo.operator" if use_mock else settings.operator
    if use_mock:
        seed_mock_database(store)
    cap = None if (args.no_cap or not settings.apply_scenario_cash_cap) else scenario.operating_cash
    agent = TreasuryAgent(client, obligations=scenario.obligations, receipt=scenario.expected_receipt,
                          payouts=scenario.payouts, reader=make_reader(llm), explainer=Explainer(llm),
                          store=store, cycle_id=cycle, operator=operator, mode=mode, screener=screener,
                          cash_cap=cap)
    if use_mock:
        seed_mock_payees(agent, scenario)
    simulator = SandboxSimulator(client)

    def credentials_for(kind: str):
        if use_mock:
            approver_id = DEMO_APPROVER_FOR_KIND[kind]
            return approver_id, DEMO_APPROVERS[approver_id][2]
        if settings.approver_id and settings.approver_pin:
            return settings.approver_id, settings.approver_pin
        return None

    ui.act("ADAPTIVE TREASURY CONTROLLER", scenario.company)
    ui.wrap("Five bills fall due in 72 hours across USD, EUR and GBP. Cash above a USD "
            f"{fmt(DEFAULT_POLICY.reserve_floor)} reserve floor covers only part of them. The agent must choose "
            "what to fund, what to convert, what to defer and what a human must decide — and adapt when the "
            "evidence or the balance changes.", indent=2)
    ui.out(ui.s(f"  Running against {where} · model: {llm.name if llm else 'none (deterministic reader)'} · cycle {cycle}", "dim"))
    ui.out(ui.s(f"  Operator {operator} · audit DB {store.path.name} ({store.keyed and 'HMAC-chained' or 'hash-chained'}) · "
                f"screening {screener.version if screener else 'OFF'}", "dim"))
    if screener is None:
        ui.out(ui.s("  WARNING: counterparty screening is disabled (TREASURY_SCREENING_LIST=off).", "b", "red"))
    ui.pause()

    summary = {"cycle": cycle, "mode": mode}
    code = 0
    try:
        agent.audit.act = "act1"
        summary.update(act1(ui, agent, scenario))
        agent.checkpoint("act1")
        agent.audit.act = "act2"
        act2(ui, agent, scenario)
        agent.checkpoint("act2")
        agent.audit.act = "act3"
        act3(ui, agent, scenario, simulator)
        agent.checkpoint("act3")
        agent.audit.act = "act4"
        report = act4(ui, agent, simulator, auto=args.yes, credentials_for=credentials_for)
        agent.audit.act = "close"
        summary["close"] = close(ui, agent, scenario, summary["opening"], report)
    except (AgentHalted, AirwallexError, SimulationError) as exc:
        ui.out(ui.s(f"\n  STOPPED SAFELY: {exc}", "b", "red"))
        agent.audit.record("stopped", str(exc))
        code = 1
    finally:
        try:
            agent.checkpoint("final")
            write_json(settings.state_dir / "runs" / f"{cycle}.summary.json", summary)
        finally:
            store.close()
            if mock:
                mock.stop()
    return code


def seed_mock_database(store) -> None:
    """Mock only: enrol the demo approvers (fake money, throwaway database)."""
    for approver_id, (name, roles, pin) in DEMO_APPROVERS.items():
        store.enroll_approver(approver_id, name, roles, pin, created_by="seed:mock-demo")


def seed_mock_payees(agent: TreasuryAgent, scenario) -> None:
    """Mock only: the Germany supplier's account was verified by call-back before this cycle,
    so Act 1's conversion can stay autonomous (live: python manage.py pin-payee)."""
    for ob in scenario.obligations:
        dest = agent._destination(ob)
        if dest and agent.store.get_payee(payee_key(ob)) is None:
            fp, masked = dest
            entry = agent.store.repin_payee(
                payee_key(ob), fp, masked, changed_by="seed:mock-demo",
                reason="demo seed: account verified by call-back before the cycle",
                audit=agent.audit.draft("payee_pinned",
                                        f"{ob.counterparty} pinned to {masked} (demo seed: verified by "
                                        "call-back before the cycle).",
                                        obligation_id=ob.id, actor="seed:mock-demo", destination=masked))
            agent.audit.adopt(entry)


if __name__ == "__main__":
    sys.exit(main())
