"""Orchestrator: read state -> plan -> act -> recalculate.

The agent is a state machine over obligations. Events move it forward:

  bootstrap()              read balances + indicative rates, open the ledger, assess the forecast
  triage()                 Act 1: screen counterparties, then plan every obligation with the policy rules
  ingest_customer_email()  Act 2: model reads the email; code lowers confidence and the limit;
                           planned conversions now over the limit become approval-gated
  on_balance_event()       Act 3: confirm an inflow against Airwallex, then re-plan ONLY the
                           decisions whose outcome depended on scarce cash
  approve() / execute()    Act 4: authenticated, role-checked approval -> single-use quote ->
                           conversion (REST) -> beneficiary -> transfer, with duplicate protection
  refresh_payouts()        poll transfers to a terminal status (SENT is never final)
  reserve_report()         confirm the reserve floor against reconciled balances

Controls enforced before any money moves (re-checked at execution, not just at planning):
counterparty screening, pinned payee bank details, cumulative autonomy limit, bound and
authenticated approval, reserve floor, ledger reconciliation, and a database-level
one-payout-per-invoice constraint.

It imports nothing from ``simulation.py``: it cannot tell a sandbox from production.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Callable, Mapping, Sequence

import policy as rules
from airwallex_client import AirwallexClient, AirwallexError, AmbiguousResultError
from approvals import ApprovalBook, ApprovalError, ApprovalRequest, ApprovalStatus
from config import BASE_CURRENCY, DEFAULT_POLICY, PolicyConfig
from email_reader import EmailReader, EmailSignal
from explainer import Explainer
from forecast import Assessment, EmailImpact, ExpectedReceipt, apply_email, assess
from journal import AuditLog, OperationStore
from ledger import Ledger, Mismatch
from models import (ZERO, Action, Decision, Obligation, State, check_transition, fmt, q2,
                    to_decimal)
from screening import Screener, ScreenResult
from store import AuthError, DuplicatePayout, Store, mask

SETTLED_CONVERSION = {"SETTLED"}
TRANSFER_SUCCESS = {"PAID"}
TRANSFER_FAILED = {"CANCELLED", "FAILED"}
QUOTE_RETRY_CODES = {"expired_quote", "invalid_quote_id", "quote_expired", "quote_id_invalid"}


class AgentHalted(RuntimeError):
    """Execution stopped for safety (reconciliation mismatch, bad quote, schema failure...)."""


# ---------------------------------------------------------------------------
# Records and event results
# ---------------------------------------------------------------------------
@dataclass
class ObligationRecord:
    ob: Obligation
    state: State = State.PENDING
    decision: Decision | None = None
    approval_id: str | None = None
    history: list[dict] = field(default_factory=list)
    conversion: dict | None = None
    transfer: dict | None = None
    beneficiary_id: str | None = None
    deferred_until: datetime | None = None


@dataclass
class TriageResult:
    records: list[ObligationRecord]
    book_balances: dict[str, Decimal]
    actual_balances: dict[str, Decimal]
    capped: bool
    headroom_before: Decimal
    headroom_after: Decimal
    total_need_usd: Decimal
    cash_above_floor_usd: Decimal
    coverage: Decimal
    confidence: Decimal
    limit: Decimal
    assessment: Assessment
    rates: dict[str, Decimal]
    screening_hits: list[int]


@dataclass
class ConfidenceEvent:
    signal: EmailSignal
    impact: EmailImpact
    limit_before: Decimal
    limit_after: Decimal
    gated: list[tuple[ObligationRecord, ApprovalRequest]]


@dataclass
class RecalcChange:
    obligation_id: int
    old_state: State
    new_state: State
    old_decision: Decision
    new_decision: Decision
    superseded_approval: str | None
    new_approval: str | None


@dataclass
class RecalcResult:
    currency: str
    amount: Decimal
    reference: str
    headroom_before: Decimal
    headroom_after_deposit: Decimal
    headroom_after: Decimal
    changes: list[RecalcChange]
    untouched: list[int]


@dataclass
class ExecutionResult:
    obligation_id: int
    status: str                  # paid_out | in_flight | gated | blocked | handoff
    detail: str
    quote: dict | None = None
    conversion: dict | None = None
    beneficiary_id: str | None = None
    transfer: dict | None = None
    replayed: bool = False


@dataclass
class ReserveReport:
    book: dict[str, Decimal]
    actual: dict[str, Decimal]
    committed_by_kind: dict[str, Decimal]
    committed: Decimal
    uncommitted: Decimal
    floor: Decimal
    headroom: Decimal
    intact: bool
    mismatches: list[Mismatch]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def usd_per_unit_from_rate(payload: Mapping, currency: str, base: str = BASE_CURRENCY) -> Decimal:
    """Read an indicative rate defensively; prefer the CLIENT amounts over the bare rate."""
    for detail in payload.get("rate_details", []) or []:
        if detail.get("level", "CLIENT") == "CLIENT" and detail.get("buy_amount") and detail.get("sell_amount"):
            value = to_decimal(detail["sell_amount"]) / to_decimal(detail["buy_amount"])
            break
    else:
        rate = to_decimal(payload["rate"])
        pair = str(payload.get("currency_pair", ""))
        if pair == f"{currency}{base}":
            value = rate
        elif pair == f"{base}{currency}":
            value = Decimal(1) / rate
        else:
            raise AgentHalted(f"cannot interpret rate for {currency}: pair {pair!r}")
    if not Decimal("0.0001") < value < Decimal("1000"):
        raise AgentHalted(f"implausible {currency}/{base} rate {value}")
    return value.quantize(Decimal("0.000001"))


def _resolve_path(payload: Mapping, path: str):
    if path == "transfer_method":
        methods = payload.get("transfer_methods") or []
        return methods[0] if methods else None
    node = payload
    for part in path.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return None
        node = node[part]
    return node


def check_against_schema(payload: Mapping, schema: Mapping) -> list[str]:
    """Return problems: missing required fields or values that fail the schema's patterns."""
    problems = []
    for spec in schema.get("fields", []) or []:
        path = spec.get("path") or spec.get("key")
        if not path:
            continue
        value = _resolve_path(payload, path)
        if value in (None, ""):
            if spec.get("required"):
                problems.append(f"missing required field {path}")
            continue
        pattern = (spec.get("rule") or {}).get("pattern")
        if pattern:
            try:
                if not re.fullmatch(pattern, str(value)):
                    problems.append(f"{path} does not match the required pattern")
            except re.error:
                continue  # a pattern Python cannot compile is checked server-side
    return problems


def payee_key(ob: Obligation) -> str:
    return " ".join(ob.counterparty.casefold().split())


def account_fields(bank: Mapping) -> dict:
    fields = {k: str(bank.get(k) or "").replace(" ", "").upper()
              for k in ("iban", "account_number", "account_routing_type1", "account_routing_value1",
                        "swift_code", "account_currency", "bank_country_code")}
    # Keep historical fingerprints stable for destinations without a second routing identifier.
    for k in ("account_routing_type2", "account_routing_value2"):
        value = str(bank.get(k) or "").replace(" ", "").upper()
        if value:
            fields[k] = value
    return fields


def masked_account(fields: Mapping) -> str:
    acct = fields["iban"] or fields["account_number"]
    text = ("IBAN " if fields["iban"] else "Acct ") + mask(acct)
    if fields["swift_code"]:
        text += f" · BIC {fields['swift_code']}"
    return text + f" · {fields['account_currency']}"


# ---------------------------------------------------------------------------
# The agent
# ---------------------------------------------------------------------------
class TreasuryAgent:
    def __init__(self, client: AirwallexClient, *, obligations: Sequence[Obligation],
                 receipt: ExpectedReceipt, payouts: Mapping[int, Mapping], reader: EmailReader,
                 explainer: Explainer, store: Store, cycle_id: str, operator: str, mode: str = "live",
                 screener: Screener | None = None, policy: PolicyConfig = DEFAULT_POLICY,
                 cash_cap: Mapping[str, Decimal] | None = None, sleep=time.sleep,
                 clock: Callable[[], datetime] | None = None):
        if not operator:
            raise ValueError("the operator running the agent must be identified")
        self.client = client
        self.policy = policy
        self.receipt = receipt
        self.payouts = dict(payouts)
        self.reader = reader
        self.explainer = explainer
        self.store = store
        self.cycle_id = cycle_id
        self.operator = operator
        self.screener = screener
        self.cash_cap = dict(cash_cap) if cash_cap else None
        self._sleep = sleep
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self.policy_fp = rules.policy_fingerprint(policy)
        if store.cycle(cycle_id) is None:
            store.start_cycle(cycle_id, mode=mode, operator=operator, policy_fingerprint=self.policy_fp,
                              model=getattr(reader, "name", "rules"))
        self.audit = AuditLog(store, cycle_id)
        self.ops = OperationStore(store, cycle_id)
        self.approvals = ApprovalBook(ttl_hours=policy.approval_ttl_hours,
                                      persist=lambda req: store.save_approval(cycle_id, req))
        for req in self.approvals.reload(store.approval_rows(cycle_id)):
            self.audit.record("approval_expired",
                              f"Approval {req.id} ({req.kind}, #{req.obligation_id} "
                              f"{fmt(req.amount, req.currency)} → {req.counterparty}) had passed its expiry "
                              "when this cycle was opened again: closed, and it cannot be spent.",
                              obligation_id=req.obligation_id, approval_id=req.id,
                              actor=f"cycle:{cycle_id}")
        self.records: dict[int, ObligationRecord] = {
            ob.id: ObligationRecord(ob) for ob in sorted(obligations, key=rules.priority_key)}
        self.ledger: Ledger | None = None
        self.rates: dict[str, Decimal] = {}
        self.assessment: Assessment | None = None
        self.confidence: Decimal = Decimal("0")
        self.autonomous_executed: Decimal = ZERO
        self.halted: str | None = None
        self.audit.record("cycle_started", f"Cycle {cycle_id} started by {operator} ({mode}).",
                          actor=f"operator:{operator}", policy_fingerprint=self.policy_fp,
                          code_fingerprint=store.cycle(cycle_id)["code_fingerprint"],
                          model=getattr(reader, "name", "rules"),
                          screening_list=getattr(screener, "version", None),
                          audit_chain=store.keyed and "hmac-sha256" or "sha256")

    # ------------------------------------------------------------------ basics
    def _read_balances(self) -> dict[str, Decimal]:
        return {cur: b.available for cur, b in self.client.get_balances().items()}

    def headroom(self) -> Decimal:
        return q2(self.ledger.free(BASE_CURRENCY) - self.policy.reserve_floor)

    def _held(self) -> dict[str, Decimal]:
        return {cur: self.ledger.free(cur) for cur in self.ledger.currencies() if cur != BASE_CURRENCY}

    def _planned_autonomous(self) -> Decimal:
        return q2(sum((r.decision.fx.est_sell_amount for r in self.records.values()
                       if r.state is State.FX_PLANNED), ZERO))

    def _ctx(self, autonomous_used=None) -> rules.PlanContext:
        used = self.autonomous_executed if autonomous_used is None else autonomous_used
        return rules.PlanContext(headroom=self.headroom(), held=self._held(), usd_per_unit=self.rates,
                                 confidence=self.confidence, autonomous_used=used)

    def _now(self) -> datetime:
        return self._clock()

    def _halt(self, why: str) -> None:
        self.halted = why
        self.audit.record("halted", why)
        raise AgentHalted(why)

    def _ensure_running(self) -> None:
        if self.halted:
            raise AgentHalted(f"agent halted: {self.halted}")

    def _sync(self, wait_seconds: float = 0.0, poll_every: float = 1.0) -> dict[str, Decimal]:
        """Re-read Airwallex and reconcile. Any unexplained movement halts execution.
        After our own money movement, allow a short settlement lag before declaring a mismatch."""
        deadline = time.monotonic() + wait_seconds
        while True:
            actual = self._read_balances()
            mismatches = self.ledger.reconcile(actual)
            if not mismatches:
                return actual
            if time.monotonic() >= deadline:
                self._halt("ledger out of sync with Airwallex: " + "; ".join(map(str, mismatches)))
            self._sleep(poll_every)

    def _transition(self, rec: ObligationRecord, new: State, why: str, rule: str) -> None:
        check_transition(rec.state, new)
        rec.history.append({"act": self.audit.act, "from": rec.state.value, "to": new.value, "rule": rule})
        self.audit.record("state", why, obligation_id=rec.ob.id, rule=rule, from_state=rec.state.value,
                          to_state=new.value, policy_fingerprint=self.policy_fp)
        rec.state = new

    def checkpoint(self, act: str) -> None:
        self.store.save_snapshot(self.cycle_id, act, self.snapshot())

    # ------------------------------------------------------------------ screening and payees
    def _beneficiary_spec(self, ob_id: int) -> Mapping | None:
        return (self.payouts.get(ob_id) or {}).get("beneficiary")

    def _payee_names(self, ob: Obligation) -> list[str]:
        names = [ob.counterparty]
        spec = self._beneficiary_spec(ob.id)
        if spec:
            b = spec.get("beneficiary") or {}
            names += [b.get("company_name"), (b.get("bank_details") or {}).get("account_name"),
                      " ".join(x for x in (b.get("first_name"), b.get("last_name")) if x)]
        return [n for n in names if n]

    def _screen(self, ob: Obligation) -> ScreenResult | None:
        if self.screener is None:
            return None
        res = self.screener.screen(self._payee_names(ob))
        self.audit.record("screened", f"{'HIT' if res.hit else 'clear'}: {ob.counterparty} against screening "
                          f"list {res.list_version}.", obligation_id=ob.id, hit=res.hit,
                          matched=res.matched_name, list_entry=res.list_entry, list_version=res.list_version)
        return res

    def _destination(self, ob: Obligation) -> tuple[str, str] | None:
        spec = self._beneficiary_spec(ob.id)
        if not spec:
            return None
        fields = account_fields((spec.get("beneficiary") or {}).get("bank_details") or {})
        return self.store.fingerprint("payee-account", fields), masked_account(fields)

    # ------------------------------------------------------------------ Act 1
    def bootstrap(self) -> None:
        actual = self._read_balances()
        self.ledger = Ledger(actual, cap=self.cash_cap)
        self.audit.record("balances_read", "Opening position read from Airwallex /balances/current.",
                          actual=actual, book=self.ledger.balances, capped=self.ledger.capped)
        foreign = sorted({r.ob.currency for r in self.records.values() if r.ob.currency != BASE_CURRENCY})
        for cur in foreign:
            need = sum((rules.gross_need(r.ob, self.policy) for r in self.records.values()
                        if r.ob.currency == cur), ZERO)
            payload = self.client.get_rate(buy_currency=cur, sell_currency=BASE_CURRENCY, buy_amount=need)
            self.rates[cur] = usd_per_unit_from_rate(payload, cur)
        self.audit.record("rates_read", "Indicative FX rates for planning (not quotes).", rates=self.rates)
        self.assessment = assess(self.receipt)
        self.confidence = self.assessment.confidence
        self.audit.record("forecast", " ".join(self.assessment.lines), confidence=self.confidence,
                          limit=rules.autonomous_fx_limit(self.confidence))

    def triage(self) -> TriageResult:
        self._ensure_running()
        if self.ledger is None:
            self.bootstrap()
        if any(r.state is not State.PENDING for r in self.records.values()):
            raise AgentHalted("triage already ran; later changes arrive as events, not reruns")
        headroom_before = self.headroom()
        decisions: dict[int, Decision] = {}
        hits: list[int] = []
        for rec in self.records.values():
            res = self._screen(rec.ob)
            if res and res.hit:
                hits.append(rec.ob.id)
                decisions[rec.ob.id] = self._screening_decision(rec.ob, res)
        clear = [r.ob for r in self.records.values() if r.ob.id not in decisions]
        decisions.update(rules.plan(clear, self._ctx(), self.policy))
        for rec in self.records.values():
            self._apply_decision(rec, decisions[rec.ob.id])
        total_need = q2(sum((d.usd_equivalent for d in decisions.values()), ZERO))
        held_usd = sum((rules.usd_equivalent(v, c, self.rates) for c, v in self._held_at_open().items()), ZERO)
        cash_above_floor = q2(headroom_before + held_usd)
        return TriageResult(
            records=list(self.records.values()), book_balances=dict(self.ledger.opening),
            actual_balances=dict(self.ledger.actual_opening), capped=self.ledger.capped,
            headroom_before=headroom_before, headroom_after=self.headroom(),
            total_need_usd=total_need, cash_above_floor_usd=cash_above_floor,
            coverage=(cash_above_floor / total_need).quantize(Decimal("0.001")) if total_need else Decimal(1),
            confidence=self.confidence, limit=rules.autonomous_fx_limit(self.confidence),
            assessment=self.assessment, rates=dict(self.rates), screening_hits=hits)

    def _screening_decision(self, ob: Obligation, res: ScreenResult) -> Decision:
        gross = rules.gross_need(ob, self.policy)
        return Decision(
            ob.id, Action.ESCALATE, "R0_SCREENING_HIT",
            f"Counterparty screening matched '{res.list_entry}' (list {res.list_version}). No cash is planned and "
            f"nothing will be paid unless a compliance officer clears it.",
            gross_amount=gross, fee=rules.payout_fee(ob, self.policy),
            usd_equivalent=rules.usd_equivalent(gross, ob.currency, self.rates), requires_approval=True)

    def _held_at_open(self) -> dict[str, Decimal]:
        return {c: v for c, v in self.ledger.opening.items() if c != BASE_CURRENCY and c in self.rates}

    def _apply_decision(self, rec: ObligationRecord, d: Decision) -> None:
        ob = rec.ob
        if d.action is Action.CONVERT and not d.requires_approval and self.store.get_payee(payee_key(ob)) is None:
            d = replace(rules.with_note(d, "R8: first payment to an account not yet pinned for this payee; "
                                           "a human must approve the destination."), requires_approval=True)
        if d.action is Action.FUND:
            target, kind = State.FUNDED, "funded"
        elif d.action is Action.CONVERT:
            target, kind = (State.AWAITING_APPROVAL if d.requires_approval else State.FX_PLANNED), "fx_reserved"
        elif d.action is Action.DEFER:
            target, kind = State.DEFERRED, None
        else:
            target, kind = State.ESCALATED, "held_pending_approval"
        check_transition(rec.state, target)
        if kind:
            self.ledger.commit(ob.id, BASE_CURRENCY, d.usd_draw, kind)
            if ob.currency != BASE_CURRENCY:
                self.ledger.commit(ob.id, ob.currency, d.held_draw,
                                   "fx_held" if d.action is not Action.FUND else kind)
        rec.decision = d
        self._transition(rec, target, d.reason, d.rule)
        if target is State.DEFERRED:
            now = self._now()
            if rec.deferred_until is None or rec.deferred_until <= now:
                rec.deferred_until = now + timedelta(days=self.policy.deferral_horizon_days)
        else:
            rec.deferred_until = None
        if target is State.AWAITING_APPROVAL:
            self._request_fx_approval(rec)
        elif target is State.ESCALATED:
            if d.rule == "R0_SCREENING_HIT":
                self._request_screening_approval(rec)
            else:
                self._request_exception_approval(rec)

    # ------------------------------------------------------------------ approval requests
    def _record_request(self, rec: ObligationRecord, req: ApprovalRequest, source: str, **extra) -> None:
        previous = rec.approval_id
        rec.approval_id = req.id
        self.audit.record("approval_requested", req.explanation or req.kind, obligation_id=rec.ob.id,
                          approval_id=req.id, code=req.code, kind=req.kind, amount=req.amount,
                          currency=req.currency, counterparty=req.counterparty, destination=req.destination,
                          requested_by=req.requested_by, supersedes=previous, explained_by=source, **extra)

    def _request_fx_approval(self, rec: ObligationRecord, extra_evidence: Sequence[str] = (),
                             model_reason: str = "") -> ApprovalRequest:
        d, ob = rec.decision, rec.ob
        fx = d.fx
        limit = rules.autonomous_fx_limit(self.confidence)
        dest = self._destination(ob)
        if dest is None:
            self._halt(f"no beneficiary details on file for obligation #{ob.id}; cannot bind a destination")
        dest_fp, dest_masked = dest
        evidence = [
            f"Obligation #{ob.id} {ob.name}: {fmt(ob.amount, ob.currency)} to {ob.counterparty}, due in {ob.due_in_hours}h.",
            f"Pays to {dest_masked} (account fingerprint {dest_fp[:12]}).",
            f"Minimum conversion: buy {fmt(fx.buy_amount, fx.buy_currency)} "
            f"(incl. {fmt(fx.fee, fx.buy_currency)} {ob.payout_method} fee, less {fmt(fx.held_used, fx.buy_currency)} held), "
            f"≈ {fmt(fx.est_sell_amount, fx.sell_currency)}.",
            f"Forecast confidence {self.confidence} → autonomous limit {fmt(limit, BASE_CURRENCY)}.",
            *[n for n in d.notes if n.startswith("R8")],
            *extra_evidence,
        ]
        ceiling = rules.approval_sell_ceiling(fx.est_sell_amount, self.policy)
        facts = {
            "ask": f"Approve converting {fmt(fx.buy_amount, fx.buy_currency)} (≈ {fmt(fx.est_sell_amount, fx.sell_currency)}, "
                   f"max {fmt(ceiling, fx.sell_currency)}) to pay {ob.counterparty}.",
            "why": f"The conversion needs a human: autonomous limit {fmt(limit, BASE_CURRENCY)} at forecast confidence "
                   f"{self.confidence}" + ("; first payment to this account." if any(n.startswith("R8") for n in d.notes)
                                           else "."),
            # Only text this program wrote reaches the model. The card's own evidence keeps the
            # customer's quoted words for the human, but a quote is untrusted input and must not
            # become the prompt of the call that drafts that human's note.
            "evidence_summary": model_reason or " ".join(self.assessment.lines if self.assessment else ()),
        }
        note, source = self.explainer.explain(facts)
        req = self.approvals.request(
            kind="FX_CONVERSION", obligation_id=ob.id, action="CONVERT", amount=fx.buy_amount,
            currency=fx.buy_currency, counterparty=ob.counterparty, evidence=evidence, requested_by=self.operator,
            sell_currency=fx.sell_currency, max_sell_amount=ceiling, destination=dest_masked,
            destination_fp=dest_fp, explanation=note)
        self._record_request(rec, req, source, max_sell=ceiling)
        return req

    def _request_exception_approval(self, rec: ObligationRecord, why: str | None = None) -> ApprovalRequest:
        d, ob = rec.decision, rec.ob
        head = f"Obligation #{ob.id} {ob.name}: {fmt(ob.amount, ob.currency)} to {ob.counterparty}, due in {ob.due_in_hours}h."
        if why:  # raised at execution time (e.g. payee details changed)
            evidence = [head, why]
        else:
            funding = (f"Funding: {fmt(d.usd_draw, BASE_CURRENCY)} held pending approval."
                       if d.usd_draw > 0 else f"Funding gap above the floor: {fmt(d.funding_gap, BASE_CURRENCY)}.")
            evidence = [
                head,
                f"Rule {d.rule}: {fmt(d.usd_equivalent, BASE_CURRENCY)} equivalent vs "
                f"{fmt(self.policy.single_payment_approval_threshold, BASE_CURRENCY)} single-payment threshold."
                if d.rule == "R5_ESCALATE_THRESHOLD" else f"Rule {d.rule}: {d.reason}",
                funding,
            ]
        dest = self._destination(ob)
        note, source = self.explainer.explain({
            "ask": f"Decide on paying {fmt(ob.amount, ob.currency)} to {ob.counterparty} ({ob.name}), "
                   f"due in {ob.due_in_hours}h.", "why": why or d.reason})
        req = self.approvals.request(
            kind="POLICY_EXCEPTION", obligation_id=ob.id, action="PAYOUT", amount=ob.amount,
            currency=ob.currency, counterparty=ob.counterparty, evidence=evidence, requested_by=self.operator,
            destination=dest[1] if dest else None, destination_fp=dest[0] if dest else None, explanation=note)
        self._record_request(rec, req, source)
        return req

    def _request_screening_approval(self, rec: ObligationRecord, why: str | None = None) -> ApprovalRequest:
        ob = rec.ob
        why = why or rec.decision.reason
        evidence = [f"Obligation #{ob.id} {ob.name}: {fmt(ob.amount, ob.currency)} to {ob.counterparty}.",
                    f"Names screened: {', '.join(self._payee_names(ob))}.", why]
        req = self.approvals.request(kind="SCREENING_REVIEW", obligation_id=ob.id, action="CLEAR_SCREENING_HIT",
                                     amount=ob.amount, currency=ob.currency, counterparty=ob.counterparty,
                                     evidence=evidence, requested_by=self.operator, explanation=why)
        self._record_request(rec, req, "template")
        return req

    def _request_payout_failure_approval(self, rec: ObligationRecord, transfer: dict, why: str) -> ApprovalRequest:
        ob = rec.ob
        evidence = [why, f"Original request_id {transfer.get('request_id')}; a resend must use a NEW request_id."]
        note, source = self.explainer.explain({"ask": f"Decide whether to resend {fmt(ob.amount, ob.currency)} "
                                                      f"to {ob.counterparty}.", "why": why})
        req = self.approvals.request(kind="PAYOUT_FAILED", obligation_id=ob.id, action="RESEND_PAYOUT",
                                     amount=ob.amount, currency=ob.currency, counterparty=ob.counterparty,
                                     evidence=evidence, requested_by=self.operator, explanation=note)
        self._record_request(rec, req, source)
        return req

    # ------------------------------------------------------------------ approver decisions
    def pending_approvals(self) -> list[ApprovalRequest]:
        return [r for r in self.approvals.requests.values() if r.status is ApprovalStatus.PENDING]

    def _authenticate(self, approver_id: str, pin: str, approval_id: str):
        try:
            return self.store.authenticate(approver_id, pin)
        except AuthError as exc:
            self.audit.record("approval_auth_failed", str(exc), actor=f"unauthenticated:{approver_id or '?'}",
                              approval_id=approval_id)
            raise ApprovalError(str(exc)) from exc

    def approve(self, approval_id: str, *, approver_id: str, pin: str, confirm_code: str) -> ApprovalRequest:
        approver = self._authenticate(approver_id, pin, approval_id)
        try:
            req = self.approvals.approve(approval_id, approver_id=approver.approver_id,
                                         approver_roles=approver.roles, confirm_code=confirm_code)
        except ApprovalError as exc:
            self.audit.record("approval_refused", str(exc), actor=f"approver:{approver.approver_id}",
                              approval_id=approval_id)
            raise
        self.audit.record("approval_granted", f"{approver.display_name} ({approver.approver_id}) approved the "
                          f"card shown (code {req.code}).", obligation_id=req.obligation_id,
                          actor=f"approver:{approver.approver_id}", approval_id=req.id, amount=req.amount,
                          currency=req.currency, counterparty=req.counterparty, destination=req.destination,
                          digest=req.digest)
        return req

    def reject(self, approval_id: str, *, approver_id: str, pin: str, reason: str = "") -> ApprovalRequest:
        approver = self._authenticate(approver_id, pin, approval_id)
        req = self.approvals.reject(approval_id, approver_id=approver.approver_id, approver_roles=approver.roles)
        self.audit.record("approval_rejected", f"{approver.approver_id} rejected: {reason or 'no reason given'}",
                          obligation_id=req.obligation_id, actor=f"approver:{approver.approver_id}",
                          approval_id=req.id)
        rec = self.records.get(req.obligation_id)
        if rec and rec.state is State.AWAITING_APPROVAL and rec.approval_id == req.id:
            released = self.ledger.release(rec.ob.id)
            self._transition(rec, State.ESCALATED, f"Conversion rejected by {approver.approver_id}; "
                             f"{fmt(released)} of reserved cash released. The obligation stays with a human.",
                             "APPROVAL_REJECTED")
        return req

    # ------------------------------------------------------------------ Act 2
    def ingest_customer_email(self, email: str) -> ConfidenceEvent:
        self._ensure_running()
        signal = self.reader.read(email, self.receipt.context())
        self.audit.record("email_read", f"Customer email read by {signal.reader}: stance={signal.stance}.",
                          stance=signal.stance, invoice_id=signal.invoice_id,
                          delay_days=signal.expected_delay_days, quote=signal.evidence_quote)
        impact = apply_email(self.confidence, signal, self.receipt, self.policy.planning_window_hours)
        limit_before = rules.autonomous_fx_limit(impact.before)
        self.confidence = impact.after
        limit_after = rules.autonomous_fx_limit(self.confidence)
        self.audit.record("confidence", impact.explanation, before=impact.before, after=impact.after,
                          limit_before=limit_before, limit_after=limit_after)
        gated = []
        running = self.autonomous_executed  # the limit is cumulative across the cycle
        for rec in self.records.values():
            if rec.state is not State.FX_PLANNED:
                continue
            est = rec.decision.fx.est_sell_amount
            if not rules.requires_fx_approval(est, self.confidence, running):
                running += est
                continue
            why = (f"R7: conversion ≈ {fmt(est, BASE_CURRENCY)} now exceeds the autonomous limit "
                   f"{fmt(limit_after, BASE_CURRENCY)} (confidence {impact.before} → {impact.after}); "
                   f"the same action now needs a human.")
            rec.decision = replace(rules.with_note(rec.decision, why), requires_approval=True)
            self._transition(rec, State.AWAITING_APPROVAL, why, "R7_FX_APPROVAL_GATE")
            req = self._request_fx_approval(rec, extra_evidence=(
                f"Customer email ({self.receipt.customer}): \"{signal.evidence_quote}\"",
                f"Confidence {impact.before} → {impact.after}; limit {fmt(limit_before, BASE_CURRENCY)} → "
                f"{fmt(limit_after, BASE_CURRENCY)}.",
            ), model_reason=impact.explanation)
            gated.append((rec, req))
        return ConfidenceEvent(signal, impact, limit_before, limit_after, gated)

    # ------------------------------------------------------------------ Act 3
    def on_balance_event(self, *, currency: str, amount, reference: str = "",
                         wait_seconds: float = 20.0, poll_every: float = 1.0) -> RecalcResult:
        """A bank notification says money arrived. Confirm it on Airwallex, then re-plan
        only the decisions that were constrained by cash."""
        self._ensure_running()
        amount = q2(amount)
        headroom_before = self.headroom()
        deadline = time.monotonic() + wait_seconds
        while True:
            actual = self._read_balances()
            inflow = self.ledger.unexplained_inflow(currency, actual)
            if inflow >= amount or time.monotonic() >= deadline:
                break
            self._sleep(poll_every)
        if inflow <= 0:
            self._halt(f"notified of {fmt(amount, currency)} but no inflow is visible on Airwallex")
        if inflow < amount:
            self._halt(f"notified of {fmt(amount, currency)} but Airwallex shows only {fmt(inflow, currency)}")
        # Exactly the notified deposit is booked. The rest of the unexplained inflow is left for the
        # reconciliation below to name: money nobody identified is not cash the plan may spend, and
        # booking it first would make the book agree with the bank by construction.
        self.ledger.apply_inflow(currency, amount)
        mismatches = self.ledger.reconcile(actual)
        if mismatches:
            self._halt("unexpected movement during deposit: " + "; ".join(map(str, mismatches)))
        self.audit.record("deposit_confirmed", f"Inflow {fmt(amount, currency)} confirmed on Airwallex "
                          f"({reference}). Recalculating cash-constrained decisions only.",
                          currency=currency, amount=amount)
        headroom_after_deposit = self.headroom()

        affected = [r for r in self.records.values()
                    if r.decision is not None and r.decision.cash_constrained
                    and r.state in {State.DEFERRED, State.ESCALATED}]
        untouched = [r.ob.id for r in self.records.values() if r not in affected]
        for rec in affected:
            self.ledger.release(rec.ob.id)
        new = rules.plan([r.ob for r in affected],
                         self._ctx(autonomous_used=self.autonomous_executed + self._planned_autonomous()),
                         self.policy)
        changes = []
        for rec in affected:
            old_state, old_decision, old_approval = rec.state, rec.decision, rec.approval_id
            decision = rules.with_note(new[rec.ob.id], f"Recalculated after {fmt(inflow, currency)} deposit.")
            self._apply_decision(rec, decision)
            superseded = None
            if old_approval and old_approval != rec.approval_id:
                prev = self.approvals.get(old_approval)
                superseded = old_approval if prev.status is ApprovalStatus.SUPERSEDED else None
            elif old_approval and rec.state is not State.ESCALATED:
                if self.approvals.get(old_approval).status in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED}:
                    self.approvals.supersede(old_approval)  # the exception is no longer needed
                    superseded = old_approval
                rec.approval_id = None
            changes.append(RecalcChange(rec.ob.id, old_state, rec.state, old_decision, rec.decision,
                                        superseded, rec.approval_id if rec.approval_id != old_approval else None))
        self.audit.record("recalculated", f"Recalculated #{', #'.join(str(c.obligation_id) for c in changes) or '-'}; "
                          f"untouched #{', #'.join(map(str, untouched))}.",
                          affected=[c.obligation_id for c in changes], untouched=untouched)
        return RecalcResult(currency, inflow, reference, headroom_before, headroom_after_deposit,
                            self.headroom(), changes, untouched)

    # ------------------------------------------------------------------ Act 4
    def reschedule_deferred(self) -> list[ExecutionResult]:
        """A deferral is a date, not a dead end: when it comes due, re-plan against current cash."""
        self._ensure_running()
        if self.ledger is None:
            return []
        now = self._now()
        results = []
        for rec in self.records.values():
            if rec.state is not State.DEFERRED or rec.deferred_until is None or rec.deferred_until > now:
                continue
            due = rec.deferred_until
            decision = rules.plan([rec.ob], self._ctx(), self.policy)[rec.ob.id]
            self.audit.record("deferral_reviewed",
                              f"Deferral review due {due.isoformat()}: re-planned #{rec.ob.id} "
                              f"as {decision.action.value} ({decision.rule}).",
                              obligation_id=rec.ob.id, rule=decision.rule)
            self._apply_decision(rec, rules.with_note(decision, f"Deferral review due {due.isoformat()}."))
            if rec.state is State.DEFERRED:
                results.append(ExecutionResult(
                    rec.ob.id, "deferred",
                    f"Still cash-constrained; next review {rec.deferred_until.isoformat()}."))
        return results

    def execute(self) -> list[ExecutionResult]:
        """Execute every conversion the agent is authorised to make right now."""
        self._ensure_running()
        results = self.reschedule_deferred()
        for rec in self.records.values():
            if rec.state is State.FUNDED:
                if rec.transfer is None:
                    results.append(self._pay(rec, ExecutionResult(rec.ob.id, "in_flight", "funding payout")))
            elif rec.state is State.FX_PLANNED:
                results.append(self._convert_and_pay(rec))
            elif rec.state is State.AWAITING_APPROVAL:
                req = self.approvals.get(rec.approval_id) if rec.approval_id else None
                if req and req.status is ApprovalStatus.APPROVED:
                    results.append(self._convert_and_pay(rec))
            elif rec.state is State.CONVERTED and rec.transfer is None:
                results.append(self._pay(rec, ExecutionResult(rec.ob.id, "in_flight", "resuming payout")))
            elif rec.state is State.ESCALATED and rec.approval_id:
                req = self.approvals.get(rec.approval_id)
                if req.status is ApprovalStatus.APPROVED and not req.consumed_ref:
                    why = (f"{req.kind} approved by {req.decided_by}: {fmt(req.amount, req.currency)} to "
                           f"{req.counterparty} is handed to the payments team; this agent does not execute "
                           "policy exceptions itself.")
                    self.approvals.consume(req.id, ref="handoff")
                    self.audit.record("handoff", why, obligation_id=rec.ob.id, approval_id=req.id)
                    results.append(ExecutionResult(rec.ob.id, "handoff", why))
        return results

    def _book_quote(self, fx) -> dict:
        quote = self.client.create_quote(buy_currency=fx.buy_currency, sell_currency=fx.sell_currency,
                                         buy_amount=fx.buy_amount)
        if quote.get("buy_currency") != fx.buy_currency or quote.get("sell_currency") != fx.sell_currency \
                or q2(quote.get("buy_amount", 0)) != fx.buy_amount or not quote.get("quote_id"):
            self._halt("quote does not match the request")
        return quote

    def _escalate(self, rec: ObligationRecord, why: str, rule: str, *, kind: str, release_reserved: bool) -> None:
        if release_reserved:
            self.ledger.release(rec.ob.id, currency=BASE_CURRENCY)
            if rec.state is not State.CONVERTED:
                self.ledger.release(rec.ob.id, currency=rec.ob.currency)
        rec.decision = replace(rules.with_note(rec.decision, why), requires_approval=True)
        self._transition(rec, State.ESCALATED, why, rule)
        if kind == "SCREENING_REVIEW":
            self._request_screening_approval(rec, why)
        else:
            self._request_exception_approval(rec, why)

    def _pre_money_checks(self, rec: ObligationRecord, *, stage: str) -> tuple[ExecutionResult | None, str, str]:
        """Screening and payee-detail checks, run immediately before any money moves."""
        ob = rec.ob
        res = self._screen(ob)
        if res and res.hit:
            why = f"Screening hit at {stage}: '{res.list_entry}' (list {res.list_version}). Nothing paid."
            self._escalate(rec, why, "R0_SCREENING_HIT", kind="SCREENING_REVIEW",
                           release_reserved=rec.state is not State.CONVERTED)
            return ExecutionResult(ob.id, "blocked", why), "", ""
        dest = self._destination(ob)
        if dest is None:
            self._halt(f"no beneficiary details on file for obligation #{ob.id}")
        fp, masked = dest
        pin = self.store.get_payee(payee_key(ob))
        if pin and pin["fingerprint"] != fp:
            why = (f"Payee bank details changed: pinned {pin['masked']}, now {masked}. Verify out of band "
                   f"(call-back) and re-pin with manage.py before paying. Nothing paid.")
            self._escalate(rec, why, "PAYEE_DETAILS_CHANGED", kind="POLICY_EXCEPTION",
                           release_reserved=rec.state is not State.CONVERTED)
            return ExecutionResult(ob.id, "blocked", why), fp, masked
        return None, fp, masked

    def _convert_and_pay(self, rec: ObligationRecord) -> ExecutionResult:
        ob, fx = rec.ob, rec.decision.fx
        self._sync()
        prior = self._prior_payment(rec)
        if prior:  # checked BEFORE converting, so a repeat run cannot even buy the currency
            paid = q2(prior.get("transfer_amount") or 0)
            gap = (f" of {fmt(paid, ob.currency)} against an invoice of {fmt(ob.amount, ob.currency)}"
                   if paid != q2(ob.amount) else "")
            why = (f"Invoice {ob.reference} to {ob.counterparty} was already paid{gap} by transfer "
                   f"{prior.get('id')} ({prior.get('status')}); not paying twice.")
            self.audit.record("duplicate_invoice", why, obligation_id=ob.id, transfer_id=prior.get("id"))
            return ExecutionResult(ob.id, "blocked", why)
        stop, fp, masked = self._pre_money_checks(rec, stage="conversion")
        if stop:
            return stop
        recorded = self.store.live_payout(payee_fingerprint=fp, reference=ob.reference, currency=ob.currency)
        transfer_key = f"transfer:ob{ob.id}"
        if recorded and recorded["request_id"] != self.ops.request_id_of(transfer_key):
            why = (f"Invoice {ob.reference} to {ob.counterparty} already has a live payout recorded in the "
                   f"database (cycle {recorded['cycle_id']}, {recorded['amount']} {recorded['currency']}, "
                   f"status {recorded['status']}); not converting or paying again.")
            self.audit.record("duplicate_invoice", why, obligation_id=ob.id)
            return ExecutionResult(ob.id, "blocked", why)
        # Lock the invoice in the database BEFORE buying currency for it: if this process dies between the
        # conversion and the payout, no other run can convert or pay this invoice again.
        payout_rid = self.ops.request_id(transfer_key)
        try:
            self.store.reserve_payout(request_id=payout_rid, cycle_id=self.cycle_id, obligation_id=ob.id,
                                      payee_fingerprint=fp, reference=ob.reference, currency=ob.currency,
                                      amount=ob.amount)
        except DuplicatePayout as exc:
            why = (f"Invoice {ob.reference} already has a live payout recorded "
                   f"(request {exc.existing.get('request_id')}); not converting or paying again.")
            self.audit.record("duplicate_invoice", why, obligation_id=ob.id)
            return ExecutionResult(ob.id, "blocked", why)

        def release(why: str) -> None:  # nothing moved: free the invoice and retire the unused payout id
            self.store.update_payout(payout_rid, status="cancelled", note=why)
            self.ops.rotate(transfer_key, why)

        key = f"fx_conversion:ob{ob.id}"
        for attempt in range(2):
            quote = self._book_quote(fx)
            sell = q2(quote["sell_amount"])
            self.audit.record("fx_quote", f"Locked single-use quote {quote['quote_id']}: buy "
                              f"{fmt(fx.buy_amount, fx.buy_currency)} for {fmt(sell, fx.sell_currency)} at client "
                              f"rate {quote.get('client_rate')}.", obligation_id=ob.id, quote_id=quote["quote_id"],
                              sell_amount=sell)
            stop = self._authorise(rec, quote, fp)  # re-checked for every quote, including a retry
            if stop:
                release(f"not converted: {stop.status}")
                return stop
            try:
                conv, replayed = self.ops.run(
                    key,
                    create=lambda rid, qid=quote["quote_id"]: self.client.create_conversion(
                        rid, buy_currency=fx.buy_currency, sell_currency=fx.sell_currency,
                        buy_amount=fx.buy_amount, quote_id=qid),
                    lookup=self.client.find_conversion)
                break
            except AmbiguousResultError as exc:
                self.audit.record("error", f"conversion outcome unknown; invoice stays locked: {exc}",
                                  obligation_id=ob.id)
                raise
            except AirwallexError as exc:
                if exc.code in QUOTE_RETRY_CODES and attempt == 0:
                    # The quote was rejected outright, so nothing moved: new operation, fresh quote.
                    self.ops.rotate(key, f"{exc.code} on quote {quote['quote_id']}")
                    continue
                release(f"conversion rejected: {exc.code}")
                self.audit.record("error", str(exc), obligation_id=ob.id)
                raise

        conv = self._await_settlement(conv)
        bought, sold = q2(conv.get("buy_amount", fx.buy_amount)), q2(conv["sell_amount"])
        if bought != fx.buy_amount:
            self._halt(f"conversion bought {bought}, expected {fx.buy_amount}")
        autonomous = rec.state is State.FX_PLANNED
        self._rebind_settled_cost(rec, conv, sold, autonomous=autonomous)
        if not replayed or self.ledger.committed_for(ob.id, BASE_CURRENCY) > 0:
            self.ledger.release(ob.id, currency=BASE_CURRENCY)
            self.ledger.release(ob.id, currency=ob.currency)
            self.ledger.apply_conversion(sell_currency=fx.sell_currency, sell_amount=sold,
                                         buy_currency=fx.buy_currency, buy_amount=bought)
            self.ledger.commit(ob.id, ob.currency, fx.gross_need, "payout_pending")
            if self.headroom() < 0:
                self._halt(f"settled conversion left the book {fmt(-self.headroom(), BASE_CURRENCY)} "
                           "below the reserve floor")
            if autonomous:
                self.autonomous_executed = q2(self.autonomous_executed + sold)
        if rec.approval_id and self.approvals.get(rec.approval_id).status is ApprovalStatus.APPROVED:
            req = self.approvals.consume(rec.approval_id, ref=str(conv.get("conversion_id")))
            if self.store.get_payee(payee_key(ob)) is None and req.destination_fp == fp:
                entry = self.store.pin_payee(
                    payee_key(ob), fp, masked, pinned_by=req.decided_by, approval_id=req.id,
                    audit=self.audit.draft("payee_pinned",
                                           f"{ob.counterparty} pinned to {masked}: destination approved by "
                                           f"{req.decided_by} on {req.id}.",
                                           obligation_id=ob.id, actor=f"approver:{req.decided_by}",
                                           destination=masked))
                self.audit.adopt(entry)
        rec.conversion = conv
        self._transition(rec, State.CONVERTED,
                         f"Converted the minimum over REST: sold {fmt(sold, fx.sell_currency)}, bought "
                         f"{fmt(bought, fx.buy_currency)} (conversion {conv.get('conversion_id')}, "
                         f"status {conv.get('status')}).", "R3_CONVERT_MINIMUM")
        self._sync(wait_seconds=10)
        result = ExecutionResult(ob.id, "in_flight", "converted", quote=quote, conversion=conv, replayed=replayed)
        return self._pay(rec, result)

    def _rebind_settled_cost(self, rec: ObligationRecord, conv: dict, sold: Decimal, *,
                             autonomous: bool) -> None:
        """What a person approved, or what the autonomous tier allowed, was a maximum COST. The quote
        is only an estimate of it, so the settled figure is measured against the ceiling again before
        the book accepts the conversion; a rate that moved against us cannot quietly spend more."""
        fx = rec.decision.fx
        idents = f"conversion {conv.get('conversion_id')}"
        req = self.approvals.get(rec.approval_id) if rec.approval_id else None
        ceiling = req.max_sell_amount if req is not None and req.max_sell_amount is not None else None
        if ceiling is not None and sold > ceiling:
            self._halt(f"{idents} settled at {fmt(sold, fx.sell_currency)}, above the "
                       f"{fmt(ceiling, fx.sell_currency)} ceiling bound into approval {req.id}")
        if autonomous and rules.requires_fx_approval(sold, self.confidence, self.autonomous_executed):
            self._halt(f"{idents} settled at {fmt(sold, fx.sell_currency)}: above the "
                       f"{fmt(rules.autonomous_fx_limit(self.confidence), BASE_CURRENCY)} autonomous limit "
                       "this action was allowed to act under")

    def _authorise(self, rec: ObligationRecord, quote: dict, dest_fp: str) -> ExecutionResult | None:
        """Authority and reserve checks against the actual quote. Returns a stop result or None."""
        ob, fx = rec.ob, rec.decision.fx
        sell = q2(quote["sell_amount"])
        if rec.state is State.FX_PLANNED:
            reasons = []
            if rules.requires_fx_approval(sell, self.confidence, self.autonomous_executed):
                reasons.append(f"R7: quoted cost {fmt(sell, BASE_CURRENCY)} plus "
                               f"{fmt(self.autonomous_executed, BASE_CURRENCY)} already converted autonomously exceeds "
                               f"the limit {fmt(rules.autonomous_fx_limit(self.confidence), BASE_CURRENCY)}")
            if self.store.get_payee(payee_key(ob)) is None:
                reasons.append("R8: the destination account is not pinned for this payee")
            if reasons:
                why = "; ".join(reasons) + ". Quote left unused; a human must approve."
                rec.decision = replace(rules.with_note(rec.decision, why), requires_approval=True)
                self._transition(rec, State.AWAITING_APPROVAL, why, "R7_FX_APPROVAL_GATE")
                self._request_fx_approval(rec)
                return ExecutionResult(ob.id, "gated", why, quote=quote)
        if rec.state is State.AWAITING_APPROVAL:
            try:
                self.approvals.verify(rec.approval_id, obligation_id=ob.id, action="CONVERT",
                                      amount=fx.buy_amount, currency=fx.buy_currency,
                                      counterparty=ob.counterparty, sell_currency=fx.sell_currency,
                                      sell_amount=sell, destination_fp=dest_fp)
            except ApprovalError as exc:
                self.audit.record("blocked", str(exc), obligation_id=ob.id)
                return ExecutionResult(ob.id, "blocked", str(exc), quote=quote)
        others = self.ledger.committed(BASE_CURRENCY, exclude_obligation=ob.id)
        if not rules.reserve_ok(self.ledger.balance(BASE_CURRENCY) - sell, others, self.policy):
            why = f"Selling {fmt(sell, BASE_CURRENCY)} would breach the reserve floor; not executed."
            self.audit.record("blocked", why, obligation_id=ob.id)
            return ExecutionResult(ob.id, "blocked", why, quote=quote)
        return None

    def _await_settlement(self, conv: dict, attempts: int = 5) -> dict:
        for _ in range(attempts):
            if conv.get("status") in SETTLED_CONVERSION:
                return conv
            self._sleep(1.0)
            conv = self.client.get_conversion(conv["conversion_id"])
        self._halt(f"conversion {conv.get('conversion_id')} not settled (status {conv.get('status')})")

    def _find_beneficiary(self, rec: ObligationRecord) -> dict | None:
        """An existing Airwallex beneficiary with this nickname AND the same bank account."""
        spec = self._beneficiary_spec(rec.ob.id)
        if not spec:
            return None
        bank = spec["beneficiary"]["bank_details"]
        for item in self.client.find_beneficiaries(nick_name=spec["nickname"]):
            details = (item.get("beneficiary") or {}).get("bank_details") or {}
            if account_fields(details) == account_fields(bank):
                return item
        return None

    def _prior_payment(self, rec: ObligationRecord) -> dict | None:
        """A live transfer for this invoice (same reference, currency and payee) that this cycle did not
        create — e.g. from an earlier run. Checked before any money moves. The figure is not part of an
        invoice's identity: a transfer that paid it for another amount is still this invoice being paid,
        so it blocks rather than looking like a fresh obligation."""
        ob = rec.ob
        ours = self.ops.request_id_of(f"transfer:ob{ob.id}")
        beneficiary = self._find_beneficiary(rec)
        known_ids = {beneficiary["id"]} if beneficiary else set()
        spec = (self._beneficiary_spec(ob.id) or {}).get("beneficiary", {})
        payee_names = {n.strip().lower() for n in (ob.counterparty, spec.get("company_name"),
                                                   (spec.get("bank_details") or {}).get("account_name")) if n}
        for t in self.client.list_transfers(transfer_currency=ob.currency):
            payee = t.get("beneficiary") or {}
            names = {str(n).strip().lower() for n in (payee.get("company_name"),
                                                      (payee.get("bank_details") or {}).get("account_name")) if n}
            same_payee = t.get("beneficiary_id") in known_ids or bool(names & payee_names)
            if (same_payee and t.get("reference") == ob.reference and t.get("transfer_currency") == ob.currency
                    and t.get("status") not in TRANSFER_FAILED and t.get("request_id") != ours):
                return t
        return None

    def _verified_beneficiary_id(self, rec: ObligationRecord, beneficiary_id: str) -> str:
        spec = self._beneficiary_spec(rec.ob.id)
        candidates = self.client.find_beneficiaries(nick_name=spec["nickname"])
        actual = next((item for item in candidates if item.get("id") == beneficiary_id), None)
        details = ((actual or {}).get("beneficiary") or {}).get("bank_details") or {}
        if actual is None or account_fields(details) != account_fields(spec["beneficiary"]["bank_details"]):
            self._halt(f"beneficiary {beneficiary_id} no longer matches the approved destination")
        return beneficiary_id

    def _ensure_beneficiary(self, rec: ObligationRecord) -> str:
        spec = self._beneficiary_spec(rec.ob.id)
        if not spec:
            self._halt(f"no beneficiary details on file for obligation #{rec.ob.id}")
        key = f"beneficiary:ob{rec.ob.id}"
        stored = self.ops.result(key)
        if stored:
            return self._verified_beneficiary_id(rec, stored["id"])
        bank = spec["beneficiary"]["bank_details"]

        def lookup(_rid=None):
            return self._find_beneficiary(rec)

        existing = lookup()
        if existing:
            self.ops.record_existing(key, {"id": existing["id"]}, "matched by nickname + bank account")
            self.audit.record("beneficiary_reused", f"Reusing beneficiary {existing['id']} ({spec['nickname']}).",
                              obligation_id=rec.ob.id)
            return existing["id"]
        schema = self.client.beneficiary_schema(
            bank_country_code=bank["bank_country_code"], account_currency=bank["account_currency"],
            transfer_method=spec["transfer_methods"][0], entity_type=spec["beneficiary"]["entity_type"])
        problems = check_against_schema(spec, schema)
        if problems:
            self._halt("beneficiary payload fails the Airwallex schema: " + "; ".join(problems))
        self.audit.record("beneficiary_schema", f"Payload checked against the {bank['bank_country_code']} "
                          f"{bank['account_currency']} {spec['transfer_methods'][0]} schema "
                          f"({len(schema.get('fields', []))} fields).", obligation_id=rec.ob.id)
        created, _ = self.ops.run(key, create=lambda _rid: self.client.create_beneficiary(spec), lookup=lookup)
        # Operation results are redacted at rest; validate current bank data, not that copy.
        self._verified_beneficiary_id(rec, created["id"])
        self.audit.record("beneficiary_created", f"Created beneficiary {created['id']} for {rec.ob.counterparty}.",
                          obligation_id=rec.ob.id)
        return created["id"]

    def _pay(self, rec: ObligationRecord, result: ExecutionResult) -> ExecutionResult:
        ob, d = rec.ob, rec.decision
        key = f"transfer:ob{ob.id}"
        if self.ops.result(key) is None:
            prior = self._prior_payment(rec)
            if prior:
                why = (f"Invoice {ob.reference} already paid by transfer {prior.get('id')} "
                       f"({prior.get('status')}); payout not repeated. Converted funds stay ring-fenced.")
                self.audit.record("duplicate_invoice", why, obligation_id=ob.id, transfer_id=prior.get("id"))
                result.status, result.detail = "blocked", why
                return result
            stop, fp, masked = self._pre_money_checks(rec, stage="payout")
            if stop:
                result.status, result.detail = stop.status, stop.detail
                return result
            pin = self.store.get_payee(payee_key(ob))
            if pin is None or pin["fingerprint"] != fp:
                why = "Destination account is not pinned for this payee; payout not sent."
                self._escalate(rec, why, "R8_PAYEE_NOT_PINNED", kind="POLICY_EXCEPTION", release_reserved=False)
                result.status, result.detail = "blocked", why
                return result
        else:
            fp = None
        # The beneficiary first: if Airwallex rejects the payee details, no payout row is reserved.
        beneficiary_id = self._ensure_beneficiary(rec)
        rec.beneficiary_id = beneficiary_id
        rid = self.ops.request_id(key)
        if fp is not None:
            try:  # database-level guard: one live payout per invoice, ever (atomic, survives restarts)
                self.store.reserve_payout(request_id=rid, cycle_id=self.cycle_id, obligation_id=ob.id,
                                          payee_fingerprint=fp, reference=ob.reference, currency=ob.currency,
                                          amount=ob.amount)
            except DuplicatePayout as exc:
                why = (f"Invoice {ob.reference} already has a live payout recorded "
                       f"(request {exc.existing.get('request_id')}); not paying twice.")
                self.audit.record("duplicate_invoice", why, obligation_id=ob.id)
                result.status, result.detail = "blocked", why
                return result
        reason = self.payouts.get(ob.id, {}).get("reason", "goods_purchased")
        try:
            transfer, replayed = self.ops.run(
                key,
                create=lambda rid: self.client.create_transfer(
                    rid, beneficiary_id=beneficiary_id, transfer_currency=ob.currency, transfer_amount=ob.amount,
                    source_currency=ob.currency, transfer_method=ob.payout_method, reason=reason,
                    reference=ob.reference),
                lookup=self.client.find_transfer)
        except AmbiguousResultError:
            raise  # stays 'initiated' in the database, which keeps blocking any second attempt
        except AirwallexError as exc:
            if not exc.is_duplicate_request:
                # Rejected outright, so nothing was paid. The currency is already bought, so the invoice
                # stays locked: the old request id is retired and the reservation moves to a new one.
                new_rid = self.ops.rotate(key, f"transfer rejected: {exc.code}")
                self.store.rekey_payout(rid, new_rid, note=f"transfer rejected: {exc.code}")
                self.audit.record("payout_rejected", str(exc), obligation_id=ob.id, request_id=rid)
            raise
        payer_pays = q2(transfer.get("amount_payer_pays") or (ob.amount + d.fee))
        fee = transfer.get("fee_amount")
        if fee is not None and q2(fee) != d.fee:
            self.audit.record("fee_mismatch", f"Airwallex charged {fmt(fee, ob.currency)}; policy table says "
                              f"{fmt(d.fee, ob.currency)}. Update PolicyConfig.swift_fees.", obligation_id=ob.id)
        if self.ledger.committed_for(ob.id, ob.currency) > 0:
            self.ledger.release(ob.id, currency=ob.currency)
            # Money has already moved; the ledger records it even if a fee exceeded the policy table.
            self.ledger.apply_outflow(ob.currency, payer_pays, allow_negative=True)
        rec.transfer = transfer
        self._update_payout_row(rid, transfer)
        self.audit.record("payout_sent", f"Transfer {transfer.get('id')} for {fmt(ob.amount, ob.currency)} via "
                          f"{ob.payout_method} to {ob.counterparty} (payer pays {fmt(payer_pays, ob.currency)}); "
                          f"status {transfer.get('status')}.", obligation_id=ob.id,
                          transfer_id=transfer.get("id"), request_id=transfer.get("request_id"))
        self._sync(wait_seconds=10)
        result.beneficiary_id = beneficiary_id
        result.transfer = transfer
        result.replayed = result.replayed or replayed
        result.detail = f"transfer {transfer.get('id')} {transfer.get('status')}"
        return self._settle_status(rec, result)

    def _update_payout_row(self, request_id: str, transfer: dict) -> None:
        status = transfer.get("status")
        row_status = "paid" if status in TRANSFER_SUCCESS else "failed" if status in TRANSFER_FAILED else "in_flight"
        self.store.update_payout(request_id, status=row_status, transfer_id=transfer.get("id"))

    def _settle_status(self, rec: ObligationRecord, result: ExecutionResult) -> ExecutionResult:
        status = (rec.transfer or {}).get("status")
        if status in TRANSFER_SUCCESS and rec.state in {State.CONVERTED, State.FUNDED}:
            self._transition(rec, State.PAID, f"Transfer {rec.transfer.get('id')} reached PAID.", "PAYOUT_SETTLED")
            result.status = "paid_out"
        elif status in TRANSFER_FAILED:
            result.status = "blocked"
            result.detail = f"transfer {rec.transfer.get('id')} {status}: {rec.transfer.get('failure_reason')}"
        else:
            result.status = "in_flight"  # SENT / PROCESSING are never final
        return result

    def refresh_payouts(self) -> list[ExecutionResult]:
        out = []
        for rec in self.records.values():
            if rec.state not in {State.CONVERTED, State.FUNDED} or not rec.transfer:
                continue
            latest = self.client.get_transfer(rec.transfer["id"])
            previous = rec.transfer.get("status")
            rec.transfer = latest
            status = latest.get("status")
            if status != previous:
                self.audit.record("payout_status", f"Transfer {latest.get('id')}: {previous} → {status}.",
                                  obligation_id=rec.ob.id)
                self._update_payout_row(latest.get("request_id") or self.ops.request_id_of(f"transfer:ob{rec.ob.id}"),
                                        latest)
            if status in TRANSFER_FAILED and previous not in TRANSFER_FAILED:
                # Funds return to the wallet; keep them ring-fenced and route to a human.
                payer_pays = q2(latest.get("amount_payer_pays") or rec.ob.amount + rec.decision.fee)
                self.ledger.apply_inflow(rec.ob.currency, payer_pays)
                self.ledger.commit(rec.ob.id, rec.ob.currency, payer_pays, "payout_pending")
                why = (f"Transfer {latest.get('id')} ended {status} ({latest.get('failure_type')}: "
                       f"{latest.get('failure_reason')}). {fmt(payer_pays, rec.ob.currency)} returned and "
                       "ring-fenced; a human decides whether to resend.")
                result = self._settle_status(rec, ExecutionResult(rec.ob.id, "blocked", why, transfer=latest))
                self._transition(rec, State.ESCALATED, why, "PAYOUT_FAILED")
                self._request_payout_failure_approval(rec, latest, why)
                out.append(result)
                continue
            out.append(self._settle_status(rec, ExecutionResult(rec.ob.id, "in_flight", f"transfer {status}",
                                                                transfer=latest)))
        return out

    # ------------------------------------------------------------------ reporting
    def reserve_report(self) -> ReserveReport:
        actual = self._read_balances()
        mismatches = self.ledger.reconcile(actual)
        committed = self.ledger.committed(BASE_CURRENCY)
        uncommitted = q2(self.ledger.balance(BASE_CURRENCY) - committed)
        report = ReserveReport(
            book=dict(self.ledger.balances), actual=actual,
            committed_by_kind=self.ledger.commitments_by_kind(BASE_CURRENCY), committed=committed,
            uncommitted=uncommitted, floor=self.policy.reserve_floor,
            headroom=q2(uncommitted - self.policy.reserve_floor),
            intact=uncommitted >= self.policy.reserve_floor and not mismatches, mismatches=mismatches)
        self.audit.record("reserve_confirmed" if report.intact else "reserve_alert",
                          f"{BASE_CURRENCY} {report.uncommitted:,.2f} uncommitted vs floor "
                          f"{report.floor:,.2f}: {'intact' if report.intact else 'AT RISK'}.",
                          uncommitted=report.uncommitted, floor=report.floor, reconciled=not mismatches)
        return report

    def snapshot(self) -> dict:
        return {
            "cycle_id": self.cycle_id,
            "halted": self.halted,
            "confidence": self.confidence,
            "autonomous_executed": self.autonomous_executed,
            "rates": self.rates,
            "ledger": {"opening": self.ledger.opening, "actual_opening": self.ledger.actual_opening,
                       "balances": self.ledger.balances,
                       "commitments": [c.__dict__ for c in self.ledger.commitments()]} if self.ledger else None,
            "obligations": [{
                "id": r.ob.id, "name": r.ob.name, "state": r.state.value,
                "action": r.decision.action.value if r.decision else None,
                "rule": r.decision.rule if r.decision else None,
                "reason": r.decision.reason if r.decision else None,
                "notes": list(r.decision.notes) if r.decision else [],
                "approval_id": r.approval_id, "history": r.history,
                "deferred_until": r.deferred_until.isoformat() if r.deferred_until else None,
                "conversion_id": (r.conversion or {}).get("conversion_id"),
                "transfer_id": (r.transfer or {}).get("id"),
            } for r in self.records.values()],
            "approvals": [a.to_json() for a in self.approvals.requests.values()],
        }
