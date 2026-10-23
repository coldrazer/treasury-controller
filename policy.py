"""Decision rules: fund / convert / defer / escalate.

Pure functions only: no I/O, no clock, no model calls. Every amount, limit and
threshold the agent acts on is decided here. Confidence thresholds live HERE,
never in a prompt.

Rules, in the order they are applied by ``plan``:

  R5  ESCALATE  any single payout whose USD-equivalent exceeds the policy
                threshold goes to a human, whatever the cash position. Its
                funding is assessed last (it is blocked anyway) and cash is held
                for it only if that fits above the floor.
  R4  DEFER     if planned demand exceeds headroom above the reserve floor,
                defer deferrable obligations, cheapest deferral first, until
                the plan fits.
  R1  FUND      operations-critical obligations, funded first.
  R2  FUND      fixed / remaining base-currency obligations that fit.
  R3  CONVERT   foreign-currency obligations: buy only gross need (amount + payout
                fee) minus balance already held in that currency.
  R7  gate      a conversion whose USD cost exceeds the autonomous limit for the
                current forecast confidence requires a bound human approval.
  R6  ESCALATE  a non-deferrable obligation that cannot fit above the floor.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from decimal import Decimal
from typing import Iterable, Mapping, Sequence

from config import BASE_CURRENCY, PolicyConfig
from models import (ZERO, Action, Decision, FxNeed, Obligation, ceil2, fmt, q2,
                    to_decimal)

# Autonomous conversion limit (USD) by forecast confidence. First match wins.
CONFIDENCE_TIERS: tuple[tuple[Decimal, Decimal], ...] = (
    (Decimal("0.80"), Decimal("15000.00")),  # bank + invoice data agree
    (Decimal("0.50"), Decimal("5000.00")),   # mixed evidence
    (Decimal("0.00"), Decimal("2500.00")),   # forecast contradicted
)

PRIORITY = {
    "operations_critical": 0,
    "fixed": 1,
    "time_sensitive": 2,
    "contractual": 3,
    "deferrable": 4,
}


class PolicyError(RuntimeError):
    pass


class UnknownFeeError(PolicyError):
    pass


class MissingRateError(PolicyError):
    pass


# ---------------------------------------------------------------------------
# Building blocks
# ---------------------------------------------------------------------------
def autonomous_fx_limit(confidence) -> Decimal:
    c = to_decimal(confidence)
    if not Decimal(0) <= c <= Decimal(1):
        raise PolicyError(f"confidence must be within [0, 1], got {c}")
    for floor, limit in CONFIDENCE_TIERS:
        if c >= floor:
            return limit
    return ZERO  # unreachable while the last tier starts at 0


def requires_fx_approval(sell_amount_usd, confidence, already_autonomous=ZERO) -> bool:
    """The limit caps the CUMULATIVE autonomous conversion in a cycle, so splitting one
    conversion into several smaller ones cannot get around it."""
    return q2(already_autonomous) + q2(sell_amount_usd) > autonomous_fx_limit(confidence)


def policy_fingerprint(policy: PolicyConfig) -> str:
    """SHA-256 of every number that drives decisions; recorded on each cycle for change control."""
    import forecast
    material = {
        "policy": {k: (dict(v) if hasattr(v, "items") else v) for k, v in vars(policy).items()},
        "confidence_tiers": CONFIDENCE_TIERS,
        "priority": PRIORITY,
        "forecast": {k: getattr(forecast, k) for k in (
            "ON_TIME_TOLERANCE_DAYS", "AGREEMENT", "MAX_CONFIDENCE", "UNCLEAR_CAP", "INVOICE_STATUS_SCORE",
            "DELAY_BEYOND_WINDOW", "DELAY_WITHIN_WINDOW", "DELAY_UNKNOWN", "DISPUTE")},
    }
    text = json.dumps(material, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def payout_fee(ob: Obligation, policy: PolicyConfig) -> Decimal:
    if ob.payout_method == "LOCAL":
        return q2(policy.local_fee)
    fee = policy.swift_fees.get(ob.currency)
    if fee is None:
        raise UnknownFeeError(
            f"no SWIFT fee configured for {ob.currency}; cannot size obligation {ob.id} safely"
        )
    return q2(fee)


def gross_need(ob: Obligation, policy: PolicyConfig) -> Decimal:
    return q2(ob.amount + payout_fee(ob, policy))


def usd_equivalent(amount, currency: str, usd_per_unit: Mapping[str, Decimal]) -> Decimal:
    if currency == BASE_CURRENCY:
        return q2(amount)
    rate = usd_per_unit.get(currency)
    if rate is None or rate <= 0:
        raise MissingRateError(f"no usable {currency}->{BASE_CURRENCY} rate")
    return q2(to_decimal(amount) * rate)


def fx_requirement(ob: Obligation, held, usd_per_unit, policy: PolicyConfig) -> FxNeed:
    """Minimum conversion: gross need minus what is already held, nothing more."""
    if ob.currency == BASE_CURRENCY:
        raise PolicyError("base-currency obligations need no conversion")
    rate = to_decimal(usd_per_unit)
    if rate <= 0:
        raise MissingRateError(f"bad rate for {ob.currency}: {rate}")
    gross = gross_need(ob, policy)
    use_held = min(max(q2(held), ZERO), gross)
    buy = q2(gross - use_held)
    est_sell = ceil2(buy * rate) if buy > 0 else ZERO
    return FxNeed(
        buy_currency=ob.currency,
        buy_amount=buy,
        sell_currency=BASE_CURRENCY,
        est_sell_amount=est_sell,
        usd_per_unit=rate,
        gross_need=gross,
        fee=payout_fee(ob, policy),
        held_used=use_held,
    )


def breaches_single_payment_threshold(usd_equiv, policy: PolicyConfig) -> bool:
    return q2(usd_equiv) > policy.single_payment_approval_threshold


def select_deferrals(candidates: Sequence[tuple[Obligation, Decimal]], shortfall) -> list[int]:
    """Cheapest deferral first (penalty, then size), until the shortfall closes."""
    remaining = to_decimal(shortfall)
    chosen: list[int] = []
    for ob, draw in sorted(candidates, key=lambda c: (c[0].deferral_penalty_usd, c[1], c[0].id)):
        if remaining <= 0:
            break
        chosen.append(ob.id)
        remaining -= draw
    return chosen


def reserve_ok(base_balance_after, other_base_commitments, policy: PolicyConfig) -> bool:
    """Floor check: balance after the outflow, net of every other commitment."""
    return q2(base_balance_after) - q2(other_base_commitments) >= policy.reserve_floor


def approval_sell_ceiling(est_sell, policy: PolicyConfig) -> Decimal:
    return ceil2(to_decimal(est_sell) * (Decimal(1) + policy.fx_slippage_tolerance))


def priority_key(ob: Obligation) -> tuple:
    return (PRIORITY.get(ob.category, 9), ob.due_in_hours, ob.id)


# ---------------------------------------------------------------------------
# The planner
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PlanContext:
    headroom: Decimal                   # base cash above the floor, net of other commitments
    held: Mapping[str, Decimal]         # free foreign balances
    usd_per_unit: Mapping[str, Decimal]
    confidence: Decimal
    autonomous_used: Decimal = ZERO     # autonomous conversion already planned or executed this cycle


def plan(obligations: Iterable[Obligation], ctx: PlanContext, policy: PolicyConfig) -> dict[int, Decision]:
    """Decide every obligation given. Applied to the full book at triage and to the
    affected subset on a recalculation event (same rules, current headroom)."""
    obs = sorted(obligations, key=priority_key)
    remaining = q2(ctx.headroom)
    held = {k: q2(v) for k, v in ctx.held.items()}
    limit = autonomous_fx_limit(ctx.confidence)
    autonomous_used = q2(ctx.autonomous_used)
    out: dict[int, Decision] = {}

    gross = {ob.id: gross_need(ob, policy) for ob in obs}
    fees = {ob.id: payout_fee(ob, policy) for ob in obs}
    usd_eq = {ob.id: usd_equivalent(gross[ob.id], ob.currency, ctx.usd_per_unit) for ob in obs}

    over_threshold = [ob for ob in obs if breaches_single_payment_threshold(usd_eq[ob.id], policy)]
    eligible = [ob for ob in obs if ob not in over_threshold]

    # -- R4: estimate demand in priority order and pick deferrals if short --------
    demand = ZERO
    sim_held = dict(held)
    draws: dict[int, Decimal] = {}
    for ob in eligible:
        if ob.currency == BASE_CURRENCY:
            draws[ob.id] = gross[ob.id]
        else:
            need = fx_requirement(ob, sim_held.get(ob.currency, ZERO), ctx.usd_per_unit[ob.currency], policy)
            sim_held[ob.currency] = sim_held.get(ob.currency, ZERO) - need.held_used
            draws[ob.id] = need.est_sell_amount
        demand += draws[ob.id]
    shortfall = q2(demand - remaining)
    deferred = set()
    if shortfall > 0:
        deferred = set(select_deferrals([(ob, draws[ob.id]) for ob in eligible if ob.deferrable], shortfall))

    # -- R1/R2/R3/R6: allocate in priority order -----------------------------------
    for ob in eligible:
        base = dict(gross_amount=gross[ob.id], fee=fees[ob.id], usd_equivalent=usd_eq[ob.id])
        if ob.id in deferred:
            out[ob.id] = Decision(
                ob.id, Action.DEFER, "R4_DEFER_CHEAPEST",
                f"Plan is {fmt(shortfall, BASE_CURRENCY)} short above the reserve floor. Deferral "
                f"penalty is {fmt(ob.deferral_penalty_usd, BASE_CURRENCY)}, the cheapest obligation to "
                f"defer; pushed {policy.deferral_horizon_days} days to next week.",
                cash_constrained=True, funding_gap=draws[ob.id], **base)
            continue

        if ob.currency == BASE_CURRENCY:
            draw = gross[ob.id]
            if draw <= remaining:
                remaining -= draw
                if ob.category == "operations_critical":
                    rule, why = "R1_FUND_OPERATIONS_CRITICAL", "Non-payment stops operations; funded first"
                elif ob.category == "fixed":
                    rule, why = "R2_FUND_FIXED", "Fixed and non-negotiable; funded"
                else:
                    rule, why = "R2_FUND", "Fits within headroom after higher-priority items; funded"
                out[ob.id] = Decision(
                    ob.id, Action.FUND, rule,
                    f"{why} from {BASE_CURRENCY} above the floor. Headroom left "
                    f"{fmt(remaining, BASE_CURRENCY)}.",
                    usd_draw=draw, **base)
                continue
            out[ob.id] = _shortfall_outcome(ob, draw, remaining, base)
            continue

        need = fx_requirement(ob, held.get(ob.currency, ZERO), ctx.usd_per_unit[ob.currency], policy)
        if need.buy_amount == 0:
            held[ob.currency] -= need.held_used
            out[ob.id] = Decision(
                ob.id, Action.FUND, "R2_FUND_FROM_HELD",
                f"Already holds {fmt(need.gross_need, ob.currency)} needed; no conversion required.",
                held_draw=need.held_used, fx=need, **base)
            continue
        if need.est_sell_amount <= remaining:
            remaining -= need.est_sell_amount
            held[ob.currency] = held.get(ob.currency, ZERO) - need.held_used
            gated = requires_fx_approval(need.est_sell_amount, ctx.confidence, autonomous_used)
            if not gated:
                autonomous_used += need.est_sell_amount
            fee_txt = f" + {fmt(need.fee, ob.currency)} {ob.payout_method} fee" if need.fee else ""
            held_txt = f" − {fmt(need.held_used, ob.currency)} already held" if need.held_used else ""
            reason = (
                f"Time-sensitive {ob.currency} payment. Converts the minimum: "
                f"{fmt(ob.amount, ob.currency)}{fee_txt}{held_txt} = buy {fmt(need.buy_amount, ob.currency)} "
                f"(≈ {fmt(need.est_sell_amount, BASE_CURRENCY)}). "
            )
            if gated:
                reason += (f"R7: with {fmt(autonomous_used, BASE_CURRENCY)} already converted autonomously this "
                           f"cycle, exceeds the autonomous limit {fmt(limit, BASE_CURRENCY)} at forecast "
                           f"confidence {q2(ctx.confidence)}; needs human approval.")
            else:
                reason += (f"Within autonomous limit {fmt(limit, BASE_CURRENCY)} at forecast "
                           f"confidence {q2(ctx.confidence)}.")
            out[ob.id] = Decision(
                ob.id, Action.CONVERT, "R3_CONVERT_MINIMUM", reason,
                usd_draw=need.est_sell_amount, held_draw=need.held_used, fx=need,
                requires_approval=gated, **base)
            continue
        out[ob.id] = _shortfall_outcome(ob, need.est_sell_amount, remaining, base, fx=need)

    # -- R5: threshold escalations, funding assessed last --------------------------
    for ob in over_threshold:
        base = dict(gross_amount=gross[ob.id], fee=fees[ob.id], usd_equivalent=usd_eq[ob.id])
        fx = None
        if ob.currency == BASE_CURRENCY:
            draw, held_use = gross[ob.id], ZERO
        else:
            fx = fx_requirement(ob, held.get(ob.currency, ZERO), ctx.usd_per_unit[ob.currency], policy)
            draw, held_use = fx.est_sell_amount, fx.held_used
        head = (f"{fmt(usd_eq[ob.id], BASE_CURRENCY)} equivalent exceeds the "
                f"{fmt(policy.single_payment_approval_threshold, BASE_CURRENCY)} single-payment "
                f"threshold; routed to a human. The agent will not split it to fit under the limit.")
        if draw <= remaining:
            remaining -= draw
            if held_use:
                held[ob.currency] -= held_use
            out[ob.id] = Decision(
                ob.id, Action.ESCALATE, "R5_ESCALATE_THRESHOLD",
                f"{head} Funding: fully coverable; {fmt(draw, BASE_CURRENCY)} held pending approval.",
                usd_draw=draw, held_draw=held_use, fx=fx, requires_approval=True, **base)
        else:
            gap = q2(draw - max(remaining, ZERO))
            out[ob.id] = Decision(
                ob.id, Action.ESCALATE, "R5_ESCALATE_THRESHOLD",
                f"{head} Funding: not coverable above the floor (gap {fmt(gap, BASE_CURRENCY)}).",
                fx=fx, requires_approval=True, cash_constrained=True, funding_gap=gap, **base)
    return out


def _shortfall_outcome(ob: Obligation, draw: Decimal, remaining: Decimal, base: dict,
                       fx: FxNeed | None = None) -> Decision:
    gap = q2(draw - max(remaining, ZERO))
    if ob.deferrable:
        return Decision(ob.id, Action.DEFER, "R4_DEFER_SHORTFALL",
                        f"Does not fit above the reserve floor (gap {fmt(gap, BASE_CURRENCY)}); "
                        f"deferrable with penalty {fmt(ob.deferral_penalty_usd, BASE_CURRENCY)}.",
                        fx=fx, cash_constrained=True, funding_gap=gap, **base)
    return Decision(ob.id, Action.ESCALATE, "R6_ESCALATE_SHORTFALL",
                    f"Cannot be funded above the reserve floor (gap {fmt(gap, BASE_CURRENCY)}) and "
                    f"is not deferrable; routed to a human.",
                    fx=fx, requires_approval=True, cash_constrained=True, funding_gap=gap, **base)


def with_note(decision: Decision, note: str) -> Decision:
    return replace(decision, notes=decision.notes + (note,))
