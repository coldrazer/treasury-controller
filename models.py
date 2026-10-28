"""Shared types: money helpers, obligations, decisions and the state machine."""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from decimal import ROUND_CEILING, ROUND_HALF_UP, Decimal, InvalidOperation
from enum import Enum

CENT = Decimal("0.01")
ZERO = Decimal("0.00")


# ---------------------------------------------------------------------------
# Money helpers. Amounts are major units (100 = one hundred dollars), always
# Decimal, never float.
# ---------------------------------------------------------------------------
def to_decimal(value) -> Decimal:
    if isinstance(value, bool):
        raise TypeError("bool is not an amount")
    if isinstance(value, Decimal):
        d = value
    elif isinstance(value, int):
        d = Decimal(value)
    elif isinstance(value, str):
        try:
            d = Decimal(value.strip().replace(",", ""))
        except InvalidOperation as exc:
            raise ValueError(f"not a number: {value!r}") from exc
    elif isinstance(value, float):
        d = Decimal(repr(value))
    else:
        raise TypeError(f"cannot convert {type(value).__name__} to Decimal")
    if not d.is_finite():
        raise ValueError(f"non-finite amount: {value!r}")
    return d


def q2(value) -> Decimal:
    """Round half-up to cents."""
    return to_decimal(value).quantize(CENT, rounding=ROUND_HALF_UP)


def ceil2(value) -> Decimal:
    """Round up to cents (never under-estimate a cost)."""
    return to_decimal(value).quantize(CENT, rounding=ROUND_CEILING)


def api_amount(value) -> str:
    """Major-unit string for request bodies, e.g. Decimal('12000') -> '12000.00'."""
    return format(q2(value), "f")


def clean_text(text, *, single_line: bool = False) -> str:
    """Strip control and invisible format characters (terminal escapes, bidi overrides)
    from untrusted text before it is parsed, stored or printed."""
    out = []
    for ch in str(text):
        if ch in "\n\t" and not single_line:
            out.append(ch)
        elif unicodedata.category(ch) in {"Cc", "Cf"}:
            out.append(" " if ch in "\n\t\r" else "")
        else:
            out.append(ch)
    cleaned = "".join(out)
    return re.sub(r"\s+", " ", cleaned).strip() if single_line else cleaned


def fmt(amount, currency: str | None = None) -> str:
    text = f"{q2(amount):,.2f}"
    return f"{currency} {text}" if currency else text


# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------
class State(str, Enum):
    PENDING = "pending"
    FUNDED = "funded"                       # cash ring-fenced in base currency
    FX_PLANNED = "fx_planned"               # minimum conversion planned, within autonomy
    AWAITING_APPROVAL = "awaiting_approval"  # planned action gated on a bound human approval
    CONVERTED = "converted"                 # FX booked, payout pending
    PAID = "paid"                           # payout reached a terminal success state
    DEFERRED = "deferred"
    ESCALATED = "escalated"                 # policy exception routed to a human

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.value


ALLOWED_TRANSITIONS: dict[State, frozenset[State]] = {
    State.PENDING: frozenset({State.FUNDED, State.FX_PLANNED, State.AWAITING_APPROVAL,
                              State.DEFERRED, State.ESCALATED}),
    # Self-transitions record a re-evaluation (new reason / refreshed approval evidence).
    State.DEFERRED: frozenset({State.DEFERRED, State.FUNDED, State.FX_PLANNED, State.AWAITING_APPROVAL,
                               State.ESCALATED}),
    State.ESCALATED: frozenset({State.ESCALATED, State.FUNDED, State.FX_PLANNED,
                                State.AWAITING_APPROVAL, State.DEFERRED}),
    State.FX_PLANNED: frozenset({State.AWAITING_APPROVAL, State.CONVERTED, State.DEFERRED,
                                 State.ESCALATED}),
    State.AWAITING_APPROVAL: frozenset({State.CONVERTED, State.ESCALATED, State.PAID}),
    # FUNDED -> AWAITING_APPROVAL is the payout-cap gate: a funded bill above the
    # autonomous cap waits on a human card instead of paying, then settles to PAID.
    State.FUNDED: frozenset({State.PAID, State.ESCALATED, State.AWAITING_APPROVAL}),
    State.CONVERTED: frozenset({State.PAID, State.ESCALATED}),  # failed payout goes to a human
    State.PAID: frozenset(),
}


class InvalidTransition(RuntimeError):
    pass


def check_transition(current: State, new: State) -> None:
    if new not in ALLOWED_TRANSITIONS[current]:
        raise InvalidTransition(f"{current.value} -> {new.value} is not allowed")


# ---------------------------------------------------------------------------
# Domain records
# ---------------------------------------------------------------------------
class Action(str, Enum):
    FUND = "FUND"
    CONVERT = "CONVERT"
    DEFER = "DEFER"
    ESCALATE = "ESCALATE"


@dataclass(frozen=True)
class Obligation:
    id: int
    name: str
    counterparty: str
    amount: Decimal
    currency: str
    due_in_hours: int
    category: str            # operations_critical | fixed | time_sensitive | contractual | deferrable
    deferrable: bool
    deferral_penalty_usd: Decimal
    payout_method: str       # LOCAL | SWIFT
    payout_country: str
    reference: str

    def __post_init__(self):
        if self.amount <= 0:
            raise ValueError(f"obligation {self.id}: amount must be positive")
        if self.payout_method not in {"LOCAL", "SWIFT"}:
            raise ValueError(f"obligation {self.id}: payout_method must be LOCAL or SWIFT")
        if len(self.currency) != 3 or not self.currency.isupper():
            raise ValueError(f"obligation {self.id}: bad currency {self.currency!r}")


@dataclass(frozen=True)
class FxNeed:
    buy_currency: str
    buy_amount: Decimal        # minimum to buy: gross need minus balance already held
    sell_currency: str
    est_sell_amount: Decimal   # indicative, rounded up
    usd_per_unit: Decimal
    gross_need: Decimal        # obligation amount + payout fee, in buy currency
    fee: Decimal
    held_used: Decimal         # existing buy-currency balance applied first


@dataclass(frozen=True)
class Decision:
    obligation_id: int
    action: Action
    rule: str
    reason: str
    gross_amount: Decimal      # amount + payout fee, obligation currency
    fee: Decimal
    usd_equivalent: Decimal    # of the gross amount
    usd_draw: Decimal = ZERO   # base-currency cash committed by this decision
    held_draw: Decimal = ZERO  # obligation-currency cash committed by this decision
    fx: FxNeed | None = None
    requires_approval: bool = False
    cash_constrained: bool = False  # outcome would change if more cash arrived
    funding_gap: Decimal = ZERO
    notes: tuple[str, ...] = field(default_factory=tuple)
