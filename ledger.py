"""Treasury ledger: book balances, commitments, and reconciliation.

The ledger is the agent's own record of cash. It starts from the balances read
from Airwallex (optionally capped to the scenario's operating cash, because the
sandbox pre-credits wallets in every currency) and then only moves on executed
operations and confirmed inflows. After every read the ledger's *changes* are
reconciled against Airwallex's *changes*; any mismatch halts execution.

Commitments ring-fence cash for a decision (funded, FX-reserved, held pending
approval) so it can never be spent twice.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from decimal import Decimal
from typing import Mapping

from models import ZERO, q2

TOLERANCE = Decimal("0.01")


@dataclass(frozen=True)
class Commitment:
    obligation_id: int
    currency: str
    amount: Decimal
    kind: str  # funded | fx_reserved | fx_held | held_pending_approval | payout_pending


@dataclass(frozen=True)
class Mismatch:
    currency: str
    book_delta: Decimal
    actual_delta: Decimal

    def __str__(self) -> str:
        return (f"{self.currency}: ledger moved {self.book_delta:+,.2f} but Airwallex moved "
                f"{self.actual_delta:+,.2f}")


class LedgerError(RuntimeError):
    pass


class Ledger:
    def __init__(self, actual_opening: Mapping[str, Decimal], cap: Mapping[str, Decimal] | None = None):
        self.actual_opening = {c: q2(v) for c, v in actual_opening.items()}
        self.opening: dict[str, Decimal] = {}
        for cur, actual in self.actual_opening.items():
            limit = None if cap is None else cap.get(cur)
            self.opening[cur] = actual if limit is None else min(actual, q2(limit))
        if cap:
            for cur in cap:
                self.opening.setdefault(cur, ZERO)
                self.actual_opening.setdefault(cur, ZERO)
        self.balances: dict[str, Decimal] = dict(self.opening)
        self._commitments: list[Commitment] = []
        self.capped = bool(cap) and any(self.opening[c] < self.actual_opening[c] for c in self.opening)

    # ----------------------------------------------------------------- queries
    def balance(self, currency: str) -> Decimal:
        return self.balances.get(currency, ZERO)

    def committed(self, currency: str, *, exclude_obligation: int | None = None) -> Decimal:
        return q2(sum((c.amount for c in self._commitments
                       if c.currency == currency and c.obligation_id != exclude_obligation), ZERO))

    def committed_for(self, obligation_id: int, currency: str | None = None) -> Decimal:
        return q2(sum((c.amount for c in self._commitments
                       if c.obligation_id == obligation_id and (currency is None or c.currency == currency)),
                      ZERO))

    def commitments(self) -> list[Commitment]:
        return list(self._commitments)

    def commitments_by_kind(self, currency: str) -> dict[str, Decimal]:
        out: dict[str, Decimal] = defaultdict(lambda: ZERO)
        for c in self._commitments:
            if c.currency == currency:
                out[c.kind] += c.amount
        return dict(out)

    def free(self, currency: str) -> Decimal:
        return q2(self.balance(currency) - self.committed(currency))

    def currencies(self) -> list[str]:
        return sorted(set(self.balances) | set(self.actual_opening))

    # ----------------------------------------------------------------- commitments
    def commit(self, obligation_id: int, currency: str, amount, kind: str) -> None:
        amount = q2(amount)
        if amount <= 0:
            return
        if amount > self.free(currency):
            raise LedgerError(f"cannot commit {currency} {amount:,.2f} for #{obligation_id}: "
                              f"only {self.free(currency):,.2f} free")
        self._commitments.append(Commitment(obligation_id, currency, amount, kind))

    def release(self, obligation_id: int, *, currency: str | None = None, kind: str | None = None) -> Decimal:
        released = ZERO
        keep = []
        for c in self._commitments:
            if c.obligation_id == obligation_id and (currency is None or c.currency == currency) \
                    and (kind is None or c.kind == kind):
                released += c.amount
            else:
                keep.append(c)
        self._commitments = keep
        return q2(released)

    # ----------------------------------------------------------------- movements
    def apply_inflow(self, currency: str, amount) -> None:
        self.balances[currency] = q2(self.balance(currency) + q2(amount))

    def apply_outflow(self, currency: str, amount, *, allow_negative: bool = False) -> None:
        amount = q2(amount)
        if amount > self.balance(currency) and not allow_negative:
            raise LedgerError(f"outflow {currency} {amount:,.2f} exceeds book balance")
        self.balances[currency] = q2(self.balance(currency) - amount)

    def apply_conversion(self, *, sell_currency: str, sell_amount, buy_currency: str, buy_amount) -> None:
        self.apply_outflow(sell_currency, sell_amount)
        self.apply_inflow(buy_currency, buy_amount)

    # ----------------------------------------------------------------- reconciliation
    def reconcile(self, actual: Mapping[str, Decimal]) -> list[Mismatch]:
        out = []
        for cur in sorted(set(self.currencies()) | set(actual)):
            book_delta = q2(self.balance(cur) - self.opening.get(cur, ZERO))
            actual_delta = q2(actual.get(cur, ZERO) - self.actual_opening.get(cur, ZERO))
            if abs(book_delta - actual_delta) > TOLERANCE:
                out.append(Mismatch(cur, book_delta, actual_delta))
        return out

    def unexplained_inflow(self, currency: str, actual: Mapping[str, Decimal]) -> Decimal:
        book_delta = self.balance(currency) - self.opening.get(currency, ZERO)
        actual_delta = actual.get(currency, ZERO) - self.actual_opening.get(currency, ZERO)
        return q2(actual_delta - book_delta)
