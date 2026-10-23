"""Receipt forecast confidence from bank history, invoice data and customer email.

Confidence is computed in code from evidence:
  * bank history  - share of this customer's past receipts paid within tolerance
  * invoice data  - status of the invoice the receipt depends on
When both sources independently support the receipt (each >= AGREEMENT), the
forecast takes their average (capped). If they disagree, the weaker one wins.

A customer email can only lower confidence. The mapping from confidence to the
autonomous conversion limit lives in ``policy.py``.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import Decimal

from email_reader import EmailSignal
from models import q2

ON_TIME_TOLERANCE_DAYS = 3
AGREEMENT = Decimal("0.80")
MAX_CONFIDENCE = Decimal("0.95")
UNCLEAR_CAP = Decimal("0.60")
INVOICE_STATUS_SCORE = {
    "acknowledged": Decimal("1.00"),   # customer confirmed receipt of invoice / PO matched
    "sent": Decimal("0.70"),
    "overdue": Decimal("0.40"),
    "disputed": Decimal("0.20"),
}
# Multipliers applied when an email contradicts the forecast.
DELAY_BEYOND_WINDOW = Decimal("0.40")
DELAY_WITHIN_WINDOW = Decimal("0.80")
DELAY_UNKNOWN = Decimal("0.50")
DISPUTE = Decimal("0.30")


@dataclass(frozen=True)
class PastReceipt:
    invoice_id: str
    due: date
    paid: date
    amount: Decimal

    @property
    def days_late(self) -> int:
        return (self.paid - self.due).days


@dataclass(frozen=True)
class ExpectedReceipt:
    customer: str
    invoice_id: str
    amount: Decimal
    currency: str
    due_in_hours: int
    invoice_status: str
    history: tuple[PastReceipt, ...]

    def context(self) -> dict:
        return {"customer": self.customer, "invoice_id": self.invoice_id, "amount": f"{self.amount:,.2f}",
                "currency": self.currency, "due_in_hours": self.due_in_hours}


@dataclass(frozen=True)
class Assessment:
    confidence: Decimal
    bank_score: Decimal
    invoice_score: Decimal
    agree: bool
    lines: tuple[str, ...]


@dataclass(frozen=True)
class EmailImpact:
    before: Decimal
    after: Decimal
    factor: Decimal | None
    cap: Decimal | None
    explanation: str


def bank_score(history: tuple[PastReceipt, ...]) -> Decimal:
    if not history:
        return Decimal("0.50")
    on_time = sum(1 for r in history if r.days_late <= ON_TIME_TOLERANCE_DAYS)
    return Decimal(on_time) / Decimal(len(history))


def invoice_score(status: str) -> Decimal:
    return INVOICE_STATUS_SCORE.get(status, Decimal("0.50"))


def assess(receipt: ExpectedReceipt) -> Assessment:
    bank = bank_score(receipt.history)
    inv = invoice_score(receipt.invoice_status)
    agree = bank >= AGREEMENT and inv >= AGREEMENT
    conf = min(MAX_CONFIDENCE, (bank + inv) / 2) if agree else min(bank, inv)
    on_time = sum(1 for r in receipt.history if r.days_late <= ON_TIME_TOLERANCE_DAYS)
    lines = (
        f"Bank history: {on_time}/{len(receipt.history)} past {receipt.customer} receipts landed within "
        f"{ON_TIME_TOLERANCE_DAYS} days of due (score {q2(bank)}).",
        f"Invoice {receipt.invoice_id}: status '{receipt.invoice_status}' (score {q2(inv)}).",
        ("Both sources agree the receipt is coming." if agree
         else "Sources disagree; the weaker signal sets confidence."),
    )
    return Assessment(q2(conf), q2(bank), q2(inv), agree, lines)


def apply_email(confidence: Decimal, signal: EmailSignal, receipt: ExpectedReceipt,
                planning_window_hours: int) -> EmailImpact:
    before = q2(confidence)
    if signal.stance in {"confirm", "unrelated"}:
        why = ("Email supports the forecast; confidence is not raised by an email."
               if signal.stance == "confirm" else "Email is not about this receipt; no change.")
        return EmailImpact(before, before, None, None, why)
    if signal.stance == "unclear":
        after = min(before, UNCLEAR_CAP)
        return EmailImpact(before, after, None, UNCLEAR_CAP,
                           f"Email could not be read with certainty; confidence capped at {UNCLEAR_CAP}.")
    if signal.stance == "dispute":
        return EmailImpact(before, q2(before * DISPUTE), DISPUTE, None,
                           f"Customer disputes the invoice; confidence x{DISPUTE}.")
    # delay
    if signal.expected_delay_days is None:
        factor, why = DELAY_UNKNOWN, "Customer reports a delay of unstated length"
    elif receipt.due_in_hours + signal.expected_delay_days * 24 > planning_window_hours:
        factor = DELAY_BEYOND_WINDOW
        why = (f"Customer reports a {signal.expected_delay_days}-day delay, pushing the receipt past the "
               f"{planning_window_hours}h planning window")
    else:
        factor = DELAY_WITHIN_WINDOW
        why = f"Customer reports a {signal.expected_delay_days}-day delay inside the planning window"
    return EmailImpact(before, q2(before * factor), factor, None, f"{why}; confidence x{factor}.")
