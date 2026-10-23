"""Sandbox-only calls behind one interface, plus the scenario fixtures.

Every ``POST /simulation/*`` call lives in ``SandboxSimulator``. The decision
logic in ``agent.py`` never imports this module: the demo drives the simulator
and then hands the agent an ordinary balance event, exactly as a production
bank webhook would. Swapping the simulator for real inflows touches no logic.
"""
from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from pathlib import Path
from typing import Protocol

from airwallex_client import AirwallexClient, AirwallexError
from forecast import ExpectedReceipt, PastReceipt
from models import Obligation, clean_text, to_decimal

FIXTURES = Path(__file__).resolve().parent / "fixtures"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DepositFixture:
    amount: Decimal
    currency: str
    payer_name: str
    reference: str


@dataclass(frozen=True)
class Scenario:
    company: str
    operating_cash: dict[str, Decimal]
    obligations: tuple[Obligation, ...]
    expected_receipt: ExpectedReceipt
    customer_email: str
    deposit: DepositFixture
    payouts: dict[int, dict]
    mock_rates: dict[str, Decimal]

    def obligation(self, ob_id: int) -> Obligation:
        return next(o for o in self.obligations if o.id == ob_id)


class ScenarioError(ValueError):
    """The scenario file fails validation; nothing is planned from unvalidated input."""


CURRENCY = re.compile(r"[A-Z]{3}")
COUNTRY = re.compile(r"[A-Z]{2}")
REFERENCE = re.compile(r"[A-Za-z0-9 ./-]{1,35}")       # characters every payout rail accepts
MAX_AMOUNT = Decimal("10000000")


def _check_amount(value: Decimal, what: str) -> None:
    if not value.is_finite() or value <= 0 or value > MAX_AMOUNT or value != value.quantize(Decimal("0.01")):
        raise ScenarioError(f"{what}: amount {value} must be positive, at most {MAX_AMOUNT}, with 2 decimals")


def _check_text(value: str, what: str, max_len: int = 140) -> None:
    if not isinstance(value, str) or not 0 < len(value) <= max_len or clean_text(value, single_line=True) != value:
        raise ScenarioError(f"{what} must be 1-{max_len} printable characters")


def validate_scenario(sc: "Scenario") -> None:
    from policy import PRIORITY  # local import keeps the fixture loader light
    for ob in sc.obligations:
        where = f"obligation {ob.id}"
        _check_amount(ob.amount, where)
        _check_text(ob.name, f"{where} name")
        _check_text(ob.counterparty, f"{where} counterparty")
        if not CURRENCY.fullmatch(ob.currency):
            raise ScenarioError(f"{where}: currency {ob.currency!r} is not an ISO 4217 code")
        if not COUNTRY.fullmatch(ob.payout_country):
            raise ScenarioError(f"{where}: payout_country {ob.payout_country!r} is not an ISO 3166 code")
        if ob.payout_method not in {"SWIFT", "LOCAL"}:
            raise ScenarioError(f"{where}: payout_method must be SWIFT or LOCAL")
        if not REFERENCE.fullmatch(ob.reference):
            raise ScenarioError(f"{where}: reference must be 1-35 of A-Z a-z 0-9 space . / -")
        if not 0 <= ob.due_in_hours <= 24 * 366:
            raise ScenarioError(f"{where}: due_in_hours out of range")
        if ob.category not in PRIORITY:
            raise ScenarioError(f"{where}: unknown category {ob.category!r}")
        if ob.deferral_penalty_usd < 0:
            raise ScenarioError(f"{where}: deferral penalty cannot be negative")
    by_id = {o.id: o for o in sc.obligations}
    for ob_id, spec in sc.payouts.items():
        if ob_id not in by_id:
            raise ScenarioError(f"payout details for unknown obligation {ob_id}")
        payee = spec.get("beneficiary") or {}
        bank = (payee.get("beneficiary") or {}).get("bank_details") or {}
        if spec.get("reason") is not None and not re.fullmatch(r"[a-z_]{3,40}", str(spec["reason"])):
            raise ScenarioError(f"payout {ob_id}: reason must be an Airwallex reason code")
        if bank.get("account_currency") != by_id[ob_id].currency:
            raise ScenarioError(f"payout {ob_id}: account currency differs from the obligation currency")
        if bank.get("bank_country_code") != by_id[ob_id].payout_country:
            raise ScenarioError(f"payout {ob_id}: bank country differs from the obligation's payout country")
        if (payee.get("transfer_methods") or [None])[0] != by_id[ob_id].payout_method:
            raise ScenarioError(f"payout {ob_id}: transfer method differs from the obligation's payout method")
    for cur, value in {**sc.operating_cash, **sc.mock_rates}.items():
        if not CURRENCY.fullmatch(cur) or value < 0:
            raise ScenarioError(f"invalid currency amount {cur} {value}")
    _check_amount(sc.expected_receipt.amount, "expected receipt")
    _check_amount(sc.deposit.amount, "deposit")
    _check_text(sc.deposit.reference, "deposit reference")


def load_scenario(path: Path | None = None) -> Scenario:
    path = Path(path or FIXTURES / "scenario.json")
    raw = json.loads(path.read_text(encoding="utf-8"), parse_float=Decimal)
    obligations = tuple(
        Obligation(
            id=int(o["id"]), name=o["name"], counterparty=o["counterparty"],
            amount=to_decimal(o["amount"]), currency=o["currency"], due_in_hours=int(o["due_in_hours"]),
            category=o["category"], deferrable=bool(o["deferrable"]),
            deferral_penalty_usd=to_decimal(o["deferral_penalty_usd"]),
            payout_method=o["payout_method"], payout_country=o["payout_country"], reference=o["reference"],
        )
        for o in raw["obligations"]
    )
    ids = [o.id for o in obligations]
    if len(set(ids)) != len(ids):
        raise ScenarioError("obligation ids must be unique")
    er = raw["expected_receipt"]
    receipt = ExpectedReceipt(
        customer=er["customer"], invoice_id=er["invoice_id"], amount=to_decimal(er["amount"]),
        currency=er["currency"], due_in_hours=int(er["due_in_hours"]), invoice_status=er["invoice_status"],
        history=tuple(PastReceipt(h["invoice_id"], date.fromisoformat(h["due"]), date.fromisoformat(h["paid"]),
                                  to_decimal(h["amount"])) for h in er["history"]),
    )
    dep = raw["deposit"]
    email_path = (path.parent / raw["customer_email_file"]).resolve()
    if email_path.parent != path.parent.resolve():
        raise ScenarioError("customer_email_file must sit next to the scenario file")
    scenario = Scenario(
        company=raw["company"],
        operating_cash={k: to_decimal(v) for k, v in raw.get("operating_cash", {}).items()},
        obligations=obligations,
        expected_receipt=receipt,
        customer_email=email_path.read_text(encoding="utf-8"),
        deposit=DepositFixture(to_decimal(dep["amount"]), dep["currency"], dep["payer_name"], dep["reference"]),
        payouts={int(k): v for k, v in raw.get("payouts", {}).items()},
        mock_rates={k: to_decimal(v) for k, v in raw.get("mock_rates_usd_per_unit", {}).items()},
    )
    validate_scenario(scenario)
    return scenario


# ---------------------------------------------------------------------------
# Simulation interface
# ---------------------------------------------------------------------------
class Simulator(Protocol):
    def deposit(self, *, amount, currency: str, payer_name: str, reference: str) -> dict: ...
    def advance_transfer(self, transfer_id: str, next_status: str, failure_type: str | None = None) -> dict: ...


class SimulationError(RuntimeError):
    pass


def _account_currencies(account: dict) -> set[str]:
    out = {f.get("currency") for f in account.get("required_features", []) or []}
    out |= {f.get("currency") for f in account.get("supported_features", []) or []}
    return {c for c in out if c}


class SandboxSimulator:
    """Wraps every sandbox-only endpoint. Nothing else in the codebase calls /simulation/*."""

    def __init__(self, client: AirwallexClient, *, sleep=time.sleep):
        self.client = client
        self._sleep = sleep

    def ensure_global_account(self, currency: str = "USD", country_code: str = "US") -> str:
        """Reuse an ACTIVE Global Account in the currency; create one only if none exists."""
        for account in self.client.list_global_accounts():
            if account.get("status") == "ACTIVE" and currency in _account_currencies(account):
                return account["id"]
        created = self.client.create_global_account(str(uuid.uuid4()), country_code=country_code,
                                                    currency=currency)
        account_id = created["id"]
        for _ in range(10):
            if created.get("status") == "ACTIVE":
                return account_id
            self._sleep(1.0)
            created = self.client.request("GET", f"/global_accounts/{account_id}")
        raise SimulationError(f"Global Account {account_id} did not become ACTIVE")

    def deposit(self, *, amount, currency: str, payer_name: str, reference: str) -> dict:
        account_id = self.ensure_global_account(currency)
        # The deposit lands in the Global Account's currency; the API takes no currency field.
        return self.client.request("POST", "/simulation/deposit/create", body={
            "global_account_id": account_id, "amount": to_decimal(amount),
            "payer_name": payer_name, "reference": reference})

    def advance_transfer(self, transfer_id: str, next_status: str, failure_type: str | None = None) -> dict:
        if next_status not in {"PROCESSING", "SENT", "PAID", "FAILED", "CANCELLED", "OVERDUE"}:
            raise SimulationError(f"unsupported next_status {next_status}")
        body = {"next_status": next_status}
        if failure_type:
            body["failure_type"] = failure_type
        try:
            return self.client.request("POST", f"/simulation/transfers/{transfer_id}/transition", body=body)
        except AirwallexError as exc:
            raise SimulationError(f"could not move transfer {transfer_id} to {next_status}: {exc}") from exc
