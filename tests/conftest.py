import sys
from decimal import Decimal
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent import TreasuryAgent, account_fields, masked_account, payee_key  # noqa: E402
from airwallex_client import AirwallexClient  # noqa: E402
from config import DEFAULT_POLICY  # noqa: E402
from email_reader import RuleBasedReader  # noqa: E402
from explainer import Explainer  # noqa: E402
from mock_sandbox import MOCK_API_KEY, MOCK_CLIENT_ID, MockAirwallex  # noqa: E402
from policy import policy_fingerprint  # noqa: E402
from screening import ListScreener  # noqa: E402
from simulation import SandboxSimulator, load_scenario  # noqa: E402
from store import Store  # noqa: E402

AUDIT_KEY = bytes(range(32))
OPERATOR = "test.operator"
APPROVERS = {
    "sam.treasury": ("Sam", ("treasury_approver",), "fx-approve-42"),
    "dana.controller": ("Dana", ("finance_controller",), "release-funds-7"),
    "casey.compliance": ("Casey", ("compliance_officer",), "screen-names-11"),
}
APPROVER_FOR_KIND = {"FX_CONVERSION": "sam.treasury", "POLICY_EXCEPTION": "dana.controller",
                     "PAYOUT_FAILED": "dana.controller", "SCREENING_REVIEW": "casey.compliance"}


@pytest.fixture
def scenario():
    return load_scenario()


@pytest.fixture
def mock(scenario):
    m = MockAirwallex(balances=scenario.operating_cash, rates_usd_per_unit=scenario.mock_rates,
                      swift_fees=dict(DEFAULT_POLICY.swift_fees))
    m.base_url = m.start()
    yield m
    m.stop()


@pytest.fixture
def client(mock):
    return AirwallexClient(mock.base_url, MOCK_CLIENT_ID, MOCK_API_KEY, sleep=lambda s: None)


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "treasury.db", audit_key=AUDIT_KEY)
    for approver_id, (name, roles, pin) in APPROVERS.items():
        s.enroll_approver(approver_id, name, roles, pin, created_by="test-setup")
    yield s
    s.close()


@pytest.fixture
def screener():
    return ListScreener(ROOT / "fixtures" / "screening_list.json")


PIN_CYCLE = "test-pin"


def pin_cycle(store, cycle_id: str = PIN_CYCLE) -> str:
    """A cycle row to file fixture audit events under: audit_log has a real foreign key to cycles."""
    if store.cycle(cycle_id) is None:
        store.start_cycle(cycle_id, mode="test", operator=OPERATOR,
                          policy_fingerprint=policy_fingerprint(DEFAULT_POLICY), model="rules")
    return cycle_id


def pin_draft(subject: str, masked: str, *, cycle_id: str = PIN_CYCLE, actor: str = "test-fixture",
              obligation_id: int | None = None) -> dict:
    """The record a destination change must carry, in the shape store.repin_payee demands."""
    return {"cycle_id": cycle_id, "act": "setup", "actor": actor, "event": "payee_pinned",
            "reason": f"{subject} pinned to {masked} (test fixture)",
            "obligation_id": obligation_id, "data": {"destination": masked}}


def pin_payee(store, ob, payout_spec, by="dana.controller"):
    fields = account_fields(payout_spec["beneficiary"]["beneficiary"]["bank_details"])
    masked = masked_account(fields)
    cycle_id = pin_cycle(store)
    store.repin_payee(payee_key(ob), store.fingerprint("payee-account", fields), masked,
                      changed_by=by, reason="verified by call-back (test fixture)",
                      audit=pin_draft(ob.counterparty, masked, cycle_id=cycle_id,
                                      actor=f"test-fixture:{by}", obligation_id=ob.id))


@pytest.fixture
def make_agent(client, scenario, store, screener):
    counter = {"n": 0}

    def build(client_override=None, *, pin=True, pin_from=None, cycle_id=None, **overrides):
        counter["n"] += 1
        kwargs = dict(obligations=scenario.obligations, receipt=scenario.expected_receipt,
                      payouts=scenario.payouts, reader=RuleBasedReader(), explainer=Explainer(None),
                      store=store, cycle_id=cycle_id or f"test-cycle-{counter['n']}", operator=OPERATOR,
                      mode="test", screener=screener, cash_cap=scenario.operating_cash, sleep=lambda s: None)
        kwargs.update(overrides)
        if pin:
            for ob in scenario.obligations:
                spec = (pin_from or scenario.payouts).get(ob.id)
                if spec and store.get_payee(payee_key(ob)) is None:
                    pin_payee(store, ob, spec)
        return TreasuryAgent(client_override or client, **kwargs)
    return build


@pytest.fixture
def simulator(client):
    return SandboxSimulator(client, sleep=lambda s: None)


def approve(agent, req, approver_id=None, pin=None, code=None):
    approver_id = approver_id or APPROVER_FOR_KIND[req.kind]
    return agent.approve(req.id, approver_id=approver_id, pin=pin or APPROVERS[approver_id][2],
                         confirm_code=code or req.code)


def D(x) -> Decimal:
    return Decimal(str(x))
