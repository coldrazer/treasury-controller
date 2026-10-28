"""P4-3: a re-pinned payee must not look identical to the old one.

pin-payee shows the new account in full and makes the controller type it before
a new or changed pin commits; approval cards show the extended form (first 4 and
last 4, bank name, BIC) for a destination that is new or changed.
"""
import json
from pathlib import Path

import manage
from store import Store
from tests.conftest import AUDIT_KEY


def _bootstrap_controller(monkeypatch, tmp_path):
    monkeypatch.setenv("TREASURY_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("TREASURY_AUDIT_KEY", AUDIT_KEY.hex())
    monkeypatch.setenv("TREASURY_NEW_PIN", "release-funds-7")
    assert manage.main(["add-approver", "--bootstrap", "--id", "dana.controller", "--name", "Dana",
                        "--roles", "finance_controller"]) == 0
    monkeypatch.setenv("TREASURY_ADMIN_PIN", "release-funds-7")


def _pin_args(obligation, reason, confirm=None, scenario=None):
    args = ["pin-payee", "--by", "dana.controller", "--obligation", str(obligation),
            "--reason", reason]
    if confirm is not None:
        args += ["--confirm-account", confirm]
    if scenario is not None:
        args += ["--scenario", str(scenario)]
    return args


def _swapped_scenario(tmp_path, iban):
    """A scenario copy with obligation 2's IBAN swapped, plus the email file
    load_scenario requires next to it."""
    import shutil
    fixtures = Path(__file__).resolve().parents[1] / "fixtures"
    shutil.copy(fixtures / "customer_email.txt", tmp_path / "customer_email.txt")
    data = json.loads((fixtures / "scenario.json").read_text())
    data["payouts"]["2"]["beneficiary"]["beneficiary"]["bank_details"]["iban"] = iban
    swapped = tmp_path / "swapped.json"
    swapped.write_text(json.dumps(data))
    return swapped


def _pinned_audit_events(tmp_path):
    with Store(tmp_path / "treasury.db", audit_key=AUDIT_KEY, read_only=True) as s:
        rows = s.conn.execute("SELECT data FROM audit_log WHERE event = 'payee_pinned'").fetchall()
    return [json.loads(r["data"]) if isinstance(r["data"], str) else r["data"] for r in rows]


def test_pin_payee_refuses_without_confirmation(tmp_path, monkeypatch):
    _bootstrap_controller(monkeypatch, tmp_path)
    assert manage.main(_pin_args(2, "IBAN confirmed by call-back")) == 2
    with Store(tmp_path / "treasury.db", audit_key=AUDIT_KEY, read_only=True) as s:
        assert s.get_payee("mueller feinmechanik gmbh") is None


def test_pin_payee_refuses_a_wrong_confirmation(tmp_path, monkeypatch):
    _bootstrap_controller(monkeypatch, tmp_path)
    assert manage.main(_pin_args(2, "IBAN confirmed by call-back",
                                 confirm="DE89370400440532013000")) == 0
    swapped = _swapped_scenario(tmp_path, "DE67370400440999993000")
    assert manage.main(_pin_args(2, "IBAN confirmed by call-back",
                                 confirm="DE89370400440532013000", scenario=swapped)) == 2
    with Store(tmp_path / "treasury.db", audit_key=AUDIT_KEY, read_only=True) as s:
        pin = s.get_payee("mueller feinmechanik gmbh")
        assert pin["masked"] == "IBAN ****3000 · BIC COBADEFFXXX · EUR"
    events = _pinned_audit_events(tmp_path)
    assert len(events) == 1 and events[0]["fingerprint"] == pin["fingerprint"]


def test_pin_payee_with_confirmation_records_both_fingerprints(tmp_path, monkeypatch):
    _bootstrap_controller(monkeypatch, tmp_path)
    assert manage.main(_pin_args(2, "IBAN confirmed by call-back",
                                 confirm="DE89370400440532013000")) == 0
    with Store(tmp_path / "treasury.db", audit_key=AUDIT_KEY, read_only=True) as s:
        first = s.get_payee("mueller feinmechanik gmbh")
    events = _pinned_audit_events(tmp_path)
    assert events[-1]["fingerprint"] == first["fingerprint"]
    assert events[-1]["previous_fingerprint"] is None

    swapped = _swapped_scenario(tmp_path, "DE67370400440999993000")
    assert manage.main(_pin_args(2, "IBAN confirmed by call-back",
                                 confirm="DE67370400440999993000", scenario=swapped)) == 0
    with Store(tmp_path / "treasury.db", audit_key=AUDIT_KEY, read_only=True) as s:
        second = s.get_payee("mueller feinmechanik gmbh")
    assert second["fingerprint"] != first["fingerprint"]
    events = _pinned_audit_events(tmp_path)
    assert events[-1]["fingerprint"] == second["fingerprint"]
    assert events[-1]["previous_fingerprint"] == first["fingerprint"]


def test_card_shows_extended_destination_when_new_and_masked_when_pinned(make_agent, scenario):
    """Obligation 2's FX card: unpinned, the card shows first 4 and last 4 plus the
    bank name; pinned as-is, it shows the masked form."""
    agent = make_agent(pin=False)
    agent.bootstrap()
    agent.triage()
    agent.ingest_customer_email(scenario.customer_email)
    req = next(r for r in agent.pending_approvals() if r.kind == "FX_CONVERSION")
    assert req.destination == "IBAN DE89••3000 · Commerzbank · BIC COBADEFFXXX · EUR"

    agent2 = make_agent(pin=True)
    agent2.bootstrap()
    agent2.triage()
    agent2.ingest_customer_email(scenario.customer_email)
    req2 = next(r for r in agent2.pending_approvals() if r.kind == "FX_CONVERSION")
    assert req2.destination == "IBAN ****3000 · BIC COBADEFFXXX · EUR"
