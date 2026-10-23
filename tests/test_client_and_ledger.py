"""REST client conventions, duplicate protection store, ledger reconciliation, approvals."""
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from airwallex_client import AirwallexClient, AirwallexError, AmbiguousResultError, _encode
from approvals import ApprovalBook, ApprovalError, ApprovalStatus
from config import ConfigError, load_settings
from journal import OperationStore
from store import Store
from ledger import Ledger, LedgerError
from mock_sandbox import MOCK_API_KEY, MOCK_CLIENT_ID

D = Decimal


# --- client ------------------------------------------------------------------
def test_login_and_balances_as_decimal(client):
    balances = client.get_balances()
    assert balances["USD"].available == D("37500.00") and isinstance(balances["EUR"].available, Decimal)


def test_bad_credentials_fail_clearly(mock):
    bad = AirwallexClient(mock.base_url, "nope", "nope", sleep=lambda s: None)
    with pytest.raises(AirwallexError) as exc:
        bad.get_balances()
    assert exc.value.status == 401


def test_x_api_version_is_never_sent_on_fx_calls(mock):
    c = AirwallexClient(mock.base_url, MOCK_CLIENT_ID, MOCK_API_KEY, api_version="2025-06-30", sleep=lambda s: None)
    c.get_balances()
    c.get_rate(buy_currency="EUR", sell_currency="USD", buy_amount=D("100"))   # mock rejects the header on /fx/
    c.create_quote(buy_currency="EUR", sell_currency="USD", buy_amount=D("100"))
    sent = {(r["method"], r["path"]): r["x-api-version"] for r in mock.requests}
    assert sent[("GET", "/balances/current")] == "2025-06-30"
    assert sent[("GET", "/fx/rates/current")] is None and sent[("POST", "/fx/quotes/create")] is None


def test_429_is_retried_with_backoff(client, mock):
    mock.inject("GET /balances/current", "429", "429")
    assert client.get_balances()["USD"].available == D("37500.00")


def test_expired_token_relogs_once(client, mock):
    client.get_balances()
    mock.expire_tokens()
    assert client.get_balances()["USD"].available == D("37500.00")


def test_write_5xx_is_ambiguous_not_retried(client, mock):
    mock.inject("POST /global_accounts/create", "500_after")
    with pytest.raises(AmbiguousResultError):
        client.create_global_account("11111111-2222-3333-4444-555555555555", country_code="US", currency="USD")


def test_decimal_encoding_is_exact():
    assert _encode({"a": D("12491.44"), "b": [D("0.1")]}) == b'{"a":12491.44,"b":[0.1]}'


def test_transfer_request_id_length_enforced_client_side(client):
    with pytest.raises(ValueError):
        client.create_transfer("short", beneficiary_id="b", transfer_currency="EUR", transfer_amount=1,
                               source_currency="EUR", transfer_method="SWIFT", reason="x", reference="y")


def test_settings_refuse_production_and_plain_http():
    with pytest.raises(ConfigError):
        load_settings({"AWX_BASE_URL": "https://api.airwallex.com"})
    with pytest.raises(ConfigError):
        load_settings({"AWX_BASE_URL": "http://api.sandbox.airwallex.com"})
    s = load_settings({"AWX_CLIENT_ID": "id", "AWX_API_KEY": "secret-key"})
    assert "secret-key" not in repr(s)


def test_client_repr_hides_credentials(mock):
    assert "mock-api-key" not in repr(AirwallexClient(mock.base_url, MOCK_CLIENT_ID, MOCK_API_KEY))


# --- operation store ---------------------------------------------------------------
KEY = bytes(range(32))


def _ops(tmp_path, cycle="cycle-ops"):
    db = Store(tmp_path / "ops.db", audit_key=KEY)
    if db.cycle(cycle) is None:
        db.start_cycle(cycle, mode="test", operator="t", policy_fingerprint="0" * 64, model="none")
    return db, OperationStore(db, cycle)


def test_operation_store_reuses_request_id_and_never_repeats(tmp_path):
    db, store = _ops(tmp_path)
    seen = []

    def create(rid):
        seen.append(rid)
        if len(seen) == 1:
            raise AmbiguousResultError("timeout")
        return {"id": "t1", "request_id": rid}

    result, replayed = store.run("transfer:x", create, lookup=lambda rid: None)
    assert result["id"] == "t1" and not replayed and seen[0] == seen[1]
    db.close()                                                     # "restart"
    db, store = _ops(tmp_path)
    again, replayed = store.run("transfer:x", create, lookup=lambda rid: None)
    assert replayed and again["id"] == "t1" and len(seen) == 2   # persisted across restarts
    db.close()


def test_operation_store_resolves_ambiguity_by_lookup(tmp_path):
    db, store = _ops(tmp_path)
    calls = []

    def create(rid):
        calls.append(rid)
        raise AmbiguousResultError("dropped")

    result, _ = store.run("conv:x", create, lookup=lambda rid: {"conversion_id": "c1", "request_id": rid})
    assert result["conversion_id"] == "c1" and len(calls) == 1
    db.close()


# --- ledger ----------------------------------------------------------------------
def test_ledger_cap_commit_and_reconcile():
    led = Ledger({"USD": D("900000"), "EUR": D("500")}, cap={"USD": D("37500"), "EUR": D("500"), "GBP": D("0")})
    assert led.capped and led.balance("USD") == D("37500.00") and led.balance("GBP") == 0
    led.commit(1, "USD", D("8500"), "funded")
    assert led.free("USD") == D("29000.00")
    with pytest.raises(LedgerError):
        led.commit(2, "USD", D("29000.01"), "funded")
    led.apply_conversion(sell_currency="USD", sell_amount=D("100"), buy_currency="EUR", buy_amount=D("92"))
    assert led.reconcile({"USD": D("899900"), "EUR": D("592")}) == []
    mism = led.reconcile({"USD": D("899800"), "EUR": D("592")})
    assert len(mism) == 1 and mism[0].currency == "USD"


# --- approvals -------------------------------------------------------------------------
def make_book(now):
    return ApprovalBook(ttl_hours=1, clock=lambda: now[0])


def request(book, **kw):
    args = dict(kind="FX_CONVERSION", obligation_id=2, action="CONVERT", amount=D("11512.85"), currency="EUR",
                counterparty="Mueller", evidence=["email says delayed"], sell_currency="USD",
                max_sell_amount=D("12553.91"), requested_by="op", destination_fp="f" * 64)
    args.update(kw)
    return book.request(**args)


def test_approval_is_bound_to_exact_terms():
    now = [datetime(2026, 10, 18, tzinfo=timezone.utc)]
    book = make_book(now)
    req = request(book)
    with pytest.raises(ApprovalError):
        book.approve(req.id, approver_id="lead", approver_roles={"treasury_approver"}, confirm_code="WRONG")
    book.approve(req.id, approver_id="lead", approver_roles={"treasury_approver"}, confirm_code=req.code.lower())
    ok = dict(obligation_id=2, action="CONVERT", amount=D("11512.85"), currency="EUR", counterparty="Mueller",
              sell_currency="USD", sell_amount=D("12491.44"), destination_fp="f" * 64)
    book.verify(req.id, **ok)
    for field, bad in [("amount", D("11512.86")), ("currency", "GBP"), ("counterparty", "Someone Else"),
                       ("sell_amount", D("12553.92")), ("obligation_id", 4), ("action", "PAYOUT"),
                       ("destination_fp", "e" * 64)]:
        with pytest.raises(ApprovalError):
            book.verify(req.id, **{**ok, field: bad})
    book.consume(req.id, ref="conv-1")
    with pytest.raises(ApprovalError):
        book.verify(req.id, **ok)          # single use


def test_approval_expires_and_is_superseded():
    now = [datetime(2026, 10, 18, tzinfo=timezone.utc)]
    book = make_book(now)
    first = request(book)
    second = request(book, evidence=["new evidence"])
    assert first.status is ApprovalStatus.SUPERSEDED and first.superseded_by == second.id
    with pytest.raises(ApprovalError):
        book.approve(first.id, approver_id="lead", approver_roles={"treasury_approver"}, confirm_code=first.code)
    now[0] += timedelta(hours=2)
    with pytest.raises(ApprovalError):
        book.approve(second.id, approver_id="lead", approver_roles={"treasury_approver"}, confirm_code=second.code)
    assert second.status is ApprovalStatus.EXPIRED


def test_tampered_approval_fails_digest():
    now = [datetime(2026, 10, 18, tzinfo=timezone.utc)]
    book = make_book(now)
    req = request(book)
    book.approve(req.id, approver_id="lead", approver_roles={"treasury_approver"}, confirm_code=req.code)
    req.amount = D("99999")                 # someone edits the stored request
    with pytest.raises(ApprovalError):
        book.verify(req.id, obligation_id=2, action="CONVERT", amount=D("99999"), currency="EUR",
                    counterparty="Mueller", sell_currency="USD", sell_amount=D("1"))


def test_approval_requires_evidence():
    book = ApprovalBook()
    with pytest.raises(ApprovalError):
        request(book, evidence=[])


def test_login_retries_on_5xx(mock):
    mock.inject("POST /authentication/login", "500_before")
    c = AirwallexClient(mock.base_url, MOCK_CLIENT_ID, MOCK_API_KEY, sleep=lambda s: None)
    assert c.get_balances()["USD"].available == D("37500.00")


def test_dropped_connection_on_read_is_retried(client, mock):
    mock.inject("GET /balances/current", "drop_after")
    assert client.get_balances()["USD"].available == D("37500.00")
