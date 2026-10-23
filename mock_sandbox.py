"""An offline stand-in for the Airwallex sandbox, served over real HTTP on localhost.

It lets the whole four-act demo and the test suite run with no credentials and
no network, while still exercising the real client code path (auth headers,
JSON, error codes). It enforces the behaviours the builder guide warns about:

  * bearer auth from /authentication/login; expired tokens return 401
  * ``x-api-version`` on an /fx/* call is rejected (``incorrect_version``)
  * request_id reuse is rejected; quotes are single-use and expire
  * SWIFT EUR payouts charge a flat EUR 12.85 from the same wallet; LOCAL is free
  * amounts are major units; insufficient-funds codes differ per endpoint
  * beneficiaries need ``transfer_methods`` and a checksum-valid IBAN
  * deposits respond PENDING but post to the balance immediately
  * transfers start PROCESSING and only move via the simulation endpoint

Fault injection (``inject``) lets tests force 429s, 5xx-after-commit and
dropped connections to prove duplicate protection.

This is a test double, not a description of Airwallex internals.
"""
from __future__ import annotations

import json
import re
import threading
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from airwallex_client import _encode
from models import q2, to_decimal

MOCK_CLIENT_ID = "mock-client-id"
MOCK_API_KEY = "mock-api-key"
SWIFT_RE = re.compile(r"^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$")
ID_SEGMENT = re.compile(r"/[0-9a-f-]{8,}|/ga_\w+")  # collapse ids so faults can target a route


def iban_valid(iban: str) -> bool:
    iban = (iban or "").replace(" ", "").upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", iban):
        return False
    digits = "".join(str(int(c, 36)) for c in iban[4:] + iban[:4])
    return int(digits) % 97 == 1


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S+0000")


class MockAirwallex:
    def __init__(self, *, balances: dict[str, Decimal], rates_usd_per_unit: dict[str, Decimal],
                 swift_fees: dict[str, Decimal] | None = None, client_id: str = MOCK_CLIENT_ID,
                 api_key: str = MOCK_API_KEY):
        self.client_id, self.api_key = client_id, api_key
        self.balances = {k: q2(v) for k, v in balances.items()}
        self.rates = {"USD": Decimal("1"), **{k: to_decimal(v) for k, v in rates_usd_per_unit.items()}}
        self.swift_fees = {k: q2(v) for k, v in (swift_fees or {"EUR": Decimal("12.85")}).items()}
        self.tokens: set[str] = set()
        self.quotes: dict[str, dict] = {}
        self.conversions: list[dict] = []
        self.beneficiaries: dict[str, dict] = {}
        self.transfers: dict[str, dict] = {}
        self.deposits: list[dict] = []
        self.used_request_ids: dict[str, set[str]] = defaultdict(set)
        self.global_accounts = [{
            "id": "ga_" + uuid.uuid4().hex[:16], "account_name": "Apex Components Co.", "country_code": "US",
            "status": "ACTIVE", "nick_name": "USD operating",
            "required_features": [{"currency": "USD", "transfer_method": "LOCAL"}],
            "supported_features": [{"currency": "USD", "transfer_method": "LOCAL", "type": "DEPOSIT"}],
        }]
        self.faults: dict[str, list[str]] = defaultdict(list)
        self.requests: list[dict] = []
        self.lock = threading.RLock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------ control
    def inject(self, route: str, *faults: str) -> None:
        """route like 'POST /transfers/create'; faults: '429', '409_before', '500_before', '500_after',
        'drop_after' (processed, connection dropped before the reply), 'redirect' (302 elsewhere)."""
        self.faults[route].extend(faults)

    def expire_tokens(self) -> None:
        with self.lock:
            self.tokens.clear()

    def start(self) -> str:
        mock = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):  # silence
                pass

            def _handle(self):
                mock._dispatch(self)

            do_GET = do_POST = _handle

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.05},
                                        daemon=True)
        self._thread.start()
        host, port = self._server.server_address
        return f"http://{host}:{port}"

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()

    # ------------------------------------------------------------------ plumbing
    def _dispatch(self, h: BaseHTTPRequestHandler) -> None:
        parsed = urlparse(h.path)
        length = int(h.headers.get("Content-Length") or 0)
        raw = h.rfile.read(length) if length else b""
        method, path = h.command, parsed.path
        route_path = path.removeprefix("/api/v1")
        query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        try:
            body = json.loads(raw.decode("utf-8"), parse_float=Decimal) if raw else {}
        except json.JSONDecodeError:
            return self._reply(h, 400, {"code": "invalid_argument", "message": "malformed JSON"})
        with self.lock:
            self.requests.append({"method": method, "path": route_path, "query": query, "body": body,
                                  "x-api-version": h.headers.get("x-api-version")})
            route = f"{method} {ID_SEGMENT.sub('/{id}', route_path)}"
            fault = self.faults[route].pop(0) if self.faults.get(route) else None
            if fault == "429":
                return self._reply(h, 429, {"code": "too_many_requests", "message": "slow down"})
            if fault == "500_before":
                return self._reply(h, 500, {"code": "service_unavailable", "message": "injected"})
            if fault == "redirect":  # e.g. a hijacked proxy trying to bounce credentials elsewhere
                host, port = h.server.server_address
                data = b"{}"
                h.send_response(302)
                h.send_header("Location", f"http://{host}:{port}/api/v1/stolen")
                h.send_header("Content-Length", str(len(data)))
                h.end_headers()
                h.wfile.write(data)
                return
            if fault == "409_before":
                return self._reply(h, 409, {"code": "request_pending", "message": "still processing"})
            try:
                status, payload = self._route(method, route_path, query, body, h.headers)
            except ApiError as exc:
                return self._reply(h, exc.status, {"code": exc.code, "message": exc.message})
            if fault == "500_after":
                return self._reply(h, 500, {"code": "service_unavailable", "message": "injected after commit"})
            if fault == "drop_after":
                h.close_connection = True
                return  # processed, but the caller never hears back
            return self._reply(h, status, payload)

    def _reply(self, h: BaseHTTPRequestHandler, status: int, payload) -> None:
        data = _encode(payload)
        h.send_response(status)
        h.send_header("Content-Type", "application/json")
        h.send_header("Content-Length", str(len(data)))
        h.end_headers()
        h.wfile.write(data)

    def _auth(self, headers) -> None:
        auth = headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] not in self.tokens:
            raise ApiError(401, "credentials_expired" if auth else "credentials_invalid", "invalid or expired token")

    def _route(self, method: str, path: str, query: dict, body: dict, headers):
        if method == "POST" and path == "/authentication/login":
            if headers.get("x-client-id") != self.client_id or headers.get("x-api-key") != self.api_key:
                raise ApiError(401, "credentials_invalid", "bad client id or api key")
            if body:
                raise ApiError(400, "invalid_argument", "login takes no body")
            token = uuid.uuid4().hex
            self.tokens.add(token)
            return 201, {"token": token, "expires_at": _iso(_now() + timedelta(minutes=30))}
        self._auth(headers)
        if path.startswith("/fx/") and headers.get("x-api-version"):
            raise ApiError(400, "incorrect_version", "x-api-version must be omitted on FX calls")

        m = lambda pattern: re.fullmatch(pattern, path)  # noqa: E731
        if method == "GET" and path == "/balances/current":
            return 200, [{"account_type": "cash", "currency": c, "available_amount": v, "pending_amount": 0,
                          "reserved_amount": 0, "prepayment_amount": 0, "total_amount": v}
                         for c, v in sorted(self.balances.items())]
        if method == "GET" and path == "/global_accounts":
            return 200, {"items": self.global_accounts}
        if method == "GET" and (g := m(r"/global_accounts/([\w-]+)")):
            return 200, self._find(self.global_accounts, g.group(1))
        if method == "POST" and path == "/global_accounts/create":
            return 201, self._create_global_account(body)
        if method == "GET" and path == "/fx/rates/current":
            return 200, self._rate(query)
        if method == "POST" and path == "/fx/quotes/create":
            return 201, self._quote(body)
        if method == "POST" and path == "/fx/conversions/create":
            return 201, self._convert(body)
        if method == "GET" and path == "/fx/conversions":
            rid = query.get("request_id")
            return 200, {"has_more": False, "items": [c for c in self.conversions if not rid or c["request_id"] == rid]}
        if method == "GET" and (c := m(r"/fx/conversions/([\w-]+)")):
            return 200, self._find(self.conversions, c.group(1), key="conversion_id")
        if method == "POST" and path in {"/beneficiary_api_schemas/generate", "/beneficiaries/schema"}:
            return 200, self._schema(body)
        if method == "POST" and path == "/beneficiaries/create":
            return 201, self._create_beneficiary(body)
        if method == "GET" and path == "/beneficiaries":
            nick = query.get("nick_name")
            return 200, {"has_more": False,
                         "items": [b for b in self.beneficiaries.values() if not nick or b["nickname"] == nick]}
        if method == "POST" and path == "/transfers/create":
            return 201, self._create_transfer(body)
        if method == "GET" and path == "/transfers":
            keys = ("request_id", "beneficiary_id", "transfer_currency", "status")
            return 200, {"items": [t for t in self.transfers.values()
                                   if all(t.get(k) == query[k] for k in keys if k in query)]}
        if method == "GET" and (t := m(r"/transfers/([\w-]+)")):
            if t.group(1) not in self.transfers:
                raise ApiError(404, "not_found", "transfer not found")
            return 200, self.transfers[t.group(1)]
        if method == "POST" and path == "/simulation/deposit/create":
            return 201, self._deposit(body)
        if method == "POST" and (t := m(r"/simulation/transfers/([\w-]+)/transition")):
            return 200, self._transition(t.group(1), body)
        raise ApiError(404, "not_found", f"no route {method} {path}")

    @staticmethod
    def _find(items, item_id, key="id"):
        for item in items:
            if item.get(key) == item_id:
                return item
        raise ApiError(404, "not_found", f"{item_id} not found")

    def _use_request_id(self, scope: str, request_id, code: str = "duplicate_request_id") -> None:
        if not request_id:
            raise ApiError(400, "field_required", "request_id is required")
        if request_id in self.used_request_ids[scope]:
            raise ApiError(400, code, f"request_id {request_id} already used")
        self.used_request_ids[scope].add(request_id)

    # ------------------------------------------------------------------ FX
    def _price(self, buy: str, sell: str, buy_amount: Decimal) -> tuple[Decimal, Decimal, str]:
        if buy not in self.rates or sell not in self.rates or buy == sell:
            raise ApiError(400, "unsupported_currency", f"{buy}/{sell} not supported")
        sell_amount = q2(buy_amount * self.rates[buy] / self.rates[sell])
        if "USD" in (buy, sell):
            other = sell if buy == "USD" else buy
            return sell_amount, self.rates[other], f"{other}USD"
        return sell_amount, (self.rates[buy] / self.rates[sell]).quantize(Decimal("0.000001")), f"{buy}{sell}"

    def _amount(self, value, field: str) -> Decimal:
        try:
            amount = q2(to_decimal(value))
        except (TypeError, ValueError):
            raise ApiError(400, "invalid_argument", f"{field} must be a number")
        if amount <= 0:
            raise ApiError(400, "invalid_argument", f"{field} must be positive")
        return amount

    def _rate(self, query: dict) -> dict:
        buy, sell = query.get("buy_currency"), query.get("sell_currency")
        if not buy or not sell:
            raise ApiError(400, "field_required", "buy_currency and sell_currency are required")
        buy_amount = self._amount(query.get("buy_amount", "10000"), "buy_amount")
        sell_amount, rate, pair = self._price(buy, sell, buy_amount)
        return {"buy_currency": buy, "sell_currency": sell, "currency_pair": pair, "dealt_currency": buy,
                "rate": rate, "conversion_date": _now().date().isoformat(), "created_at": _iso(_now()),
                "rate_details": [{"level": "CLIENT", "rate": rate, "buy_amount": buy_amount,
                                  "sell_amount": sell_amount}]}

    def _quote(self, body: dict) -> dict:
        buy, sell = body.get("buy_currency"), body.get("sell_currency")
        if not body.get("validity"):
            raise ApiError(400, "field_required", "validity is required")
        if "buy_amount" not in body:
            raise ApiError(400, "field_required", "buy_amount is required in this mock")
        buy_amount = self._amount(body["buy_amount"], "buy_amount")
        sell_amount, rate, pair = self._price(buy, sell, buy_amount)
        quote_id = str(uuid.uuid4())
        valid_to = _now() + timedelta(minutes=15)
        quote = {"quote_id": quote_id, "buy_currency": buy, "sell_currency": sell, "buy_amount": buy_amount,
                 "sell_amount": sell_amount, "client_rate": rate, "currency_pair": pair, "dealt_currency": buy,
                 "usage": "SINGLE_USE", "validity": body["validity"], "valid_from_at": _iso(_now()),
                 "valid_to_at": _iso(valid_to)}
        self.quotes[quote_id] = {**quote, "_used": False, "_expires": valid_to}
        return quote

    def _convert(self, body: dict) -> dict:
        self._use_request_id("conversions", body.get("request_id"))
        buy, sell = body.get("buy_currency"), body.get("sell_currency")
        if "buy_amount" in body and "sell_amount" in body:
            raise ApiError(400, "invalid_argument", "provide only one of buy_amount or sell_amount")
        buy_amount = self._amount(body.get("buy_amount"), "buy_amount")
        quote_id = body.get("quote_id")
        if quote_id:
            q = self.quotes.get(quote_id)
            if q is None or q["_used"]:
                raise ApiError(400, "invalid_quote_id", "quote is unknown or already used")
            if _now() > q["_expires"]:
                raise ApiError(400, "expired_quote", "quote expired")
            if (q["buy_currency"], q["sell_currency"], q["buy_amount"]) != (buy, sell, buy_amount):
                raise ApiError(400, "invalid_argument", "conversion does not match the quote")
            sell_amount, rate, pair = q["sell_amount"], q["client_rate"], q["currency_pair"]
        else:
            sell_amount, rate, pair = self._price(buy, sell, buy_amount)
        if self.balances.get(sell, Decimal(0)) < sell_amount:
            raise ApiError(400, "insufficient_funds", f"not enough {sell}")
        if quote_id:
            self.quotes[quote_id]["_used"] = True
        self.balances[sell] = q2(self.balances[sell] - sell_amount)
        self.balances[buy] = q2(self.balances.get(buy, Decimal(0)) + buy_amount)
        conv = {"conversion_id": str(uuid.uuid4()), "request_id": body["request_id"], "quote_id": quote_id,
                "buy_currency": buy, "sell_currency": sell, "buy_amount": buy_amount, "sell_amount": sell_amount,
                "client_rate": rate, "currency_pair": pair, "dealt_currency": buy, "status": "SETTLED",
                "short_reference_id": _now().strftime("%Y%m%d-") + uuid.uuid4().hex[:6].upper(),
                "created_at": _iso(_now())}
        self.conversions.append(conv)
        return conv

    # ------------------------------------------------------------------ payouts
    def _schema(self, body: dict) -> dict:
        cond = {k: body.get(k) for k in ("bank_country_code", "account_currency", "transfer_method", "entity_type")}
        fields = [
            {"key": "entity_type", "path": "beneficiary.entity_type", "required": True,
             "rule": {"type": "string", "pattern": "COMPANY|PERSONAL"}},
            {"key": "bank_country_code", "path": "beneficiary.bank_details.bank_country_code", "required": True,
             "rule": {"type": "string", "pattern": "^[A-Z]{2}$"}},
            {"key": "account_currency", "path": "beneficiary.bank_details.account_currency", "required": True,
             "rule": {"type": "string", "pattern": "^[A-Z]{3}$"}},
            {"key": "transfer_method", "path": "transfer_method", "required": True,
             "rule": {"type": "string", "pattern": "LOCAL|SWIFT"}},
            {"key": "account_name", "path": "beneficiary.bank_details.account_name", "required": True,
             "rule": {"type": "string", "pattern": "^.{2,200}$"}},
            {"key": "country_code", "path": "beneficiary.address.country_code", "required": True,
             "rule": {"type": "string", "pattern": "^[A-Z]{2}$"}},
            {"key": "city", "path": "beneficiary.address.city", "required": True,
             "rule": {"type": "string", "pattern": "^.{1,50}$"}},
            {"key": "street_address", "path": "beneficiary.address.street_address", "required": True,
             "rule": {"type": "string", "pattern": "^.{1,200}$"}},
            {"key": "nickname", "path": "nickname", "required": False},
        ]
        if cond["entity_type"] == "COMPANY":
            fields.append({"key": "company_name", "path": "beneficiary.company_name", "required": True,
                           "rule": {"type": "string", "pattern": "^.{1,200}$"}})
        if cond["transfer_method"] == "SWIFT":
            fields.append({"key": "swift_code", "path": "beneficiary.bank_details.swift_code", "required": True,
                           "rule": {"type": "string", "pattern": SWIFT_RE.pattern}})
            if cond["bank_country_code"] in {"DE", "FR", "NL", "ES", "IT"}:
                fields.append({"key": "iban", "path": "beneficiary.bank_details.iban", "required": True,
                               "rule": {"type": "string", "pattern": "^[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}$"}})
        return {"condition": {**cond, "type": "BANK_ACCOUNT"}, "fields": fields, "key": "newRecipient"}

    def _create_beneficiary(self, body: dict) -> dict:
        if "payment_methods" in body and "transfer_methods" not in body:
            raise ApiError(400, "001", "transfer_methods is required")
        methods = body.get("transfer_methods")
        if not methods or any(m not in {"LOCAL", "SWIFT"} for m in methods):
            raise ApiError(400, "001", "transfer_methods must be LOCAL and/or SWIFT")
        ben = body.get("beneficiary") or {}
        bank = ben.get("bank_details") or {}
        for key in ("account_currency", "account_name", "bank_country_code"):
            if not bank.get(key):
                raise ApiError(400, "validation_failed", f"beneficiary.bank_details.{key} is required")
        if "SWIFT" in methods:
            if not SWIFT_RE.fullmatch(bank.get("swift_code") or ""):
                raise ApiError(400, "validation_failed", "invalid swift_code")
            if bank.get("iban") is not None and not iban_valid(bank["iban"]):
                raise ApiError(400, "083", "invalid IBAN")
        bid = str(uuid.uuid4())
        record = {"id": bid, "beneficiary": ben, "nickname": body.get("nickname"),
                  "payer_entity_type": body.get("payer_entity_type", "COMPANY"), "transfer_methods": methods}
        self.beneficiaries[bid] = record
        return record

    def _create_transfer(self, body: dict) -> dict:
        rid = body.get("request_id") or ""
        if not 10 <= len(rid) <= 50:
            raise ApiError(400, "018", "request_id must be 10-50 characters")
        if "payment_currency" in body or "payment_amount" in body:
            raise ApiError(400, "001", "transfer_currency is required")
        for key in ("transfer_currency", "transfer_amount", "reason", "reference", "beneficiary_id"):
            if not body.get(key):
                raise ApiError(400, "field_required", f"{key} is required")
        if body.get("transfer_method") not in {"LOCAL", "SWIFT"}:
            raise ApiError(400, "invalid_argument", "transfer_method must be LOCAL or SWIFT")
        ben = self.beneficiaries.get(body["beneficiary_id"])
        if ben is None:
            raise ApiError(400, "invalid_argument", "unknown beneficiary_id")
        if body["transfer_method"] not in ben["transfer_methods"]:
            raise ApiError(400, "payout_method_unsupported", "beneficiary not set up for that method")
        cur = body["transfer_currency"]
        source = body.get("source_currency") or cur
        if source != cur:
            raise ApiError(400, "invalid_argument", "this mock supports same-currency payouts only")
        amount = self._amount(body["transfer_amount"], "transfer_amount")
        fee = self.swift_fees.get(cur, Decimal("0")) if body["transfer_method"] == "SWIFT" else Decimal("0.00")
        if fee == 0 and body["transfer_method"] == "SWIFT":
            raise ApiError(400, "fee_unknown", f"no SWIFT fee for {cur} in this mock")
        payer_pays = q2(amount + fee) if body.get("fee_paid_by", "PAYER") == "PAYER" else amount
        if self.balances.get(source, Decimal(0)) < payer_pays:
            raise ApiError(400, "balance_insufficient", f"{source} balance does not cover {payer_pays}")
        self._use_request_id("transfers", rid, code="request_id_duplicate")
        self.balances[source] = q2(self.balances[source] - payer_pays)
        tid = str(uuid.uuid4())
        transfer = {
            "id": tid, "request_id": rid, "status": "PROCESSING", "beneficiary_id": body["beneficiary_id"],
            "beneficiary": ben["beneficiary"],
            "transfer_currency": cur, "transfer_amount": amount, "source_currency": source,
            "source_amount": payer_pays, "transfer_method": body["transfer_method"], "fee_amount": fee,
            "fee_currency": source, "fee_paid_by": body.get("fee_paid_by", "PAYER"),
            "amount_payer_pays": payer_pays,
            "amount_beneficiary_receives": amount if body.get("fee_paid_by", "PAYER") == "PAYER" else q2(amount - fee),
            "reason": body["reason"], "reference": body["reference"],
            "short_reference_id": _now().strftime("%Y%m%d-") + uuid.uuid4().hex[:6].upper(),
            "created_at": _iso(_now()), "updated_at": _iso(_now()),
        }
        self.transfers[tid] = transfer
        return transfer

    def _transition(self, tid: str, body: dict) -> dict:
        t = self.transfers.get(tid)
        if t is None:
            raise ApiError(404, "not_found", "transfer not found")
        nxt = body.get("next_status")
        allowed = {"PROCESSING": {"SENT", "FAILED", "CANCELLED"}, "SENT": {"PAID", "FAILED"}}
        if nxt not in allowed.get(t["status"], set()):
            raise ApiError(400, "invalid_argument", f"cannot move {t['status']} -> {nxt}")
        if nxt in {"FAILED", "CANCELLED"}:
            # A failed transfer ends CANCELLED; funds return to the wallet.
            t.update(status="CANCELLED", failure_type=body.get("failure_type", "OTHER"),
                     failure_reason="simulation")
            self.balances[t["source_currency"]] = q2(self.balances[t["source_currency"]] + t["amount_payer_pays"])
        else:
            t["status"] = nxt
        t["updated_at"] = _iso(_now())
        return t

    # ------------------------------------------------------------------ deposits
    def _create_global_account(self, body: dict) -> dict:
        self._use_request_id("global_accounts", body.get("request_id"))
        feats = body.get("required_features") or []
        if not feats:
            raise ApiError(400, "field_required", "required_features is required")
        account = {"id": "ga_" + uuid.uuid4().hex[:16], "country_code": body.get("country_code"),
                   "status": "ACTIVE", "required_features": feats, "supported_features": feats,
                   "request_id": body["request_id"]}
        self.global_accounts.append(account)
        return account

    def _deposit(self, body: dict) -> dict:
        account = self._find(self.global_accounts, body.get("global_account_id"))
        amount = self._amount(body.get("amount"), "amount")
        currency = account["required_features"][0]["currency"]  # any 'currency' field is ignored
        self.balances[currency] = q2(self.balances.get(currency, Decimal(0)) + amount)
        dep = {"id": str(uuid.uuid4()), "amount": amount, "currency": currency, "deposit_type": "CREDIT",
               "payer_name": body.get("payer_name"), "reference": body.get("reference"),
               "status": "PENDING", "create_time": _iso(_now())}
        self.deposits.append(dep)
        return dep
