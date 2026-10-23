"""Airwallex REST client: auth, typed calls, retry with request_id.

Rules this client enforces:
  * Bearer token from POST /authentication/login (x-client-id + x-api-key headers,
    no body); refreshed before its 30-minute expiry and once on a 401.
  * Amounts travel as major units. JSON is parsed with Decimal; nothing is a float.
  * ``x-api-version`` is never sent on /fx/* calls.
  * 429 is always retried with backoff (the request was not processed).
  * A write that times out or returns 5xx is AMBIGUOUS: the client raises
    ``AmbiguousResultError`` and the caller must look the operation up by its
    request_id before retrying with the SAME request_id. Writes are never blindly
    re-sent with a new id.
"""
from __future__ import annotations

import http.client
import json
import random
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Callable

from config import require_https
from models import api_amount, to_decimal

_JITTER = random.SystemRandom()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: a redirect could carry our bearer token or API key to another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def make_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_NoRedirect)

API_PREFIX = "/api/v1"
TOKEN_REFRESH_AFTER_S = 25 * 60
DUPLICATE_CODES = {"duplicate_request_id", "request_id_duplicate"}
INSUFFICIENT_CODES = {"insufficient_funds", "balance_insufficient", "insufficient_fund"}


class AirwallexError(RuntimeError):
    def __init__(self, message: str, *, status: int | None = None, code: str | None = None,
                 body: Any = None, method: str = "", path: str = ""):
        super().__init__(message)
        self.status = status
        self.code = code
        self.body = body
        self.method = method
        self.path = path

    @property
    def is_duplicate_request(self) -> bool:
        return self.code in DUPLICATE_CODES

    @property
    def is_insufficient_funds(self) -> bool:
        return self.code in INSUFFICIENT_CODES

    def __str__(self) -> str:
        where = f"{self.method} {self.path}".strip()
        return f"[{self.status} {self.code}] {where}: {self.args[0]}"


class AmbiguousResultError(AirwallexError):
    """A write may or may not have been applied. Look it up before retrying."""


class _UnreadableBody(Exception):
    """A 2xx response arrived but its body could not be decoded."""


TRANSPORT_ERRORS = (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError,
                    http.client.HTTPException, _UnreadableBody)


def _encode(obj) -> bytes:
    """JSON-encode, writing Decimal as an exact JSON number (no float rounding)."""
    marks: dict[str, str] = {}

    def default(o):
        if isinstance(o, Decimal):
            token = f"__dec{len(marks)}__"
            marks[token] = format(o, "f")
            return token
        raise TypeError(f"not JSON serialisable: {type(o).__name__}")

    text = json.dumps(obj, default=default, separators=(",", ":"))
    for token, number in marks.items():
        text = text.replace(f'"{token}"', number)
    return text.encode("utf-8")


def _decode(raw: bytes):
    if not raw:
        return None
    return json.loads(raw.decode("utf-8"), parse_float=Decimal)


@dataclass
class Balance:
    currency: str
    available: Decimal
    pending: Decimal
    reserved: Decimal
    total: Decimal


class AirwallexClient:
    def __init__(self, base_url: str, client_id: str, api_key: str, *, api_version: str | None = None,
                 timeout: float = 20.0, max_retries: int = 4,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic):
        if not client_id or not api_key:
            raise ValueError("Airwallex client_id and api_key are required (set AWX_CLIENT_ID / AWX_API_KEY)")
        self.base_url = require_https(base_url, "Airwallex base URL")
        self._opener = make_opener()
        self._client_id = client_id
        self._api_key = api_key
        self.api_version = api_version
        self.timeout = timeout
        self.max_retries = max_retries
        self._sleep = sleep
        self._clock = clock
        self._token: str | None = None
        self._token_at: float = 0.0
        self.calls: list[tuple[str, str, int | None]] = []  # (method, path, status) for audit/tests

    def __repr__(self) -> str:  # never leak credentials
        return f"AirwallexClient(base_url={self.base_url!r})"

    # ------------------------------------------------------------------ transport
    def _url(self, path: str, params: dict | None = None) -> str:
        if not path.startswith("/"):
            raise ValueError("path must start with '/'")
        url = f"{self.base_url}{API_PREFIX}{path}"
        if params:
            clean = {k: (api_amount(v) if isinstance(v, Decimal) else v)
                     for k, v in params.items() if v is not None}
            url += "?" + urllib.parse.urlencode(clean)
        return url

    def _send(self, method: str, path: str, *, headers: dict, params=None, body=None):
        data = _encode(body) if body is not None else None
        req = urllib.request.Request(self._url(path, params), data=data, method=method)
        for key, value in headers.items():
            req.add_header(key, value)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:  # nosec B310: https-only (validated in __init__), no redirects
                status = resp.status
                raw = resp.read()
                self.calls.append((method, path, status))
                try:
                    return status, _decode(raw)
                except (ValueError, UnicodeDecodeError) as exc:
                    raise _UnreadableBody(f"HTTP {status} with an unreadable body") from exc
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                payload = _decode(raw)
            except (ValueError, UnicodeDecodeError):
                payload = {"message": raw[:300].decode("utf-8", "replace")}
            self.calls.append((method, path, exc.code))
            return exc.code, payload

    def login(self) -> None:
        for attempt in range(self.max_retries + 1):
            status, payload = self._send("POST", "/authentication/login", headers={
                "x-client-id": self._client_id, "x-api-key": self._api_key})
            if (status == 429 or status >= 500) and attempt < self.max_retries:
                self._backoff(attempt + 1)
                continue
            break
        if status not in (200, 201) or not isinstance(payload, dict) or not payload.get("token"):
            code = payload.get("code") if isinstance(payload, dict) else None
            raise AirwallexError("login failed; check AWX_CLIENT_ID / AWX_API_KEY", status=status,
                                 code=code, method="POST", path="/authentication/login")
        self._token = payload["token"]
        self._token_at = self._clock()

    def _auth_headers(self, path: str) -> dict:
        if not self._token or self._clock() - self._token_at > TOKEN_REFRESH_AFTER_S:
            self.login()
        headers = {"Authorization": f"Bearer {self._token}"}
        if self.api_version and not path.startswith("/fx/"):
            headers["x-api-version"] = self.api_version
        return headers

    def request(self, method: str, path: str, *, params: dict | None = None, body: dict | None = None,
                write: bool | None = None, extra_headers: dict | None = None):
        """``write=True`` marks a non-idempotent call: 5xx/timeouts raise AmbiguousResultError."""
        if write is None:
            write = method != "GET"
        relogged = False
        attempt = 0
        while True:
            try:
                headers = self._auth_headers(path)  # a failed login never sent the request: safe to retry
            except TRANSPORT_ERRORS as exc:
                if attempt >= self.max_retries:
                    raise AirwallexError(f"network error during login: {exc}", method=method, path=path) from exc
                attempt += 1
                self._backoff(attempt)
                continue
            if extra_headers:
                headers.update(extra_headers)
            try:
                status, payload = self._send(method, path, headers=headers, params=params, body=body)
            except TRANSPORT_ERRORS as exc:
                if write:
                    raise AmbiguousResultError(f"no response ({exc}); outcome unknown",
                                               method=method, path=path) from exc
                if attempt >= self.max_retries:
                    raise AirwallexError(f"network error: {exc}", method=method, path=path) from exc
                attempt += 1
                self._backoff(attempt)
                continue

            if 200 <= status < 300:
                return payload
            code = payload.get("code") if isinstance(payload, dict) else None
            message = (payload.get("message") if isinstance(payload, dict) else None) or "request failed"
            if status == 401 and not relogged:
                relogged = True
                self._token = None
                continue
            if status == 429 and attempt < self.max_retries:
                attempt += 1
                self._backoff(attempt)
                continue
            if status >= 500 or (status == 409 and write):  # 409 request_pending: still processing
                if write:
                    raise AmbiguousResultError(message, status=status, code=code, body=payload,
                                               method=method, path=path)
                if attempt < self.max_retries:
                    attempt += 1
                    self._backoff(attempt)
                    continue
            raise AirwallexError(message, status=status, code=code, body=payload, method=method, path=path)

    def _backoff(self, attempt: int) -> None:
        self._sleep(min(8.0, 0.5 * 2 ** (attempt - 1)) + _JITTER.uniform(0, 0.1))

    # ------------------------------------------------------------------ typed calls
    def get_balances(self) -> dict[str, Balance]:
        rows = self.request("GET", "/balances/current")
        if isinstance(rows, dict):  # tolerate an {"items": [...]} wrapper
            rows = rows.get("items", [])
        out: dict[str, Balance] = {}
        for row in rows or []:
            if row.get("account_type", "cash").lower() != "cash":
                continue
            out[row["currency"]] = Balance(
                currency=row["currency"],
                available=to_decimal(row.get("available_amount", 0)),
                pending=to_decimal(row.get("pending_amount", 0)),
                reserved=to_decimal(row.get("reserved_amount", 0)),
                total=to_decimal(row.get("total_amount", 0)),
            )
        return out

    def list_global_accounts(self) -> list[dict]:
        payload = self.request("GET", "/global_accounts")
        return list((payload or {}).get("items", []))

    def create_global_account(self, request_id: str, *, country_code: str, currency: str,
                              transfer_method: str = "LOCAL") -> dict:
        return self.request("POST", "/global_accounts/create", body={
            "request_id": request_id, "country_code": country_code,
            "required_features": [{"currency": currency, "transfer_method": transfer_method}]})

    def get_rate(self, *, buy_currency: str, sell_currency: str, buy_amount) -> dict:
        return self.request("GET", "/fx/rates/current", params={
            "buy_currency": buy_currency, "sell_currency": sell_currency,
            "buy_amount": to_decimal(buy_amount)})

    def create_quote(self, *, buy_currency: str, sell_currency: str, buy_amount,
                     validity: str = "MIN_15") -> dict:
        # A quote moves no money, so a retry is safe; an unused quote simply expires.
        return self.request("POST", "/fx/quotes/create", write=False, body={
            "buy_currency": buy_currency, "sell_currency": sell_currency,
            "buy_amount": to_decimal(buy_amount), "validity": validity})

    def create_conversion(self, request_id: str, *, buy_currency: str, sell_currency: str,
                          buy_amount, quote_id: str | None) -> dict:
        body = {"request_id": request_id, "buy_currency": buy_currency,
                "sell_currency": sell_currency, "buy_amount": api_amount(buy_amount)}
        if quote_id:
            body["quote_id"] = quote_id
        return self.request("POST", "/fx/conversions/create", body=body, write=True)

    def find_conversion(self, request_id: str) -> dict | None:
        payload = self.request("GET", "/fx/conversions", params={"request_id": request_id})
        items = [i for i in (payload or {}).get("items", []) if i.get("request_id") == request_id]
        return items[0] if items else None

    def get_conversion(self, conversion_id: str) -> dict:
        return self.request("GET", f"/fx/conversions/{urllib.parse.quote(conversion_id)}")

    def beneficiary_schema(self, *, bank_country_code: str, account_currency: str,
                           transfer_method: str, entity_type: str) -> dict:
        body = {"bank_country_code": bank_country_code, "account_currency": account_currency,
                "transfer_method": transfer_method, "entity_type": entity_type, "type": "BANK_ACCOUNT"}
        try:  # path documented in the API reference
            return self.request("POST", "/beneficiary_api_schemas/generate", body=body, write=False)
        except AirwallexError as exc:
            if exc.status != 404:
                raise
        # path named in the build spec
        return self.request("POST", "/beneficiaries/schema", body=body, write=False)

    def find_beneficiaries(self, *, nick_name: str) -> list[dict]:
        payload = self.request("GET", "/beneficiaries", params={"nick_name": nick_name})
        return list((payload or {}).get("items", []))

    def create_beneficiary(self, payload: dict) -> dict:
        return self.request("POST", "/beneficiaries/create", body=payload, write=True)

    def create_transfer(self, request_id: str, *, beneficiary_id: str, transfer_currency: str,
                        transfer_amount, source_currency: str, transfer_method: str, reason: str,
                        reference: str, fee_paid_by: str = "PAYER") -> dict:
        if not 10 <= len(request_id) <= 50:
            raise ValueError("transfer request_id must be 10-50 characters")
        return self.request("POST", "/transfers/create", write=True, body={
            "request_id": request_id, "beneficiary_id": beneficiary_id,
            "transfer_currency": transfer_currency, "transfer_amount": api_amount(transfer_amount),
            "source_currency": source_currency, "transfer_method": transfer_method,
            "reason": reason, "reference": reference, "fee_paid_by": fee_paid_by})

    def find_transfer(self, request_id: str) -> dict | None:
        payload = self.request("GET", "/transfers", params={"request_id": request_id})
        items = [i for i in (payload or {}).get("items", []) if i.get("request_id") == request_id]
        return items[0] if items else None

    def list_transfers(self, **filters) -> list[dict]:
        """Recent transfers (Airwallex returns the last 30 days by default), filtered server-side."""
        payload = self.request("GET", "/transfers", params=filters)
        items = list((payload or {}).get("items", []))
        return [i for i in items if all(i.get(k) == v for k, v in filters.items() if v is not None)]

    def get_transfer(self, transfer_id: str) -> dict:
        return self.request("GET", f"/transfers/{urllib.parse.quote(transfer_id)}")
