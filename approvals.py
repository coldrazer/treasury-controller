"""Approval binding with authenticated approvers, roles and segregation of duties.

Every human approval is bound to the exact action, amount, currency, counterparty,
destination account (keyed fingerprint), sell ceiling, evidence, requester and expiry.
A SHA-256 digest of those fields yields the confirmation code on the card. To approve,
an authenticated approver (identity + PIN, checked by the store) must hold the role the
approval kind requires, must not be the person who requested it, and must type the
card's code. Approvals are single-use, expire, are superseded when evidence changes,
and every state change is written through to the database, whose triggers refuse any
edit to the bound terms.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum
from typing import Callable, Iterable

from models import ZERO, q2

# Which role may decide which kind of approval (least privilege).
ROLE_FOR_KIND = {
    "FX_CONVERSION": frozenset({"treasury_approver", "finance_controller"}),
    "POLICY_EXCEPTION": frozenset({"finance_controller"}),
    "PAYOUT_FAILED": frozenset({"finance_controller"}),
    "SCREENING_REVIEW": frozenset({"compliance_officer"}),
}


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"
    CONSUMED = "consumed"
    EXPIRED = "expired"


class ApprovalError(RuntimeError):
    pass


@dataclass
class ApprovalRequest:
    id: str
    kind: str
    obligation_id: int
    action: str
    amount: Decimal
    currency: str
    counterparty: str
    evidence: tuple[str, ...]
    requested_by: str
    sell_currency: str | None = None
    max_sell_amount: Decimal | None = None
    destination: str | None = None        # masked account shown to the approver
    destination_fp: str | None = None     # keyed fingerprint of the full account details
    explanation: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    digest: str = ""
    status: ApprovalStatus = ApprovalStatus.PENDING
    decided_by: str | None = None
    decided_at: datetime | None = None
    superseded_by: str | None = None
    consumed_ref: str | None = None

    @property
    def code(self) -> str:
        return self.digest[:8].upper()

    def bound_fields(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "obligation_id": self.obligation_id,
            "action": self.action,
            "amount": format(q2(self.amount), "f"),
            "currency": self.currency,
            "counterparty": self.counterparty,
            "destination_fp": self.destination_fp,
            "sell_currency": self.sell_currency,
            "max_sell_amount": None if self.max_sell_amount is None else format(q2(self.max_sell_amount), "f"),
            "evidence": list(self.evidence),
            "requested_by": self.requested_by,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }

    def to_json(self) -> dict:
        data = asdict(self)
        for key, value in list(data.items()):
            if isinstance(value, Decimal):
                data[key] = str(value)
            elif isinstance(value, datetime):
                data[key] = value.isoformat()
            elif isinstance(value, Enum):
                data[key] = value.value
        data["code"] = self.code
        return data

    def for_reader(self) -> dict:
        """What a person deciding is allowed to see. ``to_json`` is the binding record: the digest
        and the keyed destination fingerprint belong to the store, not to a screen, and neither may
        be copied into a confirmation prompt that is itself shown next to the code being confirmed."""
        return {
            "id": self.id, "kind": self.kind, "obligation_id": self.obligation_id, "action": self.action,
            "amount": format(q2(self.amount), "f"), "currency": self.currency,
            "counterparty": self.counterparty, "destination": self.destination,
            "sell_currency": self.sell_currency,
            "max_sell_amount": None if self.max_sell_amount is None else format(q2(self.max_sell_amount), "f"),
            "evidence": list(self.evidence), "explanation": self.explanation,
            "requested_by": self.requested_by, "code": self.code, "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "expires_at": None if self.expires_at is None else self.expires_at.isoformat(),
            "decided_by": self.decided_by,
        }


def compute_digest(fields: dict) -> str:
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _row_time(value):
    return datetime.fromisoformat(value) if value else None


def approval_from_row(row: dict) -> ApprovalRequest:
    """Rebuild a card from the row the store wrote for it. The digest is the stored one: reopening is
    not a re-issue, and ``_check_live`` re-verifies the terms against it the moment the card is used."""
    return ApprovalRequest(
        id=row["id"], kind=row["kind"], obligation_id=row["obligation_id"], action=row["action"],
        amount=q2(row["amount"]), currency=row["currency"], counterparty=row["counterparty"],
        evidence=tuple(json.loads(row["evidence"])), requested_by=row["requested_by"],
        sell_currency=row["sell_currency"],
        max_sell_amount=None if row["max_sell_amount"] is None else q2(row["max_sell_amount"]),
        destination=row["destination"], destination_fp=row["destination_fp"], explanation=row["explanation"],
        created_at=_row_time(row["created_at"]), expires_at=_row_time(row["expires_at"]),
        digest=row["digest"], status=ApprovalStatus(row["status"]), decided_by=row["decided_by"],
        decided_at=_row_time(row["decided_at"]), superseded_by=row["superseded_by"],
        consumed_ref=row["consumed_ref"])


class ApprovalBook:
    def __init__(self, *, ttl_hours: int = 24,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                 persist: Callable[[ApprovalRequest], None] | None = None):
        self.ttl = timedelta(hours=ttl_hours)
        self.clock = clock
        self.requests: dict[str, ApprovalRequest] = {}
        self._persist = persist or (lambda req: None)

    # -- lifecycle -------------------------------------------------------------
    def request(self, *, kind: str, obligation_id: int, action: str, amount, currency: str,
                counterparty: str, evidence: Iterable[str], requested_by: str,
                sell_currency: str | None = None, max_sell_amount=None, destination: str | None = None,
                destination_fp: str | None = None, explanation: str = "") -> ApprovalRequest:
        evidence = tuple(evidence)
        if kind not in ROLE_FOR_KIND:
            raise ApprovalError(f"unknown approval kind {kind}")
        if not evidence:
            raise ApprovalError("an approval request must name its evidence")
        if q2(amount) <= ZERO:
            raise ApprovalError("an approval request must name a positive amount")
        if not requested_by:
            raise ApprovalError("an approval request must name who requested it")
        now = self.clock()
        req = ApprovalRequest(
            id=f"apr_{uuid.uuid4().hex[:12]}", kind=kind, obligation_id=obligation_id, action=action,
            amount=q2(amount), currency=currency, counterparty=counterparty, evidence=evidence,
            requested_by=requested_by, sell_currency=sell_currency,
            max_sell_amount=None if max_sell_amount is None else q2(max_sell_amount),
            destination=destination, destination_fp=destination_fp, explanation=explanation,
            created_at=now, expires_at=now + self.ttl)
        req.digest = compute_digest(req.bound_fields())
        self._persist(req)  # the new card exists before older ones are superseded by it
        for other in self.open_for(obligation_id):
            if other.id != req.id:
                other.status = ApprovalStatus.SUPERSEDED
                other.superseded_by = req.id
                self._persist(other)
        self.requests[req.id] = req
        return req

    def open_for(self, obligation_id: int) -> list[ApprovalRequest]:
        return [r for r in self.requests.values()
                if r.obligation_id == obligation_id
                and r.status in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED}]

    def reload(self, rows: Iterable[dict]) -> list[ApprovalRequest]:
        """Adopt the cards an earlier run of this cycle left behind, so a crash cannot strand one:
        reloaded cards take part in supersession again and anything past its expiry is closed here
        and written back, never spent by a later run. Returns what it expired."""
        expired: list[ApprovalRequest] = []
        for row in rows:
            if row["status"] not in (ApprovalStatus.PENDING.value, ApprovalStatus.APPROVED.value):
                continue
            req = approval_from_row(row)
            self.requests[req.id] = req
            if req.expires_at and self.clock() > req.expires_at:
                req.status = ApprovalStatus.EXPIRED
                self._persist(req)
                expired.append(req)
        return expired

    def get(self, approval_id: str) -> ApprovalRequest:
        try:
            return self.requests[approval_id]
        except KeyError as exc:
            raise ApprovalError(f"unknown approval {approval_id}") from exc

    def _check_live(self, req: ApprovalRequest) -> None:
        if req.expires_at and self.clock() > req.expires_at:
            if req.status in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED}:
                req.status = ApprovalStatus.EXPIRED
                self._persist(req)
            raise ApprovalError(f"approval {req.id} expired")
        if compute_digest(req.bound_fields()) != req.digest:
            raise ApprovalError(f"approval {req.id} fields changed after it was shown")

    def approve(self, approval_id: str, *, approver_id: str, approver_roles: Iterable[str],
                confirm_code: str) -> ApprovalRequest:
        """Call only with an approver the store has just authenticated."""
        req = self.get(approval_id)
        if req.status is not ApprovalStatus.PENDING:
            raise ApprovalError(f"approval {req.id} is {req.status.value}, not pending")
        self._check_live(req)
        if not approver_id:
            raise ApprovalError("approver identity is required")
        if approver_id == req.requested_by:
            raise ApprovalError("segregation of duties: the requester cannot approve their own request")
        if not ROLE_FOR_KIND[req.kind] & frozenset(approver_roles):
            raise ApprovalError(f"{approver_id} lacks a role that may approve {req.kind} "
                                f"(needs one of {sorted(ROLE_FOR_KIND[req.kind])})")
        if (confirm_code or "").strip().upper() != req.code:
            raise ApprovalError("confirmation code does not match the card shown")
        req.status = ApprovalStatus.APPROVED
        req.decided_by = approver_id
        req.decided_at = self.clock()
        self._persist(req)
        return req

    def reject(self, approval_id: str, *, approver_id: str, approver_roles: Iterable[str]) -> ApprovalRequest:
        req = self.get(approval_id)
        if req.status is not ApprovalStatus.PENDING:
            raise ApprovalError(f"approval {req.id} is {req.status.value}, not pending")
        if approver_id == req.requested_by:
            raise ApprovalError("segregation of duties: the requester cannot decide their own request")
        if not ROLE_FOR_KIND[req.kind] & frozenset(approver_roles):
            raise ApprovalError(f"{approver_id} lacks a role that may decide {req.kind}")
        req.status = ApprovalStatus.REJECTED
        req.decided_by = approver_id
        req.decided_at = self.clock()
        self._persist(req)
        return req

    def supersede(self, approval_id: str) -> ApprovalRequest:
        req = self.get(approval_id)
        if req.status in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED}:
            req.status = ApprovalStatus.SUPERSEDED
            self._persist(req)
        return req

    # -- binding check at execution time ----------------------------------------
    def verify(self, approval_id: str, *, obligation_id: int, action: str, amount, currency: str,
               counterparty: str, sell_currency: str | None = None, sell_amount=None,
               destination_fp: str | None = None) -> ApprovalRequest:
        req = self.get(approval_id)
        if req.status is not ApprovalStatus.APPROVED:
            raise ApprovalError(f"approval {req.id} is {req.status.value}, not approved")
        self._check_live(req)
        mismatches = []
        if req.obligation_id != obligation_id:
            mismatches.append("obligation")
        if req.action != action:
            mismatches.append("action")
        if q2(req.amount) != q2(amount):
            mismatches.append(f"amount {q2(amount)} != approved {q2(req.amount)}")
        if req.currency != currency:
            mismatches.append("currency")
        if req.counterparty != counterparty:
            mismatches.append("counterparty")
        if req.sell_currency != sell_currency:
            mismatches.append("sell currency")
        if req.destination_fp is not None and req.destination_fp != destination_fp:
            mismatches.append("destination account differs from the one approved")
        if req.max_sell_amount is not None:
            if sell_amount is None or q2(sell_amount) > req.max_sell_amount:
                mismatches.append(f"sell amount {sell_amount} above approved ceiling {req.max_sell_amount}")
        if mismatches:
            raise ApprovalError(f"approval {req.id} does not cover this action: " + "; ".join(mismatches))
        return req

    def consume(self, approval_id: str, *, ref: str) -> ApprovalRequest:
        req = self.get(approval_id)
        if req.status is not ApprovalStatus.APPROVED:
            raise ApprovalError(f"approval {req.id} is {req.status.value}; cannot consume")
        req.status = ApprovalStatus.CONSUMED
        req.consumed_ref = ref
        self._persist(req)
        return req
