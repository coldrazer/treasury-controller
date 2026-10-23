"""Audit log and duplicate-protection store, both backed by the hardened database.

``AuditLog`` appends every action, with its reason and actor, to the hash-chained,
append-only ``audit_log`` table. Data is redacted before it is stored.

``OperationStore`` gives each money-moving operation a stable request_id that is
committed to the database *before* the call is made. A retry of the same operation
reuses that id; an ambiguous failure is resolved by looking the id up, never by
sending a second request with a fresh id. A completed operation can never change
(enforced by a trigger), and a retired id can never be reused (enforced by a trigger).
"""
from __future__ import annotations

import json
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from airwallex_client import AirwallexError, AmbiguousResultError
from store import Store, jsonable


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(jsonable(data), indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


@dataclass
class AuditEntry:
    ts: str
    act: str
    actor: str
    event: str
    reason: str
    obligation_id: int | None = None
    data: dict = field(default_factory=dict)
    entry_hash: str = ""


class AuditLog:
    def __init__(self, store: Store, cycle_id: str, *, actor: str = "agent"):
        self.store = store
        self.cycle_id = cycle_id
        self.actor = actor
        self.act = "setup"
        self.entries: list[AuditEntry] = []   # this process's entries, for display
        self._lock = threading.Lock()

    def draft(self, event: str, reason: str, *, obligation_id: int | None = None, actor: str | None = None,
              **data) -> dict:
        """The record for a change some other module commits: hand it to the store so the event is
        written in the same transaction as the row it describes, never after it."""
        return {"cycle_id": self.cycle_id, "act": self.act, "actor": actor or self.actor, "event": event,
                "reason": reason, "obligation_id": obligation_id, "data": data}

    def record(self, event: str, reason: str, *, obligation_id: int | None = None, actor: str | None = None,
               **data) -> AuditEntry:
        with self._lock:
            stored = self.store.append_audit(cycle_id=self.cycle_id, act=self.act, actor=actor or self.actor,
                                             event=event, reason=reason, obligation_id=obligation_id, data=data)
        return self.adopt(stored)

    def adopt(self, stored: dict) -> AuditEntry:
        """Claim a record the store wrote inside its own transaction, so what this run shows matches
        what the chain holds."""
        entry = AuditEntry(ts=stored["ts"], act=stored["act"], actor=stored["actor"], event=stored["event"],
                           reason=stored["reason"], obligation_id=stored["obligation_id"], data=stored["data"],
                           entry_hash=stored["entry_hash"])
        with self._lock:
            self.entries.append(entry)
        return entry


class OperationStore:
    def __init__(self, store: Store, cycle_id: str):
        self.store = store
        self.cycle_id = cycle_id

    def request_id(self, key: str) -> str:
        op = self.store.get_operation(self.cycle_id, key)
        if op is None:
            rid = str(uuid.uuid4())
            self.store.create_operation(self.cycle_id, key, rid)  # committed BEFORE the call goes out
            return rid
        return op["request_id"]

    def request_id_of(self, key: str) -> str | None:
        op = self.store.get_operation(self.cycle_id, key)
        return op["request_id"] if op else None

    def result(self, key: str) -> dict | None:
        op = self.store.get_operation(self.cycle_id, key)
        return op["result"] if op and op["status"] == "succeeded" else None

    def record_existing(self, key: str, result: dict, why: str) -> dict:
        """Mark an operation done because the object already exists (found by lookup)."""
        return self.store.record_existing_operation(self.cycle_id, key, result, why)

    def rotate(self, key: str, why: str) -> str:
        """New id after a DEFINITIVE rejection (the old id provably moved nothing). The old id is retired forever."""
        rid = str(uuid.uuid4())
        self.store.rotate_request_id(self.cycle_id, key, rid, why)
        return rid

    def run(self, key: str, create: Callable[[str], dict], lookup: Callable[[str], dict | None],
            *, max_attempts: int = 3) -> tuple[dict, bool]:
        """Execute ``create(request_id)`` at most once in effect. Returns (result, replayed)."""
        done = self.result(key)
        if done is not None:
            return done, True
        rid = self.request_id(key)
        last_exc: Exception | None = None
        for _ in range(max_attempts):
            self.store.bump_attempt(self.cycle_id, key)
            try:
                result = create(rid)
            except AmbiguousResultError as exc:
                last_exc = exc
                found = self._find(lookup, rid, key)
                if found is None:
                    continue  # provably not applied: retry with the SAME request_id
                result = found
            except AirwallexError as exc:
                if not exc.is_duplicate_request:
                    raise
                found = self._find(lookup, rid, key)
                if found is None:
                    raise
                result = found
            return self.store.finish_operation(self.cycle_id, key, result), False
        self.store.mark_unresolved(self.cycle_id, key)
        raise AmbiguousResultError(f"operation {key} unresolved after {max_attempts} attempts: {last_exc}")

    def _find(self, lookup: Callable[[str], dict | None], rid: str, key: str) -> dict | None:
        """Ask the bank what its record of ``rid`` is. A lookup that itself fails has told us nothing,
        and treating that as 'the operation did not happen' would let the caller retire the id and pay
        again: unresolved is the only safe reading, so the request id stays locked."""
        try:
            return lookup(rid)
        except Exception as exc:  # noqa: BLE001 - any lookup failure is the same absence of evidence
            self.store.mark_unresolved(self.cycle_id, key)
            raise AmbiguousResultError(
                f"operation {key} stays unresolved: the bank could not be asked about {rid} ({exc})") from exc
