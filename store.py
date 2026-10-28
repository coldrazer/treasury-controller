"""Hardened persistence: one SQLite database for everything the agent must not lose or forge.

What makes it tight:

  * Audit log is append-only. Triggers reject UPDATE and DELETE, and every entry is
    HMAC-SHA256 hash-chained to the previous one with a key kept OUTSIDE the database
    (TREASURY_AUDIT_KEY). A forged, edited, re-ordered or deleted row breaks the chain;
    without the key the chain cannot be recomputed. ``verify()`` re-checks all of it.
  * Request ids are UNIQUE forever, a retired id can never be reused, and a completed
    operation can never change (Airwallex rejects reused ids for 7 days; we never risk it).
  * One live payout per invoice is a UNIQUE index (payee fingerprint + reference +
    currency + amount, excluding failed payouts): a second payment is refused by the
    database itself, before Airwallex is called.
  * Approval rows: the bound fields (amount, currency, counterparty, destination,
    evidence, digest...) are immutable, status transitions are enforced, terminal rows
    are frozen, the approver must differ from the requester, and rows are never deleted.
  * Approver state is authenticated against its latest HMAC audit event before use;
    PINs are stored as scrypt hashes. Legacy unauthenticated records fail closed.
  * Payee bank details are pinned by keyed fingerprint; changes need a history row.
  * Bank account numbers and similar identifiers are masked before anything is stored.
  * Files are created owner-only (0600 / 0700), a process lock allows a single writer,
    and WAL + synchronous=FULL make commits durable.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum
from pathlib import Path
from typing import Iterable

try:  # POSIX
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None
    import msvcrt

SCHEMA_VERSION = "1"
GENESIS = "0" * 64
KDF = "scrypt:n=16384,r=8,p=1"
MAX_FAILED_PINS = 5
LOCKOUT = timedelta(minutes=15)
MAX_LOCKOUT = timedelta(hours=24)
MIN_PIN_CHARS = 8
APPROVER_ID = re.compile(r"[a-z0-9._-]{3,64}")
ROLES = frozenset({"treasury_approver", "finance_controller", "compliance_officer"})

SENSITIVE_KEYS = frozenset({
    "iban", "account_number", "account_routing_value1", "account_routing_value2", "card", "number", "token",
    "personal_id_number", "legal_rep_id_number", "legal_rep_bank_account_number", "date_of_birth",
    "personal_email", "personal_mobile_number", "binding_mobile_number", "legal_rep_mobile_number",
    "business_phone_number", "api_key", "x-api-key", "authorization", "password", "pin",
    # NOTE: "fingerprint" is deliberately NOT sensitive. A payee fingerprint is a keyed
    # HMAC identifier, not the account itself: it cannot be brute-forced back into bank
    # details, it is already shown truncated in approval evidence and stored in full in
    # payee_history, and the audit event for a pin change is only reconstructable if it
    # carries both fingerprints in full.
})


class StoreError(RuntimeError):
    pass


class StoreLocked(StoreError):
    pass


class AuthError(StoreError):
    pass


class ChainIntegrityError(StoreError):
    """The store refused to open for writing: its own audit record did not verify."""


class DuplicatePayout(StoreError):
    def __init__(self, message: str, existing: dict):
        super().__init__(message)
        self.existing = existing


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _check_pin_policy(pin: str) -> None:
    """A passcode gates real money, and a database backup hands an attacker the salt and hash for free.
    Six digits is 10^6 guesses, which scrypt slows but does not prevent, so digits alone are not a
    passcode here: what is asked for is a short phrase, which the lockout below can actually protect."""
    if not isinstance(pin, str) or len(pin) < MIN_PIN_CHARS:
        raise AuthError(f"a passcode must be at least {MIN_PIN_CHARS} characters; use a short phrase")
    if pin.isdigit():
        raise AuthError("a passcode may not be digits only: an all-digit code is crackable offline "
                        "from a database backup")
    if len(set(pin)) < 4:
        raise AuthError("a passcode must use at least 4 different characters")


def _lockout_until(failed: int) -> str | None:
    """When a failed attempt closes a batch of guesses, the account locks: each batch doubles the wait
    (capped at a day) and the count is never reset, so guessing cannot resume on the old clock forever."""
    if failed < MAX_FAILED_PINS or failed % MAX_FAILED_PINS:
        return None
    wait = min(LOCKOUT * (2 ** (failed // MAX_FAILED_PINS - 1)), MAX_LOCKOUT)
    return (datetime.now(timezone.utc) + wait).isoformat(timespec="microseconds")


def jsonable(value):
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, bytes):
        return "<bytes>"
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [jsonable(v) for v in value]
    return value


def canonical(value) -> str:
    return json.dumps(jsonable(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def mask(value) -> str:
    text = "".join(ch for ch in str(value) if ch.isalnum())
    return ("****" + text[-4:]) if len(text) > 4 else "****"


# IBAN-shaped text in free-form strings (API error messages, reasons): masked like any other account number.
IBAN_TEXT = re.compile(r"\b[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]){11,30}\b")


def scrub_text(text: str) -> str:
    return IBAN_TEXT.sub(lambda m: mask(m.group(0)), text)


SECRET_KEYS = frozenset({"token", "api_key", "x-api-key", "authorization", "password", "pin", "client_secret"})


def redact(value):
    """Mask bank identifiers (last 4 kept, as on a statement) and secrets (nothing kept) anywhere in a
    structure before it is stored."""
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            key = str(k).lower()
            if v in (None, "") or isinstance(v, (dict, list)):
                out[k] = redact(v)
            elif key in SECRET_KEYS:
                out[k] = "****"
            elif key in SENSITIVE_KEYS:
                out[k] = mask(v)
            else:
                out[k] = redact(v)
        return out
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return scrub_text(value)
    return value


def code_fingerprint(root: Path | None = None) -> str:
    """SHA-256 over the shipped .py sources: ties every cycle to the exact code that ran."""
    root = root or Path(__file__).resolve().parent
    h = hashlib.sha256()
    for path in sorted(root.glob("*.py")):
        h.update(path.name.encode())
        h.update(path.read_bytes())
    return h.hexdigest()


def load_audit_key(raw: str | None) -> bytes | None:
    if not raw:
        return None
    raw = raw.strip()
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        import base64
        key = base64.b64decode(raw, validate=True)
    if len(key) < 32:
        raise StoreError("TREASURY_AUDIT_KEY must be at least 32 bytes (64 hex characters)")
    return key


def generate_audit_key() -> str:
    return secrets.token_hex(32)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
# Constant DDL (no runtime input). Every protective trigger aborts the statement that violates it.
SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TRIGGER meta_frozen BEFORE UPDATE ON meta BEGIN SELECT RAISE(ABORT, 'meta is immutable'); END;
CREATE TRIGGER meta_no_delete BEFORE DELETE ON meta BEGIN SELECT RAISE(ABORT, 'meta is immutable'); END;

CREATE TABLE cycles (
  cycle_id TEXT PRIMARY KEY CHECK (length(cycle_id) BETWEEN 3 AND 80),
  started_at TEXT NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('mock', 'live', 'test', 'admin')),
  operator TEXT NOT NULL CHECK (length(operator) > 0),
  policy_fingerprint TEXT NOT NULL CHECK (length(policy_fingerprint) = 64),
  code_fingerprint TEXT NOT NULL CHECK (length(code_fingerprint) = 64),
  model TEXT NOT NULL
);
CREATE TRIGGER cycles_frozen BEFORE UPDATE ON cycles BEGIN SELECT RAISE(ABORT, 'cycles are immutable'); END;
CREATE TRIGGER cycles_no_delete BEFORE DELETE ON cycles BEGIN SELECT RAISE(ABORT, 'cycles cannot be deleted'); END;

CREATE TABLE audit_log (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  cycle_id TEXT NOT NULL REFERENCES cycles(cycle_id),
  ts TEXT NOT NULL,
  act TEXT NOT NULL,
  actor TEXT NOT NULL CHECK (length(actor) > 0),
  event TEXT NOT NULL CHECK (length(event) > 0),
  reason TEXT NOT NULL,
  obligation_id INTEGER,
  data TEXT NOT NULL CHECK (json_valid(data)),
  prev_hash TEXT NOT NULL CHECK (length(prev_hash) = 64),
  entry_hash TEXT NOT NULL UNIQUE CHECK (length(entry_hash) = 64)
);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER audit_chain_link BEFORE INSERT ON audit_log
  WHEN NEW.prev_hash != COALESCE((SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1), '0000000000000000000000000000000000000000000000000000000000000000')
  BEGIN SELECT RAISE(ABORT, 'audit chain broken: prev_hash must equal the last entry_hash'); END;

CREATE TABLE operations (
  cycle_id TEXT NOT NULL REFERENCES cycles(cycle_id),
  op_key TEXT NOT NULL,
  request_id TEXT NOT NULL UNIQUE CHECK (length(request_id) BETWEEN 10 AND 64),
  status TEXT NOT NULL CHECK (status IN ('pending', 'succeeded', 'unresolved')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  result TEXT CHECK (result IS NULL OR json_valid(result)),
  note TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (cycle_id, op_key),
  CHECK ((status = 'succeeded') = (result IS NOT NULL))
);
CREATE TABLE retired_request_ids (
  request_id TEXT PRIMARY KEY,
  cycle_id TEXT NOT NULL REFERENCES cycles(cycle_id),
  op_key TEXT NOT NULL,
  why TEXT NOT NULL,
  retired_at TEXT NOT NULL
);
CREATE TRIGGER retired_frozen BEFORE UPDATE ON retired_request_ids BEGIN SELECT RAISE(ABORT, 'retired request ids are permanent'); END;
CREATE TRIGGER retired_no_delete BEFORE DELETE ON retired_request_ids BEGIN SELECT RAISE(ABORT, 'retired request ids are permanent'); END;
CREATE TRIGGER operations_no_delete BEFORE DELETE ON operations BEGIN SELECT RAISE(ABORT, 'operations cannot be deleted'); END;
CREATE TRIGGER operations_final BEFORE UPDATE ON operations WHEN OLD.status = 'succeeded'
  BEGIN SELECT RAISE(ABORT, 'a completed operation cannot change'); END;
CREATE TRIGGER operations_keys_frozen BEFORE UPDATE ON operations
  WHEN NEW.cycle_id IS NOT OLD.cycle_id OR NEW.op_key IS NOT OLD.op_key OR NEW.created_at IS NOT OLD.created_at
  BEGIN SELECT RAISE(ABORT, 'operation identity is immutable'); END;
CREATE TRIGGER operations_no_retired_insert BEFORE INSERT ON operations
  WHEN EXISTS (SELECT 1 FROM retired_request_ids WHERE request_id = NEW.request_id)
  BEGIN SELECT RAISE(ABORT, 'request_id was retired and can never be reused'); END;
CREATE TRIGGER operations_rotation_rules BEFORE UPDATE OF request_id ON operations
  WHEN NEW.request_id IS NOT OLD.request_id AND (
       EXISTS (SELECT 1 FROM retired_request_ids WHERE request_id = NEW.request_id)
       OR NOT EXISTS (SELECT 1 FROM retired_request_ids WHERE request_id = OLD.request_id))
  BEGIN SELECT RAISE(ABORT, 'rotate only after retiring the old request_id, never to a retired one'); END;

CREATE TABLE approvers (
  approver_id TEXT PRIMARY KEY CHECK (length(approver_id) BETWEEN 3 AND 64 AND approver_id NOT GLOB '*[^a-z0-9._-]*'),
  display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 120),
  roles TEXT NOT NULL CHECK (json_valid(roles)),
  kdf TEXT NOT NULL,
  salt BLOB NOT NULL CHECK (length(salt) >= 16),
  pin_hash BLOB NOT NULL CHECK (length(pin_hash) = 32),
  failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
  locked_until TEXT,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL
);
CREATE TRIGGER approvers_no_delete BEFORE DELETE ON approvers BEGIN SELECT RAISE(ABORT, 'deactivate approvers; never delete them'); END;
CREATE TRIGGER approvers_identity_frozen BEFORE UPDATE ON approvers
  WHEN NEW.approver_id IS NOT OLD.approver_id OR NEW.created_at IS NOT OLD.created_at OR NEW.created_by IS NOT OLD.created_by
  BEGIN SELECT RAISE(ABORT, 'approver identity is immutable'); END;

CREATE TABLE approvals (
  id TEXT PRIMARY KEY,
  cycle_id TEXT NOT NULL REFERENCES cycles(cycle_id),
  kind TEXT NOT NULL CHECK (kind IN ('FX_CONVERSION', 'POLICY_EXCEPTION', 'PAYOUT_FAILED', 'SCREENING_REVIEW')),
  obligation_id INTEGER NOT NULL,
  action TEXT NOT NULL,
  amount TEXT NOT NULL,
  currency TEXT NOT NULL CHECK (length(currency) = 3),
  counterparty TEXT NOT NULL,
  destination TEXT,
  destination_fp TEXT,
  sell_currency TEXT,
  max_sell_amount TEXT,
  evidence TEXT NOT NULL CHECK (json_valid(evidence) AND json_array_length(evidence) > 0),
  explanation TEXT NOT NULL DEFAULT '',
  digest TEXT NOT NULL CHECK (length(digest) = 64),
  requested_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'superseded', 'consumed', 'expired')),
  decided_by TEXT REFERENCES approvers(approver_id),
  decided_at TEXT,
  superseded_by TEXT,
  consumed_ref TEXT,
  CHECK (decided_by IS NULL OR decided_by != requested_by),
  CHECK (status NOT IN ('approved', 'consumed', 'rejected') OR decided_by IS NOT NULL)
);
CREATE TRIGGER approvals_no_delete BEFORE DELETE ON approvals BEGIN SELECT RAISE(ABORT, 'approvals cannot be deleted'); END;
CREATE TRIGGER approvals_bound_fields_frozen BEFORE UPDATE ON approvals
  WHEN NEW.cycle_id IS NOT OLD.cycle_id OR NEW.kind IS NOT OLD.kind OR NEW.obligation_id IS NOT OLD.obligation_id
    OR NEW.action IS NOT OLD.action OR NEW.amount IS NOT OLD.amount OR NEW.currency IS NOT OLD.currency
    OR NEW.counterparty IS NOT OLD.counterparty OR NEW.destination IS NOT OLD.destination
    OR NEW.destination_fp IS NOT OLD.destination_fp OR NEW.sell_currency IS NOT OLD.sell_currency
    OR NEW.max_sell_amount IS NOT OLD.max_sell_amount OR NEW.evidence IS NOT OLD.evidence
    OR NEW.explanation IS NOT OLD.explanation OR NEW.digest IS NOT OLD.digest
    OR NEW.requested_by IS NOT OLD.requested_by OR NEW.created_at IS NOT OLD.created_at
    OR NEW.expires_at IS NOT OLD.expires_at
  BEGIN SELECT RAISE(ABORT, 'approval terms are immutable once shown'); END;
CREATE TRIGGER approvals_terminal_frozen BEFORE UPDATE ON approvals
  WHEN OLD.status IN ('rejected', 'superseded', 'consumed', 'expired')
  BEGIN SELECT RAISE(ABORT, 'a closed approval cannot change'); END;
CREATE TRIGGER approvals_transitions BEFORE UPDATE OF status ON approvals
  WHEN NOT ((OLD.status = 'pending' AND NEW.status IN ('pending', 'approved', 'rejected', 'superseded', 'expired'))
         OR (OLD.status = 'approved' AND NEW.status IN ('approved', 'consumed', 'superseded', 'expired')))
  BEGIN SELECT RAISE(ABORT, 'illegal approval status transition'); END;
CREATE TRIGGER approvals_decision_frozen BEFORE UPDATE ON approvals
  WHEN OLD.decided_by IS NOT NULL AND (NEW.decided_by IS NOT OLD.decided_by OR NEW.decided_at IS NOT OLD.decided_at)
  BEGIN SELECT RAISE(ABORT, 'who approved, and when, cannot change'); END;

CREATE TABLE payees (
  payee_key TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL CHECK (length(fingerprint) = 64),
  masked TEXT NOT NULL,
  pinned_at TEXT NOT NULL,
  pinned_by TEXT NOT NULL,
  approval_id TEXT REFERENCES approvals(id)
);
CREATE TABLE payee_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  payee_key TEXT NOT NULL,
  old_fingerprint TEXT,
  new_fingerprint TEXT NOT NULL,
  changed_at TEXT NOT NULL,
  changed_by TEXT NOT NULL,
  reason TEXT NOT NULL CHECK (length(reason) >= 10)
);
CREATE TRIGGER payees_no_update BEFORE UPDATE ON payees BEGIN SELECT RAISE(ABORT, 'payee bank details are pinned; re-pin through the controlled change'); END;
CREATE TRIGGER payees_delete_needs_history BEFORE DELETE ON payees
  WHEN NOT EXISTS (SELECT 1 FROM payee_history WHERE payee_key = OLD.payee_key AND old_fingerprint = OLD.fingerprint)
  BEGIN SELECT RAISE(ABORT, 'payee change must be recorded in payee_history first'); END;
CREATE TRIGGER payee_history_frozen BEFORE UPDATE ON payee_history BEGIN SELECT RAISE(ABORT, 'payee_history is append-only'); END;
CREATE TRIGGER payee_history_no_delete BEFORE DELETE ON payee_history BEGIN SELECT RAISE(ABORT, 'payee_history is append-only'); END;

CREATE TABLE payouts (
  request_id TEXT PRIMARY KEY,
  cycle_id TEXT NOT NULL REFERENCES cycles(cycle_id),
  obligation_id INTEGER NOT NULL,
  payee_fingerprint TEXT NOT NULL CHECK (length(payee_fingerprint) = 64),
  reference TEXT NOT NULL,
  currency TEXT NOT NULL CHECK (length(currency) = 3),
  amount TEXT NOT NULL,
  transfer_id TEXT UNIQUE,
  status TEXT NOT NULL CHECK (status IN ('initiated', 'in_flight', 'paid', 'failed', 'cancelled')),
  note TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX one_live_payout_per_invoice
  ON payouts (payee_fingerprint, reference, currency) WHERE status NOT IN ('failed', 'cancelled');
CREATE TRIGGER payouts_no_delete BEFORE DELETE ON payouts BEGIN SELECT RAISE(ABORT, 'payouts cannot be deleted'); END;
CREATE TRIGGER payouts_terms_frozen BEFORE UPDATE ON payouts
  WHEN NEW.cycle_id IS NOT OLD.cycle_id OR NEW.obligation_id IS NOT OLD.obligation_id
    OR NEW.payee_fingerprint IS NOT OLD.payee_fingerprint OR NEW.reference IS NOT OLD.reference
    OR NEW.currency IS NOT OLD.currency OR NEW.amount IS NOT OLD.amount OR NEW.created_at IS NOT OLD.created_at
    OR (OLD.transfer_id IS NOT NULL AND NEW.transfer_id IS NOT OLD.transfer_id)
  BEGIN SELECT RAISE(ABORT, 'payout terms are immutable'); END;
CREATE TRIGGER payouts_terminal_frozen BEFORE UPDATE ON payouts
  WHEN OLD.status IN ('paid', 'failed', 'cancelled')
  BEGIN SELECT RAISE(ABORT, 'a settled, failed or cancelled payout cannot change'); END;
CREATE TRIGGER payouts_transitions BEFORE UPDATE OF status ON payouts
  WHEN NOT (NEW.status = OLD.status
         OR (OLD.status = 'initiated' AND NEW.status IN ('in_flight', 'paid', 'failed', 'cancelled'))
         OR (OLD.status = 'in_flight' AND NEW.status IN ('paid', 'failed')))
  BEGIN SELECT RAISE(ABORT, 'illegal payout status transition'); END;

CREATE TABLE snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cycle_id TEXT NOT NULL REFERENCES cycles(cycle_id),
  act TEXT NOT NULL,
  ts TEXT NOT NULL,
  data TEXT NOT NULL CHECK (json_valid(data))
);
CREATE TRIGGER snapshots_frozen BEFORE UPDATE ON snapshots BEGIN SELECT RAISE(ABORT, 'snapshots are append-only'); END;
CREATE TRIGGER snapshots_no_delete BEFORE DELETE ON snapshots BEGIN SELECT RAISE(ABORT, 'snapshots are append-only'); END;
CREATE TABLE deferrals (
  cycle_id TEXT NOT NULL REFERENCES cycles(cycle_id),
  obligation_id INTEGER NOT NULL,
  deferred_until TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (cycle_id, obligation_id)
);
CREATE TABLE cycle_state (
  cycle_id TEXT PRIMARY KEY REFERENCES cycles(cycle_id),
  autonomous_executed TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE payout_state (
  cycle_id TEXT PRIMARY KEY REFERENCES cycles(cycle_id),
  autonomous_paid TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
"""
if f"'{GENESIS}'" not in SCHEMA:  # the chain-link trigger and the code must agree on the genesis hash
    raise ImportError("schema genesis hash mismatch")

EXPECTED_TRIGGERS = frozenset(
    line.split()[2] for line in SCHEMA.splitlines() if line.startswith("CREATE TRIGGER"))

# Rows that bind money (a payout reservation, an idempotent bank operation) hold no approval
# digest, so each of their states is signed into the audit chain the way approver state is.
ROW_STATE_VERSION = "1"
STATE_TABLES = ("operations", "payouts", "approvals", "payees", "payee_history")
_STATE_EVENTS = frozenset(f"{table}_state" for table in STATE_TABLES)
_ROW_BY_KEY = {"payouts": "SELECT * FROM payouts WHERE request_id = ?",
               "operations": "SELECT * FROM operations WHERE cycle_id = ? AND op_key = ?",
               "approvals": "SELECT * FROM approvals WHERE id = ?",
               "payees": "SELECT * FROM payees WHERE payee_key = ?",
               "payee_history": "SELECT * FROM payee_history WHERE payee_key = ? AND id = ?"}
_ROW_ALL = {"payouts": "SELECT * FROM payouts", "operations": "SELECT * FROM operations",
            "approvals": "SELECT * FROM approvals", "payees": "SELECT * FROM payees",
            "payee_history": "SELECT * FROM payee_history"}

# The payout guard used to key on the amount as well, so paying an invoice for a different figure was
# a second live payout rather than a duplicate. The tightened guard is recognised on an existing
# ledger by the old index's own text, and re-created once; any other DDL difference stays tampering.
PAYOUT_INDEX = "one_live_payout_per_invoice"
_PAYOUT_INDEX_DROP = "DROP INDEX one_live_payout_per_invoice"
LEGACY_SCHEMA = {
    PAYOUT_INDEX: "CREATE UNIQUE INDEX one_live_payout_per_invoice\n"
                  "  ON payouts (payee_fingerprint, reference, currency, amount) "
                  "WHERE status NOT IN ('failed', 'cancelled');",
}


@dataclass
class Approver:
    approver_id: str
    display_name: str
    roles: frozenset[str]
    active: bool


@dataclass
class VerifyReport:
    ok: bool
    entries: int
    head_hash: str
    chain: str
    problems: list[str]
    # Records no key can vouch for yet (rows written before state signing existed). Not tampering,
    # but not proof either: they need a trusted human decision, and they block every auth operation.
    pending: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# The store
# ---------------------------------------------------------------------------
class Store:
    def __init__(self, path: Path | str, *, audit_key: bytes | None = None, read_only: bool = False):
        self.path = Path(path)
        self._key = audit_key
        self.read_only = read_only
        self._lock_fh = None
        os.umask(0o077)  # everything this process creates (db, -wal, -shm, exports) is owner-only
        if read_only:
            if not self.path.is_file():
                raise StoreError(f"no database at {self.path}")
            self.conn = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, isolation_level=None)
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            self._acquire_lock()
            if not self.path.exists():
                os.close(os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600))
            self.conn = sqlite3.connect(str(self.path), isolation_level=None, timeout=10)
        self.conn.row_factory = sqlite3.Row
        for pragma in ("foreign_keys = ON", "trusted_schema = OFF"):
            self.conn.execute(f"PRAGMA {pragma}")
        if not read_only:
            for pragma in ("journal_mode = WAL", "synchronous = FULL", "secure_delete = ON"):
                self.conn.execute(f"PRAGMA {pragma}")
            self._migrate()
            self._harden_files()
        self._check_key()
        if not read_only:
            self._verify_on_open()

    def _verify_on_open(self) -> None:
        """A writer refuses to run a cycle on a ledger that shows tampering. Read-only opens (the
        audit tool inspecting a suspected forgery) must still open, so they are not gated. Records
        awaiting a trusted decision are not tampering: they are seeded below and reported."""
        if not self.conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'audit_log'").fetchone():
            return
        report = self.verify()
        if report.problems:
            raise ChainIntegrityError("audit record shows tampering: " + "; ".join(report.problems[:5]))
        self._seed_row_states()

    # ------------------------------------------------------------------ plumbing
    def _acquire_lock(self) -> None:
        lock_path = self.path.with_name(self.path.name + ".lock")
        fh = open(lock_path, "a+")
        os.chmod(lock_path, 0o600)
        try:
            if fcntl:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:  # pragma: no cover
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            fh.close()
            raise StoreLocked(f"{self.path} is in use by another treasury process") from exc
        self._lock_fh = fh

    def _harden_files(self) -> None:
        for suffix in ("", "-wal", "-shm"):
            p = Path(str(self.path) + suffix)
            if p.exists():
                os.chmod(p, 0o600)
        try:
            os.chmod(self.path.parent, 0o700)
        except PermissionError:  # pragma: no cover - parent owned by someone else
            pass

    def close(self) -> None:
        try:
            self.conn.close()
        finally:
            if self._lock_fh:
                self._lock_fh.close()
                self._lock_fh = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    @contextmanager
    def tx(self, *, read_only: bool = False):
        self.conn.execute("BEGIN" if read_only else "BEGIN IMMEDIATE")
        try:
            yield self.conn
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        else:
            self.conn.execute("COMMIT")

    def _meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def _migrate(self) -> None:
        exists = self.conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'meta'").fetchone()
        if not exists:
            with self.tx() as c:
                for statement in _split_sql(SCHEMA):
                    c.execute(statement)
                chain = "hmac-sha256" if self._key else "sha256"
                meta = {"schema_version": SCHEMA_VERSION, "created_at": now_iso(), "audit_chain": chain,
                        "retention": "Records are never deleted by this software. Retain at least 7 years."}
                if self._key:
                    meta["audit_key_check"] = hmac.new(self._key, b"treasury-audit-key-check",
                                                       hashlib.sha256).hexdigest()[:16]
                c.executemany("INSERT INTO meta (key, value) VALUES (?, ?)", list(meta.items()))
            return
        version = self._meta("schema_version")
        if version != SCHEMA_VERSION:
            raise StoreError(f"database schema {version} is not supported (expected {SCHEMA_VERSION})")
        self._retighten_payout_index()
        self._ensure_resume_tables()

    def _ensure_resume_tables(self) -> None:
        """Item 03 tables are purely additive: an older ledger gains them on open, using the
        exact DDL the schema check expects, so verification keeps passing on existing databases."""
        for name in ("deferrals", "cycle_state", "payout_state"):
            if not self.conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)).fetchone():
                self.conn.execute(SCHEMA_STATEMENTS[name])

    def _retighten_payout_index(self) -> None:
        """Re-create the payout guard from the current schema when the ledger still holds the known
        older shape of it. Any other difference from the current schema is left alone for verification
        to report as tampering: this is an upgrade path, not a way to make a mismatched schema pass."""
        live = self.conn.execute("SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?",
                                 (PAYOUT_INDEX,)).fetchone()
        if live is None or _normalized_sql(live["sql"] or "") != _normalized_sql(LEGACY_SCHEMA[PAYOUT_INDEX]):
            return
        with self.tx() as c:
            c.execute(_PAYOUT_INDEX_DROP)
            try:
                c.execute(SCHEMA_STATEMENTS[PAYOUT_INDEX])
            except sqlite3.IntegrityError as exc:
                raise StoreError("the tightened payout guard found live duplicates: this ledger holds two "
                                 "unfailed payouts of the same invoice; resolve them before opening it") from exc

    def _check_key(self) -> None:
        chain = self._meta("audit_chain")
        if chain == "hmac-sha256":
            if not self._key:
                raise StoreError("this database's audit chain is keyed: set TREASURY_AUDIT_KEY")
            check = hmac.new(self._key, b"treasury-audit-key-check", hashlib.sha256).hexdigest()[:16]
            if not hmac.compare_digest(check, self._meta("audit_key_check") or ""):
                raise StoreError("TREASURY_AUDIT_KEY does not match this database")
        elif chain == "sha256" and self._key:
            raise StoreError("this database was created without an audit key; it cannot be re-keyed in place")

    @property
    def keyed(self) -> bool:
        return self._meta("audit_chain") == "hmac-sha256"

    def _hash(self, message: str) -> str:
        if self._key:
            return hmac.new(self._key, message.encode("utf-8"), hashlib.sha256).hexdigest()
        return hashlib.sha256(message.encode("utf-8")).hexdigest()

    def fingerprint(self, label: str, value) -> str:
        """Keyed fingerprint (so bank details cannot be brute-forced back out of the database)."""
        message = f"{label}:{canonical(value)}"
        if self._key:
            k = hmac.new(self._key, b"treasury-fingerprint", hashlib.sha256).digest()
            return hmac.new(k, message.encode("utf-8"), hashlib.sha256).hexdigest()
        return hashlib.sha256(message.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------ cycles
    def start_cycle(self, cycle_id: str, *, mode: str, operator: str, policy_fingerprint: str,
                    model: str, code_fp: str | None = None) -> None:
        with self.tx() as c:
            c.execute("INSERT INTO cycles VALUES (?, ?, ?, ?, ?, ?, ?)",
                      (cycle_id, now_iso(), mode, operator, policy_fingerprint, code_fp or code_fingerprint(), model))

    def cycle(self, cycle_id: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM cycles WHERE cycle_id = ?", (cycle_id,)).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------ audit log
    def append_audit(self, *, cycle_id: str, act: str, actor: str, event: str, reason: str,
                     obligation_id: int | None, data: dict) -> dict:
        for _ in range(3):
            try:
                with self.tx() as c:
                    return self._append_audit(c, cycle_id=cycle_id, act=act, actor=actor, event=event,
                                              reason=reason, obligation_id=obligation_id, data=data)
            except sqlite3.OperationalError as exc:  # pragma: no cover - busy from a reader
                if "locked" not in str(exc):
                    raise
                time.sleep(0.05)
        raise StoreError("could not append to the audit log")

    def _append_audit(self, c, *, cycle_id: str, act: str, actor: str, event: str, reason: str,
                      obligation_id: int | None, data: dict) -> dict:
        """Append inside the caller's transaction, including atomic identity changes."""
        data_json = canonical(redact(jsonable(data)))
        row = c.execute("SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        prev = row["entry_hash"] if row else GENESIS
        entry = {"cycle_id": cycle_id, "ts": now_iso(), "act": act, "actor": actor, "event": event,
                 "reason": scrub_text(reason), "obligation_id": obligation_id,
                 "data": json.loads(data_json), "prev_hash": prev}
        entry_hash = self._hash(canonical(entry))
        c.execute("INSERT INTO audit_log (cycle_id, ts, act, actor, event, reason, obligation_id, data,"
                  " prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                  (cycle_id, entry["ts"], act, actor, event, entry["reason"], obligation_id, data_json,
                   prev, entry_hash))
        return {**entry, "entry_hash": entry_hash}

    def audit_entries(self, cycle_id: str | None = None) -> list[dict]:
        sql = "SELECT * FROM audit_log WHERE (?1 IS NULL OR cycle_id = ?1) ORDER BY seq"
        rows = self.conn.execute(sql, (cycle_id,)).fetchall()
        return [{**dict(r), "data": json.loads(r["data"])} for r in rows]

    # ------------------------------------------------------------------ row state
    def _row_state_hash(self, table: str, row) -> str:
        state = {k: (v.hex() if isinstance(v, bytes) else v) for k, v in dict(row).items()}
        return self._hash(f"{table}-state:v{ROW_STATE_VERSION}:" + canonical(state))

    @staticmethod
    def _row_state_key(table: str, row) -> str:
        if table == "payouts":
            return row["request_id"]
        if table == "operations":
            return f"{row['cycle_id']}|{row['op_key']}"
        if table == "approvals":
            return row["id"]
        if table == "payees":
            return row["payee_key"]
        return f"{row['payee_key']}|{row['id']}"

    def _stamp_row(self, c, table: str, *key_params, cycle_id: str | None = None) -> None:
        """Sign the row's post-write state into the audit chain, inside the caller's transaction.
        Payee rows carry no cycle, so their writers pass the cycle the change was filed under."""
        row = c.execute(_ROW_BY_KEY[table], key_params).fetchone()
        if row is None:
            raise StoreError(f"{table} row {'|'.join(map(str, key_params))} is missing")
        key = self._row_state_key(table, row)
        self._append_audit(c, cycle_id=cycle_id if cycle_id is not None else row["cycle_id"],
                           act="ledger", actor="identity-store",
                           event=f"{table}_state", reason=f"Authenticated state for {key}.",
                           obligation_id=row["obligation_id"] if table == "payouts" else None,
                           data={"table": table, "key": key, "state_hash": self._row_state_hash(table, row)})

    def _seed_row_states(self) -> None:
        """Give money rows written before state signing existed a signed state, so an upgraded
        ledger verifies. Only ever called on a store whose chain already verified, which is what
        makes it safe: a rewritten row cannot be cured here, because the state it would be
        measured against is the one the (unforgeable) chain recorded."""
        recorded: dict[str, str] = {}
        for event in sorted(_STATE_EVENTS):
            for row in self.conn.execute("SELECT data FROM audit_log WHERE event = ? ORDER BY seq", (event,)):
                data = json.loads(row["data"])
                recorded[data["key"]] = data["state_hash"]
        pending = []
        for table in STATE_TABLES:
            for row in self.conn.execute(_ROW_ALL[table]):
                key = self._row_state_key(table, row)
                if key not in recorded or not hmac.compare_digest(recorded[key], self._row_state_hash(table, row)):
                    pending.append((table, row))
        if not pending:
            return
        latest_cycle = self.conn.execute(
            "SELECT cycle_id FROM cycles ORDER BY started_at DESC LIMIT 1").fetchone()
        with self.tx() as c:
            for table, row in pending:
                if table == "payouts":
                    params: list = [row["request_id"]]
                elif table == "operations":
                    params = [row["cycle_id"], row["op_key"]]
                elif table == "approvals":
                    params = [row["id"]]
                elif table == "payees":
                    params = [row["payee_key"]]
                else:
                    params = [row["payee_key"], row["id"]]
                if table in ("payees", "payee_history") and latest_cycle is None:
                    continue  # no cycle to file the seed event under; stays pending, human decides
                self._stamp_row(c, table, *params,
                                cycle_id=latest_cycle["cycle_id"] if table in ("payees", "payee_history")
                                else None)

    # ------------------------------------------------------------------ operations
    def get_operation(self, cycle_id: str, op_key: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM operations WHERE cycle_id = ? AND op_key = ?",
                                (cycle_id, op_key)).fetchone()
        if not row:
            return None
        out = dict(row)
        out["result"] = json.loads(out["result"]) if out["result"] else None
        return out

    def create_operation(self, cycle_id: str, op_key: str, request_id: str) -> None:
        ts = now_iso()
        with self.tx() as c:
            c.execute("INSERT INTO operations (cycle_id, op_key, request_id, status, attempts, created_at, updated_at)"
                      " VALUES (?, ?, ?, 'pending', 0, ?, ?)", (cycle_id, op_key, request_id, ts, ts))
            self._stamp_row(c, "operations", cycle_id, op_key)

    def bump_attempt(self, cycle_id: str, op_key: str) -> None:
        with self.tx() as c:
            c.execute("UPDATE operations SET attempts = attempts + 1, updated_at = ? WHERE cycle_id = ? AND op_key = ?",
                      (now_iso(), cycle_id, op_key))
            self._stamp_row(c, "operations", cycle_id, op_key)

    def finish_operation(self, cycle_id: str, op_key: str, result: dict, note: str | None = None) -> dict:
        stored = redact(jsonable(result))
        with self.tx() as c:
            c.execute("UPDATE operations SET status = 'succeeded', result = ?, note = COALESCE(?, note), updated_at = ?"
                      " WHERE cycle_id = ? AND op_key = ?", (canonical(stored), note, now_iso(), cycle_id, op_key))
            self._stamp_row(c, "operations", cycle_id, op_key)
        return stored

    def mark_unresolved(self, cycle_id: str, op_key: str) -> None:
        with self.tx() as c:
            c.execute("UPDATE operations SET status = 'unresolved', updated_at = ? WHERE cycle_id = ? AND op_key = ?",
                      (now_iso(), cycle_id, op_key))
            self._stamp_row(c, "operations", cycle_id, op_key)

    def rotate_request_id(self, cycle_id: str, op_key: str, new_request_id: str, why: str) -> None:
        with self.tx() as c:
            op = c.execute("SELECT request_id FROM operations WHERE cycle_id = ? AND op_key = ?",
                           (cycle_id, op_key)).fetchone()
            c.execute("INSERT INTO retired_request_ids VALUES (?, ?, ?, ?, ?)",
                      (op["request_id"], cycle_id, op_key, why, now_iso()))
            c.execute("UPDATE operations SET request_id = ?, status = 'pending', updated_at = ?"
                      " WHERE cycle_id = ? AND op_key = ?", (new_request_id, now_iso(), cycle_id, op_key))
            self._stamp_row(c, "operations", cycle_id, op_key)

    def record_existing_operation(self, cycle_id: str, op_key: str, result: dict, note: str) -> dict:
        ts = now_iso()
        stored = redact(jsonable(result))
        with self.tx() as c:
            c.execute("INSERT INTO operations VALUES (?, ?, ?, 'succeeded', 0, ?, ?, ?, ?)",
                      (cycle_id, op_key, "existing-" + secrets.token_hex(12), canonical(stored), note, ts, ts))
            self._stamp_row(c, "operations", cycle_id, op_key)
        return stored

    # ------------------------------------------------------------------ approvers
    @staticmethod
    def _kdf(pin: str, salt: bytes) -> bytes:
        return hashlib.scrypt(pin.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=32)

    def _approver_state_hash(self, row) -> str:
        # jsonable intentionally redacts bytes; encode verifiers explicitly for integrity.
        state = {k: (v.hex() if isinstance(v, bytes) else v) for k, v in dict(row).items()}
        return self._hash("approver-state:v1:" + canonical(state))

    def _require_approver_integrity(self) -> None:
        if not self._key:
            raise AuthError("approver integrity requires an external audit key")
        report = self.verify()
        if not report.ok:
            raise AuthError("approver integrity check failed: " + "; ".join(report.problems))

    def _record_approver_state(self, c, approver_id: str) -> None:
        row = c.execute("SELECT * FROM approvers WHERE approver_id = ?", (approver_id,)).fetchone()
        cycle = "approver-security"
        c.execute("INSERT OR IGNORE INTO cycles VALUES (?, ?, 'admin', 'identity-store', ?, ?, 'none')",
                  (cycle, now_iso(), "0" * 64, code_fingerprint()))
        self._append_audit(c, cycle_id=cycle, act="identity", actor="identity-store",
                           event="approver_state", reason=f"Authenticated state for {approver_id}.",
                           obligation_id=None,
                           data={"approver_id": approver_id, "state_hash": self._approver_state_hash(row)})

    def enroll_approver(self, approver_id: str, display_name: str, roles: Iterable[str], pin: str,
                        *, created_by: str) -> Approver:
        roles = frozenset(roles)
        if not APPROVER_ID.fullmatch(approver_id or ""):
            raise AuthError("approver id must be 3-64 characters of a-z, 0-9, '.', '_' or '-'")
        if self.get_approver(approver_id):
            raise AuthError(f"approver {approver_id} already exists")
        if not roles or not roles <= ROLES:
            raise AuthError(f"roles must be a non-empty subset of {sorted(ROLES)}")
        _check_pin_policy(pin)
        salt = secrets.token_bytes(16)
        with self.tx() as c:
            self._require_approver_integrity()
            c.execute("INSERT INTO approvers (approver_id, display_name, roles, kdf, salt, pin_hash, created_at, created_by)"
                      " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                      (approver_id, display_name, json.dumps(sorted(roles)), KDF, salt, self._kdf(pin, salt),
                       now_iso(), created_by))
            self._record_approver_state(c, approver_id)
        return Approver(approver_id, display_name, roles, True)

    def set_approver_active(self, approver_id: str, active: bool) -> None:
        with self.tx() as c:
            self._require_approver_integrity()
            if c.execute("UPDATE approvers SET active = ? WHERE approver_id = ?",
                         (1 if active else 0, approver_id)).rowcount != 1:
                raise AuthError(f"unknown approver {approver_id}")
            self._record_approver_state(c, approver_id)

    def get_approver(self, approver_id: str) -> Approver | None:
        with self.tx(read_only=True):
            self._require_approver_integrity()
            row = self.conn.execute("SELECT * FROM approvers WHERE approver_id = ?", (approver_id,)).fetchone()
            if not row:
                return None
            return Approver(row["approver_id"], row["display_name"], frozenset(json.loads(row["roles"])), bool(row["active"]))

    def list_approvers(self) -> list[Approver]:
        with self.tx(read_only=True):
            self._require_approver_integrity()
            rows = self.conn.execute("SELECT * FROM approvers ORDER BY approver_id").fetchall()
            return [Approver(r["approver_id"], r["display_name"], frozenset(json.loads(r["roles"])), bool(r["active"]))
                    for r in rows]

    def authenticate(self, approver_id: str, pin: str) -> Approver:
        """Constant-time PIN check with lockout. Unknown ids and wrong PINs fail the same way,
        and account state is only revealed to a correct PIN: a wrong PIN on a deactivated or
        locked account returns the same generic error as an unknown id, so the error message
        cannot be used to enumerate accounts or their state."""
        # The failure is raised AFTER the transaction commits: raising inside the
        # block would roll back the failed-attempt count and the lockout would never land.
        failure: str | None = None
        with self.tx() as c:
            self._require_approver_integrity()
            row = c.execute("SELECT * FROM approvers WHERE approver_id = ?", (approver_id,)).fetchone()
            if row is None:
                self._kdf(pin or "", secrets.token_bytes(16))  # equalise timing
                failure = "approver id or PIN is incorrect"
            else:
                ok = hmac.compare_digest(self._kdf(pin or "", row["salt"]), row["pin_hash"])
                if not ok:
                    failed = row["failed_attempts"] + 1
                    c.execute("UPDATE approvers SET failed_attempts = ?, locked_until = ? WHERE approver_id = ?",
                              (failed, _lockout_until(failed), approver_id))
                    self._record_approver_state(c, approver_id)
                    failure = "approver id or PIN is incorrect"
                elif not row["active"]:
                    failure = "approver is deactivated"
                elif row["locked_until"] and datetime.fromisoformat(row["locked_until"]) > datetime.now(timezone.utc):
                    failure = "approver is locked after repeated failed passcodes; try later"
                else:
                    c.execute("UPDATE approvers SET failed_attempts = 0, locked_until = NULL WHERE approver_id = ?",
                              (approver_id,))
                    self._record_approver_state(c, approver_id)
        if failure is not None:
            raise AuthError(failure)
        return Approver(row["approver_id"], row["display_name"], frozenset(json.loads(row["roles"])), True)

    # ------------------------------------------------------------------ approvals
    def save_approval(self, cycle_id: str, req) -> None:
        exists = self.conn.execute("SELECT 1 FROM approvals WHERE id = ?", (req.id,)).fetchone()
        with self.tx() as c:
            if not exists:
                c.execute(
                    "INSERT INTO approvals (id, cycle_id, kind, obligation_id, action, amount, currency, counterparty,"
                    " destination, destination_fp, sell_currency, max_sell_amount, evidence, explanation, digest,"
                    " requested_by, created_at, expires_at, status, decided_by, decided_at, superseded_by,"
                    " consumed_ref) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (req.id, cycle_id, req.kind, req.obligation_id, req.action, format(req.amount, "f"), req.currency,
                     req.counterparty, req.destination, req.destination_fp, req.sell_currency,
                     None if req.max_sell_amount is None else format(req.max_sell_amount, "f"),
                     json.dumps(list(req.evidence)), req.explanation, req.digest, req.requested_by,
                     req.created_at.isoformat(), req.expires_at.isoformat(), req.status.value, req.decided_by,
                     req.decided_at.isoformat() if req.decided_at else None, req.superseded_by, req.consumed_ref))
            else:
                c.execute("UPDATE approvals SET status = ?, decided_by = ?, decided_at = ?, superseded_by = ?,"
                          " consumed_ref = ? WHERE id = ?",
                          (req.status.value, req.decided_by, req.decided_at.isoformat() if req.decided_at else None,
                           req.superseded_by, req.consumed_ref, req.id))
            self._stamp_row(c, "approvals", req.id, cycle_id=cycle_id)

    def approval_rows(self, cycle_id: str | None = None) -> list[dict]:
        sql = "SELECT * FROM approvals WHERE (?1 IS NULL OR cycle_id = ?1) ORDER BY created_at"
        return [dict(r) for r in self.conn.execute(sql, (cycle_id,)).fetchall()]

    # ------------------------------------------------------------------ resume state (item 03)
    def save_deferral(self, cycle_id: str, obligation_id: int, deferred_until: datetime) -> None:
        with self.tx() as c:
            c.execute(
                "INSERT INTO deferrals (cycle_id, obligation_id, deferred_until, updated_at)"
                " VALUES (?, ?, ?, ?) ON CONFLICT(cycle_id, obligation_id) DO UPDATE SET"
                " deferred_until = excluded.deferred_until, updated_at = excluded.updated_at",
                (cycle_id, obligation_id, deferred_until.isoformat(), now_iso()))

    def clear_deferral(self, cycle_id: str, obligation_id: int) -> None:
        with self.tx() as c:
            c.execute("DELETE FROM deferrals WHERE cycle_id = ? AND obligation_id = ?",
                      (cycle_id, obligation_id))

    def deferral_rows(self, cycle_id: str) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM deferrals WHERE cycle_id = ? ORDER BY obligation_id", (cycle_id,)).fetchall()]

    def save_cycle_state(self, cycle_id: str, autonomous_executed: Decimal) -> None:
        with self.tx() as c:
            c.execute(
                "INSERT INTO cycle_state (cycle_id, autonomous_executed, updated_at) VALUES (?, ?, ?)"
                " ON CONFLICT(cycle_id) DO UPDATE SET autonomous_executed = excluded.autonomous_executed,"
                " updated_at = excluded.updated_at",
                (cycle_id, format(autonomous_executed, "f"), now_iso()))

    def cycle_state(self, cycle_id: str) -> Decimal | None:
        row = self.conn.execute(
            "SELECT autonomous_executed FROM cycle_state WHERE cycle_id = ?", (cycle_id,)).fetchone()
        return Decimal(row["autonomous_executed"]) if row else None

    def save_payout_state(self, cycle_id: str, autonomous_paid: Decimal) -> None:
        with self.tx() as c:
            c.execute(
                "INSERT INTO payout_state (cycle_id, autonomous_paid, updated_at) VALUES (?, ?, ?)"
                " ON CONFLICT(cycle_id) DO UPDATE SET autonomous_paid = excluded.autonomous_paid,"
                " updated_at = excluded.updated_at",
                (cycle_id, format(autonomous_paid, "f"), now_iso()))

    def payout_state(self, cycle_id: str) -> Decimal | None:
        row = self.conn.execute(
            "SELECT autonomous_paid FROM payout_state WHERE cycle_id = ?", (cycle_id,)).fetchone()
        return Decimal(row["autonomous_paid"]) if row else None

    # ------------------------------------------------------------------ payees
    def get_payee(self, payee_key: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM payees WHERE payee_key = ?", (payee_key,)).fetchone()
        return dict(row) if row else None

    def _write_audit(self, c, audit) -> dict:
        """A payee change and its record commit together, or neither does. Kept mandatory: a
        destination moved with no chained event is a redirect nothing later can be reconstructed from."""
        if not isinstance(audit, dict):
            raise StoreError("a payee change must carry its audit event: the record belongs in the "
                             "same transaction as the destination")
        return self._append_audit(c, cycle_id=audit["cycle_id"], act=audit.get("act", "setup"),
                                  actor=audit["actor"], event=audit["event"], reason=audit["reason"],
                                  obligation_id=audit.get("obligation_id"), data=audit.get("data") or {})

    def pin_payee(self, payee_key: str, fingerprint: str, masked: str, *, pinned_by: str,
                  approval_id: str | None, audit) -> dict:
        with self.tx() as c:
            cur = c.execute("INSERT INTO payee_history (payee_key, old_fingerprint, new_fingerprint, changed_at,"
                            " changed_by, reason) VALUES (?, NULL, ?, ?, ?, ?)",
                            (payee_key, fingerprint, now_iso(), pinned_by, f"first payment approved ({approval_id})"))
            history_id = cur.lastrowid
            c.execute("INSERT INTO payees VALUES (?, ?, ?, ?, ?, ?)",
                      (payee_key, fingerprint, masked, now_iso(), pinned_by, approval_id))
            out = self._write_audit(c, audit)
            self._stamp_row(c, "payees", payee_key, cycle_id=audit["cycle_id"])
            self._stamp_row(c, "payee_history", payee_key, history_id, cycle_id=audit["cycle_id"])
            return out

    def repin_payee(self, payee_key: str, fingerprint: str, masked: str, *, changed_by: str, reason: str,
                    audit) -> dict:
        with self.tx() as c:
            old = c.execute("SELECT fingerprint FROM payees WHERE payee_key = ?", (payee_key,)).fetchone()
            cur = c.execute("INSERT INTO payee_history (payee_key, old_fingerprint, new_fingerprint, changed_at,"
                            " changed_by, reason) VALUES (?, ?, ?, ?, ?, ?)",
                            (payee_key, old["fingerprint"] if old else None, fingerprint, now_iso(), changed_by,
                             reason))
            history_id = cur.lastrowid
            if old:
                c.execute("DELETE FROM payees WHERE payee_key = ?", (payee_key,))
            c.execute("INSERT INTO payees VALUES (?, ?, ?, ?, ?, NULL)",
                      (payee_key, fingerprint, masked, now_iso(), changed_by))
            out = self._write_audit(c, audit)
            self._stamp_row(c, "payees", payee_key, cycle_id=audit["cycle_id"])
            self._stamp_row(c, "payee_history", payee_key, history_id, cycle_id=audit["cycle_id"])
            return out

    # ------------------------------------------------------------------ payouts
    # An invoice, not an invoice-and-figure, is what may only be paid once. The amount is a property
    # of the reservation: changing it must not free the lock or read as a different obligation.
    def reserve_payout(self, *, request_id: str, cycle_id: str, obligation_id: int, payee_fingerprint: str,
                       reference: str, currency: str, amount) -> None:
        ts = now_iso()
        try:
            with self.tx() as c:
                c.execute("INSERT INTO payouts (request_id, cycle_id, obligation_id, payee_fingerprint, reference,"
                          " currency, amount, transfer_id, status, created_at, updated_at)"
                          " VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 'initiated', ?, ?)",
                          (request_id, cycle_id, obligation_id, payee_fingerprint, reference, currency,
                           format(Decimal(amount), "f"), ts, ts))
                self._stamp_row(c, "payouts", request_id)
        except sqlite3.IntegrityError as exc:
            row = self.conn.execute(
                "SELECT * FROM payouts WHERE payee_fingerprint = ? AND reference = ? AND currency = ?"
                " AND status NOT IN ('failed', 'cancelled')",
                (payee_fingerprint, reference, currency)).fetchone()
            if row and row["request_id"] == request_id:
                return  # our own reservation (retry of the same operation)
            raise DuplicatePayout("a live payout for this invoice already exists", dict(row) if row else {}) from exc

    def live_payout(self, *, payee_fingerprint: str, reference: str, currency: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM payouts WHERE payee_fingerprint = ? AND reference = ? AND currency = ?"
            " AND status NOT IN ('failed', 'cancelled')",
            (payee_fingerprint, reference, currency)).fetchone()
        return dict(row) if row else None

    def update_payout(self, request_id: str, *, status: str, transfer_id: str | None = None,
                      note: str | None = None) -> None:
        with self.tx() as c:
            c.execute("UPDATE payouts SET status = ?, transfer_id = COALESCE(transfer_id, ?),"
                      " note = COALESCE(?, note), updated_at = ? WHERE request_id = ?",
                      (status, transfer_id, note, now_iso(), request_id))
            self._stamp_row(c, "payouts", request_id)

    def rekey_payout(self, old_request_id: str, new_request_id: str, *, note: str) -> None:
        """A transfer was rejected outright: close the old reservation and open an identical one under a
        new request id in one transaction, so the invoice is never unlocked in between."""
        with self.tx() as c:
            row = c.execute("SELECT * FROM payouts WHERE request_id = ?", (old_request_id,)).fetchone()
            if row is None or row["status"] != "initiated":
                raise StoreError(f"payout {old_request_id} is not an open reservation")
            c.execute("UPDATE payouts SET status = 'failed', note = ?, updated_at = ? WHERE request_id = ?",
                      (note, now_iso(), old_request_id))
            c.execute("INSERT INTO payouts (request_id, cycle_id, obligation_id, payee_fingerprint, reference,"
                      " currency, amount, transfer_id, status, note, created_at, updated_at)"
                      " VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 'initiated', ?, ?, ?)",
                      (new_request_id, row["cycle_id"], row["obligation_id"], row["payee_fingerprint"],
                       row["reference"], row["currency"], row["amount"], f"replaces {old_request_id}",
                       now_iso(), now_iso()))
            self._stamp_row(c, "payouts", old_request_id)
            self._stamp_row(c, "payouts", new_request_id)

    def release_payout(self, request_id: str, *, note: str) -> dict:
        """Close a reservation that provably moved no money (checked on Airwallex by a person)."""
        with self.tx() as c:
            row = c.execute("SELECT * FROM payouts WHERE request_id = ?", (request_id,)).fetchone()
            if row is None or row["status"] != "initiated" or row["transfer_id"]:
                raise StoreError(f"payout {request_id} is not an open reservation without a transfer")
            c.execute("UPDATE payouts SET status = 'cancelled', note = ?, updated_at = ? WHERE request_id = ?",
                      (note, now_iso(), request_id))
            self._stamp_row(c, "payouts", request_id)
        return dict(row)

    def payout(self, request_id: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM payouts WHERE request_id = ?", (request_id,)).fetchone()
        return dict(row) if row else None

    def payouts(self, cycle_id: str | None = None) -> list[dict]:
        sql = "SELECT * FROM payouts WHERE (?1 IS NULL OR cycle_id = ?1) ORDER BY created_at"
        return [dict(r) for r in self.conn.execute(sql, (cycle_id,)).fetchall()]

    # ------------------------------------------------------------------ snapshots
    def save_snapshot(self, cycle_id: str, act: str, data: dict) -> None:
        with self.tx() as c:
            c.execute("INSERT INTO snapshots (cycle_id, act, ts, data) VALUES (?, ?, ?, ?)",
                      (cycle_id, act, now_iso(), canonical(redact(jsonable(data)))))

    # ------------------------------------------------------------------ backup
    def backup(self, dest: Path | str) -> Path:
        """Consistent online copy (SQLite backup API), owner-only. Verify it before shipping it to
        write-once storage; the copy is chained with the same key."""
        dest = Path(dest)
        if dest.exists():
            raise StoreError(f"{dest} already exists; backups are never overwritten")
        dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.close(os.open(dest, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
        target = sqlite3.connect(str(dest))
        try:
            self.conn.backup(target)
            target.execute("PRAGMA journal_mode = DELETE")  # a single self-contained file
        finally:
            target.close()
        return dest

    # ------------------------------------------------------------------ verification
    def head(self) -> dict:
        """The latest (seq, entry_hash): record it OUTSIDE this machine to anchor the chain."""
        row = self.conn.execute("SELECT seq, entry_hash, ts FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        return {"seq": row["seq"], "entry_hash": row["entry_hash"], "ts": row["ts"]} if row else \
            {"seq": 0, "entry_hash": GENESIS, "ts": None}

    def verify(self, anchors: Iterable[dict] = ()) -> VerifyReport:
        """Check integrity, schema protections, the hash chain and approval digests. ``anchors`` are
        heads exported earlier (``head()``); each must still be in the chain, which also detects a
        truncated tail even if the attacker reset the sequence counter."""
        problems: list[str] = []
        pending: list[str] = []
        integrity = self.conn.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            problems.append(f"sqlite integrity_check: {integrity}")
        fk = self.conn.execute("PRAGMA foreign_key_check").fetchall()
        if fk:
            problems.append(f"{len(fk)} foreign-key violations")
        live_sql = {r["name"]: _normalized_sql(r["sql"]) for r in self.conn.execute(
            "SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'")}
        missing = sorted(set(EXPECTED_SCHEMA) - set(live_sql))
        lost_triggers = sorted(n for n in missing if n in EXPECTED_TRIGGERS)
        if lost_triggers:
            problems.append(f"protective triggers missing: {lost_triggers}")
        if other_missing := sorted(set(missing) - set(lost_triggers)):
            problems.append(f"schema objects missing: {other_missing}")
        if rewritten := sorted(n for n in set(EXPECTED_SCHEMA) & set(live_sql)
                               if EXPECTED_SCHEMA[n] != live_sql[n]):
            problems.append(f"protective schema rewritten: {rewritten}")
        if extra := sorted(set(live_sql) - set(EXPECTED_SCHEMA)):
            problems.append(f"unrecognised schema objects: {extra}")

        prev, expected_seq, count = GENESIS, None, 0
        approver_states = {}
        row_states: dict[str, str] = {}
        for row in self.conn.execute("SELECT * FROM audit_log ORDER BY seq"):
            count += 1
            if expected_seq is not None and row["seq"] != expected_seq:
                problems.append(f"audit gap: expected seq {expected_seq}, found {row['seq']} (rows deleted?)")
            expected_seq = row["seq"] + 1
            if row["prev_hash"] != prev:
                problems.append(f"audit seq {row['seq']}: prev_hash does not link to the previous entry")
            entry = {"cycle_id": row["cycle_id"], "ts": row["ts"], "act": row["act"], "actor": row["actor"],
                     "event": row["event"], "reason": row["reason"], "obligation_id": row["obligation_id"],
                     "data": json.loads(row["data"]), "prev_hash": row["prev_hash"]}
            if not hmac.compare_digest(self._hash(canonical(entry)), row["entry_hash"]):
                problems.append(f"audit seq {row['seq']}: entry hash mismatch (edited or forged)")
            if row["event"] == "approver_state":
                approver_states[entry["data"].get("approver_id")] = entry["data"].get("state_hash")
            elif row["event"] in _STATE_EVENTS:
                key = entry["data"].get("key")
                if key is None:
                    problems.append(f"audit seq {row['seq']}: {row['event']} entry has no row key")
                else:
                    row_states[key] = entry["data"].get("state_hash")
            prev = row["entry_hash"]
        first = self.conn.execute("SELECT MIN(seq) AS s FROM audit_log").fetchone()["s"]
        seq_row = self.conn.execute("SELECT seq FROM sqlite_sequence WHERE name = 'audit_log'").fetchone()
        if first not in (None, 1):
            problems.append(f"audit log starts at seq {first}: earliest rows were deleted")
        if seq_row and count and seq_row["seq"] != expected_seq - 1:
            problems.append("audit log tail was truncated (sequence counter is ahead of the last row)")

        for anchor in anchors:
            row = self.conn.execute("SELECT entry_hash FROM audit_log WHERE seq = ?", (int(anchor["seq"]),)).fetchone()
            if row is None:
                problems.append(f"anchored entry seq {anchor['seq']} is missing (log truncated or replaced)")
            elif not hmac.compare_digest(row["entry_hash"], str(anchor["entry_hash"])):
                problems.append(f"anchored entry seq {anchor['seq']} has a different hash (log rewritten)")

        for row in self.conn.execute("SELECT * FROM approvers"):
            expected = approver_states.pop(row["approver_id"], None)
            if expected is None:
                pending.append(f"approver {row['approver_id']}: no authenticated state; "
                               "legacy records require trusted re-enrollment")
            elif not isinstance(expected, str) or not hmac.compare_digest(self._approver_state_hash(row), expected):
                problems.append(f"approver {row['approver_id']}: state integrity mismatch")
        if approver_states:
            problems.append("authenticated approver records were deleted")

        from approvals import compute_digest  # local import: approvals does not depend on the store
        for row in self.conn.execute("SELECT * FROM approvals"):
            fields = {"id": row["id"], "kind": row["kind"], "obligation_id": row["obligation_id"],
                      "action": row["action"], "amount": row["amount"], "currency": row["currency"],
                      "counterparty": row["counterparty"], "destination_fp": row["destination_fp"],
                      "sell_currency": row["sell_currency"], "max_sell_amount": row["max_sell_amount"],
                      "evidence": json.loads(row["evidence"]), "requested_by": row["requested_by"],
                      "expires_at": row["expires_at"]}
            if compute_digest(fields) != row["digest"]:
                problems.append(f"approval {row['id']}: stored terms no longer match the digest shown")

        for table in STATE_TABLES:
            for row in self.conn.execute(_ROW_ALL[table]):
                key = self._row_state_key(table, row)
                expected = row_states.pop(key, None)
                if expected is None:
                    pending.append(f"{table} {key}: no authenticated state")
                elif not isinstance(expected, str) or not hmac.compare_digest(
                        self._row_state_hash(table, row), expected):
                    problems.append(f"{table} {key}: row state integrity mismatch (record rewritten)")
        if row_states:
            problems.append(f"authenticated {', '.join(STATE_TABLES)} states were deleted")
        return VerifyReport(ok=not problems and not pending, entries=count, head_hash=prev,
                            chain=self._meta("audit_chain") or "?", problems=problems, pending=pending)


def _split_sql(script: str) -> list[str]:
    """Split the schema on statement boundaries, keeping trigger bodies intact."""
    statements, buf, in_trigger = [], [], False
    for line in script.splitlines():
        if not line.strip():
            continue
        buf.append(line)
        stripped = line.strip()
        if stripped.startswith("CREATE TRIGGER"):
            in_trigger = True
        if (in_trigger and stripped.endswith("END;")) or (not in_trigger and stripped.endswith(";")):
            statements.append("\n".join(buf))
            buf, in_trigger = [], False
    if buf:
        raise StoreError("schema has an unterminated statement")
    return statements


def _normalized_sql(text: str) -> str:
    """DDL compared ignoring layout and case: SQLite re-writes sqlite_master.sql its own way, and
    what must match is the protection the statement expresses, not its indentation."""
    return re.sub(r"\s+", " ", text).strip().rstrip(";").upper()


# Every object this program creates, by name, as the DDL that creates it. sqlite_master is the
# authority on what guards a row, so a trigger recreated under its own name as `BEGIN SELECT 1; END`
# is a rewrite to be reported, not a name to be counted.
EXPECTED_SCHEMA = {}
# The statements verbatim as well: re-creating an object from the normalized text would rewrite
# quoted literals ('failed', 'cancelled') to upper case and silently change what the guard matches.
SCHEMA_STATEMENTS = {}
for _statement in _split_sql(SCHEMA):
    _words = _statement.split()
    _name = _words[3] if _words[1] == "UNIQUE" else _words[2]
    EXPECTED_SCHEMA[_name] = _normalized_sql(_statement)
    SCHEMA_STATEMENTS[_name] = _statement
