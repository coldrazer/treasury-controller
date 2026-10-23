"""Wiring shared by demo.py, manage.py and smoke tests: where the database lives and how it is keyed.

Live runs use one persistent database, ``state/treasury.db``, and refuse to start without
``TREASURY_AUDIT_KEY`` (fail closed: an unkeyed chain could be recomputed by anyone who can
write the file). Mock runs use a fresh database per run under ``state/mock/`` so that the
database's one-payout-per-invoice rule does not block repeated demo runs; if no key is set
they use a demo key stored next to the mock databases (fake money only).
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from config import Settings
from screening import ListScreener
from store import Store, StoreError, generate_audit_key, load_audit_key

LIVE_DB_NAME = "treasury.db"


def new_cycle_id(prefix: str = "") -> str:
    return prefix + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:6]


def live_db_path(settings: Settings) -> Path:
    return settings.state_dir / LIVE_DB_NAME


def _demo_key(settings: Settings) -> bytes:
    path = settings.state_dir / "mock" / "demo-audit.key"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not path.exists():
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(generate_audit_key())
    return load_audit_key(path.read_text().strip())


def audit_key(settings: Settings, *, mode: str) -> bytes:
    key = load_audit_key(settings.audit_key)
    if key:
        return key
    if mode == "mock":
        return _demo_key(settings)
    raise StoreError("TREASURY_AUDIT_KEY is required outside mock mode (create one with: "
                     "python manage.py gen-key, and keep it outside this machine's state folder)")


def open_store(settings: Settings, *, mode: str, cycle_id: str | None = None, read_only: bool = False,
               path: Path | None = None) -> Store:
    if path is None:
        path = settings.state_dir / "mock" / f"{cycle_id}.db" if mode == "mock" else live_db_path(settings)
    return Store(path, audit_key=audit_key(settings, mode=mode), read_only=read_only)


def make_screener(settings: Settings) -> ListScreener | None:
    if settings.screening_list is None:
        return None
    if not Path(settings.screening_list).is_file():
        raise StoreError(f"screening list not found: {settings.screening_list} "
                         "(set TREASURY_SCREENING_LIST, or 'off' to disable)")
    return ListScreener(settings.screening_list)
