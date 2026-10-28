#!/usr/bin/env python3
"""Administration for the treasury database: keys, approvers, payee pins, audit verification.

    python manage.py gen-key                          # new TREASURY_AUDIT_KEY (store it in a secrets manager)
    python manage.py add-approver --bootstrap --id dana.controller --name "Dana Reyes" --roles finance_controller
    python manage.py add-approver --by dana.controller --id sam.treasury --name "Sam Ortiz" --roles treasury_approver
    python manage.py list-approvers --by dana.controller
    python manage.py deactivate-approver --by dana.controller --id sam.treasury
    python manage.py pin-payee --by dana.controller --obligation 2 --reason "IBAN confirmed by call-back to +49 ..." --confirm-account DE89370400440532013000
    python manage.py list-payouts --by dana.controller
    python manage.py release-payout --by dana.controller --request-id <id> --reason "no transfer on Airwallex"
    python manage.py verify-audit [--anchors anchors.jsonl]        # integrity facts only, no PIN
    python manage.py anchor --append /secure/elsewhere/anchors.jsonl
    python manage.py export-audit --by dana.controller --out audit-export/
    python manage.py backup --by dana.controller --out /backups/treasury-2026-10-18.db

Every change made here is authenticated (approver id + PIN; a finance controller for access and
payee changes) and written to the same hash-chained audit log as the agent's own actions. So is
every read that discloses or copies ledger data (list-approvers, list-payouts, export-audit, backup),
which therefore also refuses a database whose own record shows tampering. ``verify-audit`` and
``anchor`` are the exception on purpose: they are how a suspected forgery is inspected, they disclose
only integrity facts (entry count, head hash, problems), and they must keep working when a writer
is refused.
``--db`` points at another database (e.g. a mock run under state/mock/).
PINs are read from the terminal; for scripted use set TREASURY_ADMIN_PIN / TREASURY_NEW_PIN.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from agent import account_fields, masked_account, payee_key
from config import DEFAULT_POLICY, ConfigError, load_settings
from policy import policy_fingerprint
from runtime import audit_key, live_db_path, new_cycle_id
from simulation import load_scenario
from store import ROLES, AuthError, Store, StoreError, canonical, generate_audit_key

ADMIN_ROLE = "finance_controller"


def _pin(env_var: str, prompt: str, *, confirm: bool = False) -> str:
    if os.environ.get(env_var):
        return os.environ[env_var]
    pin = getpass.getpass(prompt)
    if confirm and getpass.getpass("Repeat PIN: ") != pin:
        raise AuthError("PINs do not match")
    return pin


def _open(args, settings, *, read_only: bool = False) -> Store:
    path = Path(args.db) if args.db else live_db_path(settings)
    mock_dir = (settings.state_dir / "mock").resolve()
    mode = "mock" if path.resolve().parent == mock_dir else "live"
    if read_only and not path.is_file():
        raise StoreError(f"no database at {path}")
    return Store(path, audit_key=audit_key(settings, mode=mode), read_only=read_only)


def _admin_cycle(store: Store, actor: str) -> str:
    cycle = new_cycle_id("admin-")
    store.start_cycle(cycle, mode="admin", operator=actor, policy_fingerprint=policy_fingerprint(DEFAULT_POLICY),
                      model="none")
    return cycle


def _authorise(store: Store, approver_id: str, role: str | None = ADMIN_ROLE):
    try:
        who = store.authenticate(approver_id, _pin("TREASURY_ADMIN_PIN", f"PIN for {approver_id}: "))
    except AuthError as exc:
        cycle = _admin_cycle(store, f"unauthenticated:{approver_id}")
        store.append_audit(cycle_id=cycle, act="admin", actor=f"unauthenticated:{approver_id}",
                           event="admin_auth_failed", reason=str(exc), obligation_id=None, data={})
        raise
    if role and role not in who.roles:
        _audit(store, f"approver:{who.approver_id}", "admin_refused", f"{who.approver_id} is not a {role}")
        raise AuthError(f"{approver_id} is not a {role}")
    return who


def _reader(store: Store, args) -> str:
    """Listing, exporting or copying the ledger is itself an audited action, so it signs in first:
    the audit trail has to say whose hands the data passed through, not just that a file was read."""
    if not getattr(args, "by", None):
        raise AuthError("--by <approver id> is required: reading or copying ledger data is authenticated "
                        "and audited")
    return _authorise(store, args.by, role=None).approver_id


def _draft(store: Store, actor: str, event: str, reason: str, **data) -> dict:
    """An audit record for a change the store commits inside its own transaction."""
    return {"cycle_id": _admin_cycle(store, actor), "act": "admin", "actor": actor, "event": event,
            "reason": reason, "obligation_id": data.pop("obligation_id", None), "data": data}


def _audit(store: Store, actor: str, event: str, reason: str, **data) -> None:
    draft = _draft(store, actor, event, reason, **data)
    store.append_audit(cycle_id=draft["cycle_id"], act=draft["act"], actor=draft["actor"],
                       event=draft["event"], reason=draft["reason"], obligation_id=draft["obligation_id"],
                       data=draft["data"])


# ---------------------------------------------------------------------------
def cmd_gen_key(args, settings) -> int:
    print(generate_audit_key())
    print("Store this as TREASURY_AUDIT_KEY in your secrets manager. Do not keep it next to the database:\n"
          "anyone holding both can rewrite the audit chain. Losing it means the log can no longer be verified.",
          file=sys.stderr)
    return 0


def cmd_add_approver(args, settings) -> int:
    roles = {r.strip() for r in args.roles.split(",") if r.strip()}
    if not roles <= ROLES:
        raise AuthError(f"unknown role(s) {sorted(roles - ROLES)}; choose from {sorted(ROLES)}")
    with _open(args, settings) as store:
        if args.bootstrap:
            if store.list_approvers():
                raise AuthError("approvers already exist; an existing finance controller must add new ones (--by)")
            if ADMIN_ROLE not in roles:
                raise AuthError("the first approver must be a finance_controller")
            actor = f"bootstrap:{settings.operator}"
        else:
            if not args.by:
                raise AuthError("--by <finance controller id> is required")
            if args.by == args.id:
                raise AuthError("segregation of duties: nobody can enrol themselves")
            actor = f"approver:{_authorise(store, args.by).approver_id}"
        pin = _pin("TREASURY_NEW_PIN", f"New PIN for {args.id}: ", confirm=True)
        store.enroll_approver(args.id, args.name, roles, pin, created_by=actor)
        _audit(store, actor, "approver_enrolled", f"{args.id} enrolled with roles {sorted(roles)}.",
               approver_id=args.id, roles=sorted(roles))
    print(f"enrolled {args.id} ({', '.join(sorted(roles))})")
    return 0


def cmd_list_approvers(args, settings) -> int:
    with _open(args, settings) as store:
        actor = f"approver:{_reader(store, args)}"
        approvers = store.list_approvers()
        _audit(store, actor, "roster_read", f"{len(approvers)} approver records listed.")
    for a in approvers:
        print(f"{a.approver_id:<24} {'active' if a.active else 'INACTIVE':<9} {','.join(sorted(a.roles)):<40} "
              f"{a.display_name}")
    return 0


def cmd_deactivate_approver(args, settings) -> int:
    with _open(args, settings) as store:
        if args.by == args.id:
            raise AuthError("use another finance controller to deactivate this account")
        actor = f"approver:{_authorise(store, args.by).approver_id}"
        store.set_approver_active(args.id, False)
        _audit(store, actor, "approver_deactivated", f"{args.id} deactivated: {args.reason}", approver_id=args.id)
    print(f"deactivated {args.id}")
    return 0


def _show_pin_change(ob, previous, fields, new_fp, bank_name=None) -> None:
    """Full new details next to what was pinned before. The old full number is not
    stored (only its fingerprint and masked form), so the fingerprint is what proves
    the destination changed; the new number is shown in full so the controller reads
    it, not just its last 4."""
    acct = fields["iban"] or fields["account_number"]
    label = "IBAN" if fields["iban"] else "account number"
    print(f"pinning {ob.counterparty} ({ob.name}):")
    if previous is None:
        print("  previous: none (first pin for this payee)")
    else:
        print(f"  previous: {previous['masked']} (fingerprint {previous['fingerprint'][:12]})")
    bank = f" · {bank_name}" if bank_name else ""
    print(f"  new: {label} {acct}{bank} · BIC {fields['swift_code']} · {fields['account_currency']} "
          f"(fingerprint {new_fp[:12]})")
    if previous is not None:
        print("  change: the pinned account fingerprint differs; this is a NEW destination, "
              "not the one pinned before.")


def _confirm_new_account(fields, args) -> None:
    """The controller types the new account number before a new or changed pin
    commits. A swapped account sharing the old last 4 must not survive a glance at
    a masked line, and a call-back that only confirms the last 4 is not enough."""
    acct = fields["iban"] or fields["account_number"]
    label = "IBAN" if fields["iban"] else "account number"
    typed = (getattr(args, "confirm_account", None) or "").replace(" ", "").upper()
    if not typed:
        if not sys.stdin.isatty():
            raise AuthError("refusing to pin a new or changed account without --confirm-account "
                            "(not a terminal, so no prompt is possible)")
        typed = input(f"Type the new {label} to confirm: ").replace(" ", "").upper()
    if typed != acct:
        raise AuthError("confirmation does not match the new account number; pin refused")


def cmd_pin_payee(args, settings) -> int:
    if len(args.reason.strip()) < 10:
        raise AuthError("--reason must say how the account was verified (at least 10 characters)")
    scenario = load_scenario(Path(args.scenario) if args.scenario else None)
    ob = next((o for o in scenario.obligations if o.id == args.obligation), None)
    spec = scenario.payouts.get(args.obligation)
    if ob is None or not spec:
        raise StoreError(f"obligation {args.obligation} has no beneficiary details in the scenario")
    fields = account_fields(spec["beneficiary"]["beneficiary"]["bank_details"])
    with _open(args, settings) as store:
        actor_id = _authorise(store, args.by).approver_id
        masked = masked_account(fields)
        previous = store.get_payee(payee_key(ob))
        new_fp = store.fingerprint("payee-account", fields)
        if previous is None or previous["fingerprint"] != new_fp:
            _show_pin_change(ob, previous, fields, new_fp,
                             bank_name=spec["beneficiary"]["beneficiary"]["bank_details"].get("bank_name"))
            _confirm_new_account(fields, args)
        store.repin_payee(payee_key(ob), new_fp, masked,
                          changed_by=actor_id, reason=args.reason.strip(),
                          audit=_draft(store, f"approver:{actor_id}", "payee_pinned",
                                       f"{ob.counterparty} pinned to {masked}"
                                       + (f" (was {previous['masked']})" if previous else "")
                                       + f": {args.reason.strip()}",
                                       obligation_id=ob.id, destination=masked,
                                       fingerprint=new_fp,
                                       previous_fingerprint=previous["fingerprint"] if previous else None))
    print(f"pinned {ob.counterparty} → {masked}")
    return 0


def cmd_list_payouts(args, settings) -> int:
    with _open(args, settings) as store:
        actor = f"approver:{_reader(store, args)}"
        rows = store.payouts()
        _audit(store, actor, "payouts_read", f"{len(rows)} payout reservations listed.")
    for row in rows:
        print(f"{row['request_id']}  {row['status']:<10} #{row['obligation_id']}  {row['currency']} "
              f"{row['amount']:>12}  ref {row['reference']:<16} cycle {row['cycle_id']}  "
              f"transfer {row['transfer_id'] or '-'}  {row['note'] or ''}")
    return 0


def cmd_release_payout(args, settings) -> int:
    """An interrupted run left an invoice locked. After confirming on Airwallex that no transfer exists
    for the request id (and resolving any converted funds), a finance controller releases the lock."""
    if len(args.reason.strip()) < 10:
        raise AuthError("--reason must say how you confirmed nothing was sent (at least 10 characters)")
    with _open(args, settings) as store:
        actor_id = _authorise(store, args.by).approver_id
        row = store.release_payout(args.request_id, note=f"released by {actor_id}: {args.reason.strip()}")
        _audit(store, f"approver:{actor_id}", "payout_released",
               f"Reservation {args.request_id} for invoice {row['reference']} released: {args.reason.strip()}",
               obligation_id=row["obligation_id"], request_id=args.request_id)
    print(f"released {args.request_id}")
    return 0


def _load_anchors(path: str | None) -> list[dict]:
    if not path:
        return []
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def cmd_verify(args, settings) -> int:
    with _open(args, settings, read_only=True) as store:
        report = store.verify(anchors=_load_anchors(args.anchors))
        print(f"database   {store.path}")
        print(f"chain      {report.chain}  ·  {report.entries} entries  ·  head {report.head_hash}")
        if report.ok:
            print("result     OK: integrity, protective triggers, hash chain, approval digests"
                  + (", anchors" if args.anchors else ""))
            return 0
        print("result     FAILED")
        for problem in report.problems:
            print(f"  - {problem}")
        for note in report.pending:
            print(f"  ! {note}")
        return 1


def cmd_anchor(args, settings) -> int:
    with _open(args, settings, read_only=True) as store:
        head = {**store.head(), "db": str(store.path), "anchored_at": datetime.now(timezone.utc).isoformat()}
    line = json.dumps(head, sort_keys=True)
    if args.append:
        with open(args.append, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    print(line)
    return 0


def cmd_export(args, settings) -> int:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    with _open(args, settings) as store:
        actor = f"approver:{_reader(store, args)}"
        report = store.verify()
        tables = {
            "audit_log": store.audit_entries(),
            "cycles": [dict(r) for r in store.conn.execute("SELECT * FROM cycles ORDER BY started_at")],
            "approvals": store.approval_rows(),
            "payouts": store.payouts(),
            "payee_history": [dict(r) for r in store.conn.execute("SELECT * FROM payee_history ORDER BY id")],
            "payees": [dict(r) for r in store.conn.execute("SELECT * FROM payees ORDER BY payee_key")],
            "approvers": [{"approver_id": a.approver_id, "display_name": a.display_name, "roles": sorted(a.roles),
                           "active": a.active} for a in store.list_approvers()],
            "retired_request_ids": [dict(r) for r in store.conn.execute("SELECT * FROM retired_request_ids")],
        }
        files = {}
        for name, rows in tables.items():
            path = out / f"{name}.jsonl"
            body = "".join(canonical(row) + "\n" for row in rows)
            path.write_text(body, encoding="utf-8")
            files[path.name] = {"rows": len(rows), "sha256": hashlib.sha256(body.encode("utf-8")).hexdigest()}
        manifest = {"exported_at": datetime.now(timezone.utc).isoformat(), "exported_by": actor,
                    "database": str(store.path), "chain": report.chain, "head": store.head(),
                    "verified": report.ok, "problems": report.problems, "files": files}
        _audit(store, actor, "audit_exported",
               f"{sum(f['rows'] for f in files.values())} rows exported to {out} "
               f"(chain verified: {report.ok}).", out=str(out), verified=report.ok)
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    print(f"exported {sum(f['rows'] for f in files.values())} rows to {out} (verified: {report.ok})")
    return 0 if report.ok else 1


def cmd_backup(args, settings) -> int:
    with _open(args, settings) as store:
        actor = f"approver:{_reader(store, args)}"
        dest = store.backup(args.out)
        digest = hashlib.sha256(dest.read_bytes()).hexdigest()
        _audit(store, actor, "backup_taken", f"Database copied to {dest}; sha256 {digest}.",
               out=str(dest), sha256=digest)
    with Store(dest, audit_key=store._key, read_only=True) as copy:
        report = copy.verify()
    (dest.parent / (dest.name + ".sha256")).write_text(f"{digest}  {dest.name}\n", encoding="utf-8")
    print(f"backup {dest} · sha256 {digest} · {report.entries} entries · verified: {report.ok}")
    print("Ship it (and the .sha256) to write-once storage (e.g. S3 Object Lock, compliance mode).")
    return 0 if report.ok else 1


# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--db", help="database path (default: state/treasury.db)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("gen-key").set_defaults(fn=cmd_gen_key)
    a = sub.add_parser("add-approver")
    a.add_argument("--id", required=True)
    a.add_argument("--name", required=True)
    a.add_argument("--roles", required=True, help=f"comma-separated: {', '.join(sorted(ROLES))}")
    a.add_argument("--by", help="finance controller authorising the enrolment")
    a.add_argument("--bootstrap", action="store_true", help="enrol the first finance controller in an empty database")
    a.set_defaults(fn=cmd_add_approver)
    la = sub.add_parser("list-approvers", help="list approvers and their roles (audited read)")
    la.add_argument("--by", help="approver signing in for the read (required: reads are audited)")
    la.set_defaults(fn=cmd_list_approvers)
    d = sub.add_parser("deactivate-approver")
    d.add_argument("--id", required=True)
    d.add_argument("--by", required=True)
    d.add_argument("--reason", default="access removed")
    d.set_defaults(fn=cmd_deactivate_approver)
    pp = sub.add_parser("pin-payee", help="pin (or re-pin) a payee's verified bank account")
    pp.add_argument("--obligation", type=int, required=True)
    pp.add_argument("--by", required=True)
    pp.add_argument("--reason", required=True, help="how the account was verified (call-back, signed letter...)")
    pp.add_argument("--scenario", help="scenario JSON (default: fixtures/scenario.json)")
    pp.add_argument("--confirm-account", help="type the new IBAN or account number to confirm "
                                              "a new or changed pin (prompted when omitted)")
    pp.set_defaults(fn=cmd_pin_payee)
    lp = sub.add_parser("list-payouts", help="list payout reservations (audited read)")
    lp.add_argument("--by", help="approver signing in for the read (required: reads are audited)")
    lp.set_defaults(fn=cmd_list_payouts)
    r = sub.add_parser("release-payout", help="release an invoice lock left by an interrupted run")
    r.add_argument("--request-id", required=True)
    r.add_argument("--by", required=True)
    r.add_argument("--reason", required=True, help="how you confirmed on Airwallex that nothing was sent")
    r.set_defaults(fn=cmd_release_payout)
    v = sub.add_parser("verify-audit")
    v.add_argument("--anchors", help="JSONL of heads exported earlier with 'anchor'")
    v.set_defaults(fn=cmd_verify)
    an = sub.add_parser("anchor", help="print the current head (seq + hash) to record outside this machine")
    an.add_argument("--append", help="append the head to this JSONL file")
    an.set_defaults(fn=cmd_anchor)
    b = sub.add_parser("backup", help="consistent, verified copy of the database for off-site retention")
    b.add_argument("--by", help="approver taking the copy (required: copies are audited)")
    b.add_argument("--out", required=True, help="new file path (never overwritten)")
    b.set_defaults(fn=cmd_backup)
    e = sub.add_parser("export-audit")
    e.add_argument("--by", help="approver exporting the ledger (required: exports are audited)")
    e.add_argument("--out", required=True)
    e.set_defaults(fn=cmd_export)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        settings = load_settings()
        return args.fn(args, settings)
    except (ConfigError, StoreError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
