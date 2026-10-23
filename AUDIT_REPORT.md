# Security and Regulatory Controls Audit — Adaptive Treasury Controller

**Scope.** Every source file in this repository (agent, policy, client, persistence, approvals,
screening, admin CLI, demo, mock), its data at rest and its data flows to Airwallex and to the
optional language-model provider. Two passes. Pass 1 found the issues below and fixed them. Pass 2
re-reviewed the fixed code, found four more issues (S16–S19) and fixed those too.
**Date:** 2026-10-19 · **Python:** 3.11 and 3.13 · **Runtime dependencies:** none (standard library only).

**What this report can and cannot say.** Code cannot pass a regulatory audit on its own. An audit
also examines the organisation running it: who holds keys, how people get access, backups,
monitoring, vendor contracts. This report shows two things:

1. The application now implements the technical controls auditors test for.
2. It produces the evidence they ask for, and every control is backed by an automated test.

The items that need an owner outside the code are listed under **Residual risks**. Those must be
closed before going live with real money.

---

## 1. Summary

| | Before | After |
|---|---|---|
| Audit trail | JSONL file, editable and deletable | SQLite, append-only (triggers), HMAC-SHA256 hash chain keyed outside the DB, verifier, external anchors |
| Approvals | Free-text approver name, no authentication | Enrolled approvers, scrypt passcodes, cumulative lockout, roles per approval kind, segregation of duties, all attempts audited |
| Payee bank details | Taken from a file at payment time | Pinned by keyed fingerprint. A change blocks payment until a finance controller re-pins it with a reason. Destination is bound into every approval |
| Duplicate payment | Airwallex lookup plus per-run JSON | Plus a database unique index of live payouts per invoice. The invoice is locked *before* currency is bought |
| Sanctions / screening | None | Every payee name screened at triage and again before conversion and payout. A hit goes to a compliance officer |
| Sensitive data at rest | Full IBANs in `operations.json` | Masked to the last four characters everywhere; secrets removed entirely; a test proves no full IBAN reaches disk |
| Autonomy limit | Applied per conversion (could be split) | Cumulative over the cycle |
| Change provenance | None | Policy and code SHA-256 fingerprints recorded on every cycle |
| Static analysis | bandit: 2 medium, 1 low | bandit: 0 findings; pyflakes clean |
| Tests | 85 | 250 (78 dedicated control tests, plus the pass-3 regressions), passing on 3.14 |

---

## 2. Findings and fixes

Severity reflects impact on money movement or record integrity in a production deployment.

### Security

| ID | Sev | Finding | Fix | Evidence (tests) |
|---|---|---|---|---|
| S1 | High | Audit log was a plain JSONL file. Anyone with file access could edit or delete entries undetected. | `store.py`: `audit_log` table. Triggers refuse UPDATE/DELETE. Each row is HMAC-SHA256 chained to the previous one with `TREASURY_AUDIT_KEY`, held outside the DB. An insert trigger enforces the link. `verify()` re-checks integrity, triggers, chain, sequence gaps and tail truncation. `anchor` exports the head for off-host comparison. | `test_database_refuses_tampering[*]`, `test_edited_entry_is_detected_even_if_triggers_are_restored`, `test_forger_without_the_key_cannot_rebuild_the_chain`, `test_deleted_rows_are_detected`, `test_truncated_tail_is_detected_by_the_sequence_and_by_anchors` |
| S2 | High | Approvals were unauthenticated. The approver was a name in an environment variable, so anyone at the terminal could approve as anyone. | Approvers are enrolled in the DB with scrypt-hashed passcodes (n=16384, 16-byte salt), compared in constant time. Five failures lock the account for 15 minutes; the policy behind that lockout is hardened in S29. Deactivated, never deleted. Unknown ids and wrong passcodes fail identically. | `test_wrong_pin_is_refused_and_audited`, `test_repeated_wrong_pins_lock_the_approver`, `test_deactivated_approver_cannot_approve`, `test_pins_are_stored_as_scrypt_hashes` |
| S3 | High | No segregation of duties: whoever ran the agent could approve its requests. | `requested_by` is bound into the approval digest. The approver must differ, checked in code and by a DB `CHECK`. Least-privilege roles: FX → treasury approver or finance controller; policy exception and failed payout → finance controller; screening hit → compliance officer. Nobody can enrol themselves. | `test_requester_cannot_approve_their_own_request`, `test_only_the_right_role_can_decide[*]`, `test_manage_cli_enforces_roles_and_sod` |
| S4 | High | Payee bank details were read from a file at payment time. Editing the IBAN (vendor-master / business-email-compromise fraud) would redirect funds silently. | Payee accounts are pinned by keyed fingerprint. A mismatch blocks payment before any quote and escalates to a finance controller. A first payment to an unpinned account needs approval (R8). Approval cards show and bind the masked destination and its fingerprint. Re-pinning needs a finance controller, a reason of at least 10 characters and an append-only history row; the audit event is written in the same transaction (see S31). | `test_changed_bank_details_block_before_any_money_moves`, `test_approval_is_bound_to_the_destination_account`, `test_new_payee_needs_approval_and_is_pinned_by_the_approver`, `test_repinning_requires_a_reasoned_history_row` |
| S5 | High | Duplicate-payment protection had three gaps. It relied on Airwallex's transfer listing plus a per-run JSON file. A fresh state folder or a listing miss could pay an invoice twice. A crash between conversion and payout let the next run convert again. | DB unique index `one_live_payout_per_invoice` (payee fingerprint + reference + currency, excluding failed/cancelled rows; the amount was removed from the key in S24). The invoice is reserved before currency is bought. Reservations that moved no money are cancelled. A rejected transfer re-keys the reservation atomically. `manage.py release-payout` (finance controller, reason) clears a lock left by an interrupted run. | `test_one_live_payout_per_invoice_is_a_database_rule`, `test_database_blocks_repeat_payment_even_if_airwallex_lookup_misses`, `test_interrupted_run_keeps_the_invoice_locked_until_a_controller_releases_it`, `test_rejected_transfer_keeps_the_invoice_locked_under_a_new_request_id`, `test_second_run_cannot_pay_the_same_invoice_twice` |
| S6 | Medium | The request-id store was a JSON file. An edit could reuse an id or rewrite a completed operation. | `operations.request_id` is UNIQUE. Retired ids sit in a permanent table and can never be inserted or rotated back to. A completed operation is frozen by trigger. | `test_retired_request_id_can_never_be_reused`, `test_database_refuses_tampering[UPDATE operations…]` |
| S7 | Medium | Full bank account numbers were persisted (beneficiary and transfer responses in `operations.json`). | `redact()` masks account identifiers to the last four characters and removes secrets entirely, at any depth, before anything is stored. IBAN-shaped text in free-form strings (e.g. API error messages) is masked too. | `test_no_full_account_numbers_are_stored` (scans the raw DB and WAL bytes), `test_account_numbers_in_free_text_are_masked`, `test_redaction_masks_nested_identifiers` |
| S8 | Medium | State files were created with the default umask (often world-readable), with no protection against two processes writing at once. | `umask 077`; DB, WAL and SHM are 0600 and the folder 0700. An exclusive `flock` allows a single writer (auditors can still open read-only). WAL with `synchronous=FULL`, `foreign_keys=ON`, `secure_delete=ON`, `trusted_schema=OFF`. | `test_database_files_are_owner_only_and_single_writer` |
| S9 | Medium | `urllib` follows HTTP redirects, which could carry the bearer token or API key to another host. | A no-redirect opener is used for Airwallex and for the language model. | `test_http_redirects_are_never_followed` |
| S10 | Medium | The language-model base URL was unvalidated: `http://` or `file://` was accepted (bandit B310). | Only https is accepted (plain http to localhost only), checked at config load and again per request. The Airwallex client validates its base URL the same way. | `test_llm_endpoint_must_be_https`, `test_client_refuses_non_https_base_url` |
| S11 | Medium | The autonomy limit applied per conversion, so a large need could be split into several conversions just under the limit. | The limit is cumulative over the cycle, in planning (`plan()`), on the email event and at execution against the actual quote. | `test_policy_limit_counts_earlier_autonomous_conversions`, `test_execution_counts_conversions_already_made` |
| S12 | Medium | Scenario input was not validated. References, currencies and amounts were accepted unchecked, and the email path could escape the fixtures folder. | `validate_scenario()` checks: ISO currency and country codes; amounts positive, 2 decimal places, bounded; payout-rail-safe references (1–35 characters); printable names; known categories and payout methods; beneficiary details consistent with the obligation. The email file must sit next to the scenario. | `test_scenario_input_is_validated[*]`, `test_scenario_email_path_cannot_escape` |
| S13 | Low | Retry jitter used a non-cryptographic RNG (bandit B311). | `random.SystemRandom`. | bandit clean |
| S14 | Low | A `.env` holding API keys could be readable by other users without warning. | The loader warns when `.env` is group- or world-readable; `.env.example` says `chmod 600`. | `test_world_readable_env_file_is_flagged` |
| S15 | Low | Secrets could reach logs through repr or redaction (redaction kept the last four characters of tokens). | Settings and client reprs hide all credentials. Secrets are fully replaced with `****`. | `test_secrets_never_appear_in_settings_repr`, `test_client_repr_hides_credentials` |
| **Pass 2** | | | | |
| S16 | High | Live mode could start with an unkeyed (recomputable) audit chain. | Fail closed: outside mock mode `TREASURY_AUDIT_KEY` is required. A keyed DB refuses a missing or wrong key. An unkeyed DB cannot be silently re-keyed. | `test_live_mode_fails_closed_without_a_key`, `test_audit_key_is_required_and_checked`, `test_short_audit_keys_are_refused` |
| S17 | Medium | `--yes` (unattended approval from environment credentials) was usable against production. | Refused when the host is production Airwallex. It exists for sandbox demos only. | `test_live_runs_refuse_unattended_approval_on_production_and_missing_screening` |
| S18 | Medium | A reservation could be orphaned if Airwallex rejected the payee after the invoice was locked, and terminal payout rows could still be annotated. | Terminal payout rows (paid, failed or cancelled) are frozen by trigger. Release goes only through the audited `release-payout`. | `test_database_refuses_tampering[UPDATE payouts SET note…]`, `test_invalid_iban_is_rejected_at_beneficiary_creation` |
| S19 | Low | Concatenated SQL strings were flagged by bandit B608 (no injection path, but noisy). | Constant parameterised queries; constant DDL. | bandit clean |
| **Pass 3** (see `AUDIT_PASS3_2026-10-23.md` for the attack notes) | | | | |
| S20 | Critical | `verify()` compared trigger and index *names* only, so a no-op trigger recreated under its old name satisfied the verifier while a settled payout was rewritten. Payout and operation rows were bound into no digest. | Schema objects are verified by normalised **SQL text**, and every `payouts` / `operations` row is hashed into the chain with its latest authenticated state (`ROW_STATE_VERSION`). A ledger whose money rows predate signing gets its states seeded on open, and a pre-existing unverified row is reported as pending, not silently signed. | `test_no_op_triggers_recreated_under_familiar_names_are_reported`, `test_operations_row_rewrite_is_reported`, `test_money_rows_written_before_state_signing_are_seeded_on_open`, `test_money_rows_verify_before_any_tampering` |
| S21 | Critical | A customer email could label itself `unrelated` and veto its own confidence downgrade, so the headline "an email can only lower confidence" held for numbers but not for stance. | Invoice identity is derived by code from the scenario, never from the model; an addressable invoice cannot be labelled unrelated; an ambiguous reading yields a capped `unclear`, never `unrelated`; the longest stated delay wins. | `test_model_cannot_label_a_forecast_invoice_email_unrelated`, `test_an_email_that_really_is_unrelated_still_escapes`, `test_the_longest_stated_delay_is_the_one_used`, `test_model_and_rule_readers_reach_the_same_verdict` |
| S22 | High | The dashboard served the money path unauthenticated, published the approval `digest`, held hardcoded approver PINs in source, and could approve a card on a human's behalf. It also sent no framing policy. | Sign-in is checked by the store; the session token is `secrets.token_hex(32)` compared in constant time; `SECRET_FIELDS` (digest, destination fingerprint, verifiers) never reach the page; the demo passcodes are seeded into a throwaway database and are not served; a session can only sign a card with the approver's own passcode and the card's code. `Content-Security-Policy` and `X-Frame-Options: DENY` are set on every response. | `test_dashboard_holds_every_act_behind_a_signed_in_approver`, `test_dashboard_act4_stays_locked_until_a_human_signs_each_card`, `test_dashboard_signature_needs_the_card_own_code_and_a_real_pin`, `test_dashboard_page_carries_no_authority_to_the_browser`, `test_dashboard_rejects_forged_requests_without_mutation`, `test_dashboard_reset_needs_an_explicit_confirm_and_ends_the_session` |
| S23 | High | The host check compared raw strings: `https://api.airwallex.com.` (trailing dot), `https://API.AIRWALLEX.COM`, a `:443` port or a path reached the production-guard decision, and any host at all was accepted for the credential-bearing client. | `host_of()` normalises scheme case, port and trailing dot before the comparison; production needs `TREASURY_ALLOW_PRODUCTION=1`; `--yes` is refused against production in code; an unfamiliar host needs to be named exactly in `TREASURY_ALLOW_HOST`. | `test_every_spelling_of_the_production_host_is_refused`, `test_an_unfamiliar_host_never_sees_the_credentials`, `test_a_host_a_person_named_exactly_is_accepted_exactly`, `test_unattended_approval_is_refused_on_a_trailing_dot_production_host` |
| S24 | High | Paying an invoice for a different figure was a second live payout, not a duplicate: the guard, the reservation lookup and the transfer-history check all keyed on the amount. | An invoice's identity is payee + reference + currency; the amount is a property of the reservation. Existing ledgers are re-keyed once, and only when the stored index text matches the retired definition exactly — any other difference is tampering. A transfer that paid the invoice for another amount is reported with the discrepancy and blocks. | `test_a_changed_amount_is_a_second_attempt_not_a_new_invoice`, `test_an_older_ledger_is_upgraded_to_the_invoice_keyed_guard`, `test_an_unrecognised_guard_is_tampering_rather_than_something_to_upgrade`, `test_a_run_told_to_pay_less_for_a_paid_invoice_is_refused_by_the_bank` |
| S25 | High | A deposit could be booked for more than actually arrived, and movement beside the notified deposit went unremarked. | The notified amount is booked exactly, then reconciled: a shortfall, a surplus or any unrelated movement halts before the plan resumes and before `deposit_confirmed` is written. | `test_a_smaller_arrival_than_notified_is_never_booked_as_the_deposit`, `test_movement_beside_the_notified_deposit_halts_before_the_plan_resumes` |
| S26 | High | An FX conversion was checked against the *estimate* ceiling after it settled at a different rate, so the settled cost was never re-bound to what a human approved. | The settled cost is re-bound to the approval ceiling (or, for an autonomous conversion, the tier it was allowed to act under) before it touches the book; either breach halts with the conversion id named. | `test_a_conversion_that_settles_above_the_approved_ceiling_never_reaches_the_book`, `test_a_conversion_that_settles_beyond_the_autonomous_tier_halts_the_run` |
| S27 | High | An ambiguous write whose status lookup *failed* was treated as rejected, releasing the invoice for a fresh attempt that could pay twice. | A failed lookup leaves the request id locked and the outcome unresolved; only a lookup that positively reports no such request frees the operation. | `test_a_lookup_that_fails_leaves_the_request_id_locked`, `test_a_duplicate_reply_plus_a_failing_lookup_stays_unresolved`, `test_a_lookup_that_works_still_resolves_the_ambiguous_call` |
| S28 | Medium | Admin reads, exports and backups were neither authenticated nor audited, while the docs claimed they were. | `export-audit`, `backup`, `list-payouts` and `list-approvers` require `--by <approver id>`, sign in, and write what they read or copied into the chain; the manifest records whose hands the ledger passed through. `verify-audit` and `anchor` stay open without a passcode, because they are the commands an auditor needs on a ledger a writer is refused. | `test_admin_reads_and_copies_are_signed_in_and_written_to_the_chain`, `test_an_export_records_whose_hands_the_ledger_passed_through`, `test_verify_audit_stays_open_to_a_suspected_forgery_without_a_pin` |
| S29 | Medium | A passcode could be six digits, and the failed-attempt counter was zeroed each time the lockout was applied, so guessing was forgiven indefinitely. | Passcodes need 8 characters, at least 4 distinct ones and may not be digits only; every batch of five failures doubles the lockout (capped at a day) and the count is never reset. Failure state is signed into the chain, so an attacker cannot quietly rewind it either. | `test_each_batch_of_guesses_locks_the_account_for_longer`, `test_a_passcode_of_digits_only_is_not_enough_to_enrol` |
| S30 | Medium | Approval single-use and supersession lived in the process: nothing reloaded open cards at startup, so a crashed run left an approved, unconsumed card. | A reopened cycle adopts its own still-open rows: they take part in supersession again, and anything past its expiry is expired, written back and recorded. | `test_a_card_outliving_its_run_is_expired_when_the_cycle_reopens`, `test_a_reopened_run_supersedes_the_card_an_earlier_run_left_open` |
| S31 | Medium | `pin_payee` / `repin_payee` committed a destination change with no audit row in the transaction, and the demo re-payed payees under a controller's id without authenticating. | The record is mandatory and written in the same transaction: a change without one is refused, and a change whose record cannot be written rolls the destination back. Demo seeding is attributed to `seed:mock-demo`. | `test_a_payee_change_is_refused_without_its_audit_event`, `test_a_payee_change_rolls_back_when_its_record_cannot_be_written`, `test_the_pinned_destination_and_its_record_are_written_as_one_act` |
| S32 | Medium | Screening matched by exact token-set equality, so "Blackwater Shell Trading Ltd Consultants" screened clear. | Matching is by containment after normalisation, in both directions, with a two-word floor so a single shared word is not a match. | `test_extra_words_on_a_designated_name_do_not_clear_the_hit`, `test_a_shorter_form_of_a_designated_name_is_screened_too`, `test_one_shared_word_is_not_the_same_counterparty`, `test_a_one_word_list_entry_does_not_swallow_every_name` |
| S33 | Medium | The untrusted email's own `evidence_quote` was fed into the call that drafts the human's approver note (two-stage injection), and reader fields passed through with no length cap or sanitising. | Note-writing receives only facts this program wrote; payer, invoice id and expected date are capped, cleaned and checked verbatim. | `test_the_customer_quote_is_not_fed_back_to_the_note_writer`, `test_reader_cannot_add_facts_the_email_never_stated`, `test_escape_sequences_cannot_ride_through_the_reader_into_the_log` |

### Regulatory and internal control

| ID | Area | Finding | Fix | Evidence |
|---|---|---|---|---|
| R1 | Sanctions (OFAC) | No counterparty screening before paying. | `screening.py` hook. Every payee name (counterparty, beneficiary company, account holder) is screened at triage (`R0_SCREENING_HIT`: no cash planned) and again before conversion and before payout. Names are matched by containment after normalisation (extra descriptor words or a shorter form of a listed entity still hit; one shared word alone does not). Hits go to a `SCREENING_REVIEW` card that only a compliance officer can decide. Live runs refuse to start without a list unless explicitly overridden, which is recorded. | `test_screening_hit_at_triage_is_never_funded_or_paid`, `test_screening_hit_found_at_execution_stops_payment`, `test_screening_normalises_names`, `test_extra_words_on_a_designated_name_do_not_clear_the_hit` |
| R2 | Change management | No record of which policy or code version made a decision. | Each cycle row stores the SHA-256 of the policy thresholds and tiers, and of the shipped sources. Both are repeated in the `cycle_started` audit entry, together with the model and screening-list version. | `test_cycle_records_policy_and_code_fingerprints` |
| R3 | Record retention | Records could be deleted, and there was no export or backup. | Triggers forbid deleting any record table. `manage.py backup` produces a consistent, verified, never-overwritten copy plus a `.sha256`. `export-audit` writes JSONL per table and a manifest with row counts, file hashes, chain head and verification result. Both sign a person in (`--by`) and record the copy they took. | `test_backup_is_consistent_verified_and_never_overwritten`, `test_manage_cli_enforces_roles_and_sod`, `test_an_export_records_whose_hands_the_ledger_passed_through` |
| R4 | Access management | Granting and removing access left no record. | `manage.py` enrol and deactivate: authenticated as a finance controller, no self-enrolment, bootstrap allowed only into an empty DB, every action written to the same chain. Reading the roster, the reservations, or exporting and backing up the ledger needs `--by <approver id>` and is itself an event on the chain. | `test_manage_cli_enforces_roles_and_sod`, `test_admin_reads_and_copies_are_signed_in_and_written_to_the_chain` |
| R5 | Attribution | Every audit entry was attributed to "agent". | An `actor` column distinguishes `agent`, `operator:<id>`, `approver:<id>`, `unauthenticated:<claimed id>` and `bootstrap:<os user>`. | `test_wrong_pin_is_refused_and_audited`, `test_approval_rows_record_who_requested_and_who_approved` |
| R6 | Security monitoring | Failed sign-ins and refused actions were not logged. | Recorded events: `approval_auth_failed`, `approval_refused`, `admin_auth_failed` and `admin_refused`. | same as above |
| R7 | Approval evidence | Approval terms could be altered after the fact. | The `approvals` table freezes bound terms and decision fields, enforces status transitions and never deletes. `verify()` recomputes each card's digest. | `test_edited_approval_terms_break_their_digest`, `test_database_refuses_tampering[UPDATE approvals…]` |
| R8 | Exception handling | An interrupted payment had no controlled path to resolution. | `list-payouts --by` and `release-payout` (finance controller, reason of at least 10 characters, audited). Failed transfers become `PAYOUT_FAILED` cards and are never resent automatically. | `test_interrupted_run_keeps_the_invoice_locked_until_a_controller_releases_it`, `test_failed_payout_is_escalated_and_funds_ring_fenced` |

Controls from the original build that this audit re-verified:

- policy in code, never in prompts;
- model output validated, and an email can only lower confidence (prompt-injection safe);
- approval digest binding, single use, expiry, supersession;
- reserve floor checked against the actual quote;
- ledger reconciliation halts on unexplained movement;
- ambiguous writes are resolved by request-id lookup;
- `x-api-version` omitted on FX calls;
- quotes used once;
- sandbox calls isolated in `simulation.py`.

---

## 3. Control matrix

Framework references are where an auditor would look for each control. Applicability depends on the
operating entity: GLBA and BSA apply only to covered financial institutions. Airwallex, as the
licensed provider, runs its own KYC, AML and sanctions programme over these payments.

| Control | Implementation | SOC 2 (TSC) | ISO 27001:2022 Annex A | SOX ITGC | GLBA Safeguards 16 CFR 314.4 | GDPR | BSA / OFAC |
|---|---|---|---|---|---|---|---|
| Tamper-evident audit trail | HMAC chain, append-only triggers, verify, anchors | CC7.2, CC4.1 | 8.15, 5.33 | Computer operations; audit trail | (c)(8) | Art. 5(1)(f), 32 | 31 CFR 1010.410 record integrity |
| Authenticated approvers | scrypt PINs, lockout, deactivation | CC6.1 | 5.17, 8.5 | Logical access | (c)(1) | Art. 32 | — |
| Least privilege and SoD | Role per approval kind, requester ≠ approver (code + DB) | CC6.3 | 5.3, 5.15, 8.2 | SoD | (c)(1) | Art. 32 | — |
| Access provisioning and deprovisioning | `manage.py` add / deactivate, audited, no self-enrolment | CC6.2 | 5.16, 5.18 | Access provisioning | (c)(1) | Art. 32 | — |
| Payment authorisation | Digest-bound cards (amount, currency, counterparty, destination, ceiling, evidence, requester, expiry), single use | CC6.1, PI1.3 | 8.2 | Application control: authorisation | — | — | — |
| Vendor-master integrity | Payee pinning, change history with reason, block on mismatch | PI1.2, CC6.1 | 5.15, 8.3 | Master-data change control | — | Art. 5(1)(d) | — |
| Duplicate-payment prevention | Request-id discipline, unique live payout per invoice, pre-conversion lock | PI1.3, PI1.4 | 8.25 | Application control: completeness/accuracy | — | — | — |
| Reserve floor and limits | Floor at plan and execution; cumulative autonomy limit; single-payment threshold | PI1.3 | — | Application control | — | — | — |
| Reconciliation | Ledger vs Airwallex deltas; halt on mismatch | PI1.4, CC7.2 | 8.16 | Computer operations | (c)(8) | — | — |
| Sanctions screening | List hook at triage and before money moves; compliance-only clearance | — | — | — | — | — | OFAC screening (hook; provider needed) |
| Data minimisation and masking | Last-4 masking, secrets removed, IBAN text scrub | C1.1 | 8.11, 8.12 | — | (c)(3) partial | Art. 5(1)(c), 25 | — |
| Secure transmission | HTTPS only, TLS verification on, no redirects | CC6.7 | 8.20, 8.24 | — | (c)(3) in transit | Art. 32 | — |
| Change provenance | Policy and code fingerprints per cycle | CC8.1 | 8.32 | Change management | (c)(7) | — | — |
| Retention, backup, export | No deletes; verified backup; export manifest with hashes | A1.2, C1.2 | 8.13, 5.33 | Computer operations | (c)(6) | Art. 5(1)(e) (legal-obligation basis) | 5-year retention |
| Input validation and secure coding | Scenario validation, untrusted-text sanitising, model output validation, bandit clean | CC8.1, PI1.2 | 8.28 | — | — | Art. 25 | — |
| Fail-safe operation | Fail closed without audit key or screening; halt on anomalies; never auto-resend | CC7.3 | 5.26 | Computer operations | — | — | — |

---

## 4. The database

`state/treasury.db` (live) — SQLite, schema version 1. Every protection is checked by
`python manage.py verify-audit`.

| Table | Purpose | Protection |
|---|---|---|
| `meta` | Schema version, chain type, key check, retention note | Immutable |
| `cycles` | One row per run: operator, mode, policy and code fingerprints, model | Immutable, no delete |
| `audit_log` | Every action with reason, actor, data (redacted) | Append-only; `prev_hash` must equal the last `entry_hash` (trigger); HMAC-SHA256 chain |
| `operations` | Request id per money-moving operation, result (redacted) | Request id UNIQUE; completed rows frozen; identity frozen; no delete; each row's state signed into the chain |
| `retired_request_ids` | Ids that may never be used again | Permanent; enforced on insert and on rotation |
| `approvers` | Identity, roles, scrypt hash, lockout | No delete (deactivate only); identity frozen; each row's state signed into the chain |
| `approvals` | Every card shown and its outcome | Bound terms and decision frozen; legal status transitions only; requester ≠ approver; digest re-verified; a card left open by an interrupted run is reloaded, superseded or expired by the next one |
| `payees`, `payee_history` | Pinned bank-account fingerprints and every change with its reason | Pins cannot be updated in place; a change needs a history row (reason ≥ 10 characters) and its audit event in the same transaction; history is append-only |
| `payouts` | One reservation per invoice payment | Unique live payout per payee + invoice (the amount is a property of the reservation, not of the invoice's identity); terms frozen; terminal rows frozen; legal transitions only; each row's state signed into the chain |
| `snapshots` | Agent state at each act (redacted) | Append-only |

**What an attacker with write access to the file can and cannot do.**

- Triggers and indexes can be dropped, but `verify` compares each object's **SQL text** with the
  schema this code created: a name-preserving replacement (including a no-op trigger) is tampering,
  and so is any definition it does not recognise.
- Rows can be edited, but without the key the chain cannot be recomputed. Every edited or forged row,
  and every row after it, fails verification. `payouts` and `operations` rows are additionally hashed
  into the chain with their latest authenticated state, so a rewritten settled amount is reported even
  if the chain around it is intact.
- Deleting rows from the middle or the start is detected.
- Deleting the tail and rewinding SQLite's sequence counter is detected only against an anchor
  recorded off the machine (`manage.py anchor`, or `TREASURY_ANCHOR_FILE` on every run). This is why
  anchoring is a residual operational requirement.
- Someone holding **both** the database and the key can rewrite history. Key custody (below) is
  what prevents that.

---

## 5. Data flows

| Data | Goes to | Stored locally as |
|---|---|---|
| Airwallex credentials | Airwallex login only (https, no redirects) | Never stored; hidden from repr |
| Full beneficiary bank details | Airwallex (beneficiary creation) | Keyed fingerprint plus masked form (`IBAN ****3000 · BIC … · EUR`) |
| Customer email text | Optional model provider (Anthropic or OpenAI-compatible) when a key is set | Only the verbatim evidence quote and the structured signal |
| Exception facts (amounts, counterparty names) | Optional model provider, for the approver note | In the audit log |
| Approver passcodes | Nowhere | scrypt hash plus salt; never rendered to the dashboard |

With `LLM_PROVIDER=rules` nothing leaves for a model provider.

---

## 6. Residual risks — need an owner outside the code

These are organisational or infrastructure controls. Auditors will ask for them, and no change to
this code can provide them.

1. **Strong authentication.** Passcodes are a single factor. Bind approvers and the operator to the
   company's SSO with MFA (SOC 2 CC6.1; GLBA 314.4(c)(5)). The operator identity is currently the OS
   user or `TREASURY_OPERATOR`, which is self-asserted. Segregation of duties is only as strong as
   that binding.
2. **Key custody.** Hold `TREASURY_AUDIT_KEY` in a KMS or HSM, out of reach of whoever administers the
   database host.
   - Document rotation: start a new database per key epoch, verify old databases with the old key and
     keep both.
   - Losing the key means the chain can no longer be verified.
3. **Encryption at rest.** The database is not encrypted. Masking limits exposure. Use volume or
   full-disk encryption, or SQLCipher (GLBA 314.4(c)(3)).
4. **Off-host retention.** Ship nightly `manage.py backup` output and per-run anchors to write-once
   storage (e.g. S3 Object Lock in compliance mode). Retain for at least 7 years (SOX §802; BSA
   requires 5). Test restores.
5. **Real screening data.** The bundled list is fictitious. Matching normalises names, ignores legal
   suffixes and punctuation, and then treats either containment as a hit; it is not transliteration,
   fuzzy scoring or alias intelligence.
   - Integrate OFAC SDN and consolidated lists (plus EU, UK and UN as relevant) or a screening vendor
     with fuzzy matching.
   - Rescreen when lists update.
6. **Asynchronous approvals.** Approvers currently sign in at the running terminal. A production
   deployment needs an approval service with the same bindings, authenticated by SSO.
7. **Vendor master.** Payee details come from a fixture. In production they come from the AP system.
   - Its own change controls apply.
   - Document the call-back procedure behind `pin-payee`.
8. **Model provider.** Before enabling a model, sign a DPA, agree zero-retention terms and record the
   processing (GDPR Art. 28 and 30). Otherwise run `LLM_PROVIDER=rules`.
9. **Time source.** Timestamps and approval expiry use the host clock. Enforce NTP (ISO 8.17).
10. **Monitoring.** Alert on `approval_auth_failed`, `admin_auth_failed`, `admin_refused`, `halted`,
    `duplicate_invoice`, `payout_released` and any `verify-audit` failure. Repeated wrong PINs can lock
    an approver out (denial of service), so watch for them.
11. **Periodic access reviews.** Run them quarterly from `list-approvers --by` and the export.
12. **Independent testing.** Get a penetration test and an independent review of these controls.
    Run bandit and the test suite in CI on every change.
13. **Live sandbox verification.** This environment's network allowlist blocks Airwallex. Run
    `smoke_live.py` and `demo.py --live` once from a machine that can reach the sandbox.
14. **Retention versus erasure.** Records are never deleted. Personal data is limited to business
    contact names and masked accounts. Document the legal-obligation basis (GDPR Art. 17(3)(b)).

---

## 7. How this was verified

- `.venv/bin/python -m pytest` runs 250 tests and all pass on CPython 3.14.8. 78 of them are
  dedicated control tests in `tests/test_controls.py`, including tamper drills against the database
  and an end-to-end live-mode run against the mock sandbox; `tests/test_audit_regressions.py` adds the
  behavioural regressions for every finding in `AUDIT_PASS3_2026-10-23.md`, dashboard included.
  The venv holds dev tools only (pytest, pyflakes, bandit); the runtime is standard library alone.
- `bandit -r . -x ./tests,./.venv,./__pycache__` reports 0 findings at every severity. The two
  remaining `# nosec B310` lines are the https-validated, no-redirect URL opens.
- `pyflakes *.py tests/*.py` reports no warnings.
- The mock demo was run end to end; its own `verify` reported VERIFIED.
- `manage.py` was exercised for bootstrap, refused second bootstrap, wrong passcode, role refusal,
  `pin-payee`, `anchor`, `verify-audit --anchors`, `export-audit`, `backup`, and the refusal of a read
  or copy offered without `--by`, by hand and in `test_manage_cli_enforces_roles_and_sod`.
  `sample_run.txt` shows a full demo run followed by `verify-audit` and `list-payouts` on its database.
- No runtime third-party dependencies. The supply-chain surface is the Python standard library;
  pytest is dev-only.

**Operational checklist for auditors**

Reads that disclose or copy ledger data name the person who asked for them; `verify-audit` and `anchor`
deliberately do not, because they must work on a ledger whose writer is being refused.

```bash
python manage.py verify-audit --anchors /worm/anchors.jsonl        # integrity, schema text, chain, digests, anchors
python manage.py export-audit --by dana.controller --out audit-2026Q4/   # JSONL per table + manifest with hashes
python manage.py list-approvers --by dana.controller               # access review
python manage.py list-payouts --by dana.controller                 # open reservations, failures, releases
python manage.py backup --by dana.controller --out /worm/treasury-2026-10-31.db
```
