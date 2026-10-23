#!/usr/bin/env python3
"""Build step 1: verify sandbox credentials without moving money.

    python smoke_live.py

Logs in, reads balances, lists Global Accounts and fetches one indicative rate.
Read-only: no quote, conversion, beneficiary, transfer or simulation call.
"""
from __future__ import annotations

import sys
from decimal import Decimal

from airwallex_client import AirwallexClient, AirwallexError
from config import ConfigError, load_settings
from models import fmt


def main() -> int:
    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"config error: {exc}")
        return 2
    if not settings.has_airwallex_credentials:
        print("Set AWX_CLIENT_ID and AWX_API_KEY (environment or .env) first.")
        return 2
    client = AirwallexClient(settings.base_url, settings.client_id, settings.api_key,
                             api_version=settings.api_version)
    try:
        client.login()
        print(f"✓ login ok against {settings.base_url}")
        balances = client.get_balances()
        print("✓ balances:", ", ".join(f"{fmt(b.available, c)}" for c, b in sorted(balances.items())) or "(none)")
        accounts = client.list_global_accounts()
        usd = [a for a in accounts if a.get("status") == "ACTIVE"
               and any(f.get("currency") == "USD" for f in a.get("required_features", []) + a.get("supported_features", []))]
        print(f"✓ global accounts: {len(accounts)} ({len(usd)} active USD; the deposit simulation needs one)")
        rate = client.get_rate(buy_currency="EUR", sell_currency="USD", buy_amount=Decimal("1000"))
        print(f"✓ EUR/USD indicative rate: {rate.get('currency_pair')} {rate.get('rate')}")
    except AirwallexError as exc:
        print(f"✗ {exc}")
        return 1
    print("Sandbox reachable. Run: python demo.py --live")
    return 0


if __name__ == "__main__":
    sys.exit(main())
