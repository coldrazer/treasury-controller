# Handoff: Treasury Controller MCP Server

## What this is

The Adaptive Treasury Controller is a Python AI agent built for the Airwallex
Agentic Banking Hackathon (Track 1). It triages a cash shortfall across five
obligations in three currencies, gates its own autonomy on forecast confidence,
recalculates on mid-cycle deposits, and executes FX conversions and transfers
against the Airwallex sandbox.

Your job: build an MCP server that wraps the agent, register it with Muse CLI,
and prove it works by driving all four acts through MCP tool calls.

## Step 1: Get the project

The project zip is at `~/workspace/user/files/treasury-controller-2.zip`.
Unzip it somewhere sensible, for example:

```bash
mkdir -p ~/treasury && cd ~/treasury
unzip -o ~/workspace/user/files/treasury-controller-2.zip
cd treasury-controller
python3 --version   # needs 3.11+
```

Verify the CLI demo runs before you touch MCP:

```bash
python3 demo.py --yes 2>&1 | tail -5
```

You should see the four acts complete and the audit chain verify. If this
fails, stop and fix it before continuing. Nothing downstream works if the
agent itself does not run.

## Step 2: Build the MCP server

Write the following to `~/treasury/treasury-controller/mcp_server.py`.
It speaks JSON-RPC 2.0 over stdio, which is what Muse CLI expects.
It boots the real `TreasuryAgent` against the offline mock sandbox once at
startup and keeps it in memory across tool calls. Standard library only.

```python
#!/usr/bin/env python3
"""MCP server wrapping the Adaptive Treasury Controller agent.

Tools:
  treasury_status   snapshot of balances, obligations, confidence, approvals
  treasury_act1     bootstrap + triage (read balances, plan five obligations)
  treasury_act2     ingest the customer email (confidence drop)
  treasury_act3     post the sandbox deposit and recalculate
  treasury_approve  sign a pending approval card (demo approver credentials)
  treasury_execute  run execution (FX quote, conversion, beneficiary, transfer)
  treasury_reset    close the run and start a fresh cycle
"""
import json
import os
import sys
import traceback
from decimal import Decimal

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent import TreasuryAgent
from airwallex_client import AirwallexClient
from config import BASE_CURRENCY, DEFAULT_POLICY, load_settings
from demo import DEMO_APPROVERS, DEMO_APPROVER_FOR_KIND, seed_mock_database, seed_mock_payees
from email_reader import make_reader
from explainer import Explainer
from llm import make_llm
from mock_sandbox import MOCK_API_KEY, MOCK_CLIENT_ID, MockAirwallex
from models import State
from runtime import make_screener, new_cycle_id, open_store
from simulation import SandboxSimulator, load_scenario


def ser(o):
    if isinstance(o, Decimal):
        return float(o)
    if isinstance(o, State):
        return o.value
    if isinstance(o, (list, tuple)):
        return [ser(x) for x in o]
    if isinstance(o, dict):
        return {str(k): ser(v) for k, v in o.items()}
    if hasattr(o, "__dataclass_fields__"):
        return {f: ser(getattr(o, f)) for f in o.__dataclass_fields__}
    return o if isinstance(o, (str, int, float, bool)) or o is None else str(o)


class TreasuryMCP:
    def __init__(self):
        settings = load_settings()
        self.scenario = load_scenario()
        self.mock = MockAirwallex(
            balances=self.scenario.operating_cash,
            rates_usd_per_unit=self.scenario.mock_rates,
            swift_fees=dict(DEFAULT_POLICY.swift_fees))
        base_url = self.mock.start()
        client = AirwallexClient(base_url, MOCK_CLIENT_ID, MOCK_API_KEY,
                                 api_version=settings.api_version)
        llm = make_llm(settings)
        cycle = new_cycle_id()
        store = open_store(settings, mode="mock", cycle_id=cycle)
        seed_mock_database(store)
        agent = TreasuryAgent(
            client, obligations=self.scenario.obligations,
            receipt=self.scenario.expected_receipt, payouts=self.scenario.payouts,
            reader=make_reader(llm), explainer=Explainer(llm),
            store=store, cycle_id=cycle, operator="demo.operator",
            mode="mock", screener=make_screener(settings),
            cash_cap=self.scenario.operating_cash)
        seed_mock_payees(agent, self.scenario)
        self.agent = agent
        self.sim = SandboxSimulator(client)
        self.cycle = cycle

    def reset(self):
        self.agent.store.close()
        self.mock.stop()
        self.__init__()
        return {"ok": True, "cycle": self.cycle}

    def status(self):
        a = self.agent
        obs = []
        for rec in a.records.values():
            ob = rec.ob
            obs.append({"id": ob.id, "name": ob.name,
                        "counterparty": ob.counterparty,
                        "amount": float(ob.amount), "currency": ob.currency,
                        "due_hours": ob.due_in_hours, "state": rec.state.value,
                        "decision": ser(rec.decision)})
        appr = [{"id": r.id, "kind": r.kind, "amount": float(r.amount),
                 "currency": r.currency, "counterparty": r.counterparty,
                 "code": r.code} for r in a.pending_approvals()]
        return {"cycle": self.cycle, "confidence": float(a.confidence),
                "obligations": obs, "pending_approvals": appr}

    def act1(self):
        a = self.agent
        a.audit.act = "act1"
        a.bootstrap()
        tri = a.triage()
        a.checkpoint("act1")
        return {"ok": True, "coverage": float(tri.coverage),
                "confidence": float(tri.confidence),
                "decisions": {oid: ser(d) for oid, d in
                              ((r.ob.id, r.decision) for r in a.records.values())}}

    def act2(self):
        a = self.agent
        a.audit.act = "act2"
        ev = a.ingest_customer_email(self.scenario.customer_email)
        a.checkpoint("act2")
        return {"ok": True, "limit_before": float(ev.limit_before),
                "limit_after": float(ev.limit_after),
                "gated": [r.ob.id for r, _ in ev.gated]}

    def act3(self):
        a = self.agent
        a.audit.act = "act3"
        dep = self.scenario.deposit
        self.sim.deposit(amount=dep.amount, currency=dep.currency,
                         payer_name=dep.payer_name, reference=dep.reference)
        rc = a.on_balance_event(currency=dep.currency, amount=dep.amount,
                                reference=dep.reference)
        a.checkpoint("act3")
        return {"ok": True,
                "changes": [{"id": c.obligation_id,
                             "was": c.old_state.value,
                             "now": c.new_state.value} for c in rc.changes],
                "untouched": sorted(rc.untouched)}

    def approve(self, approval_id):
        a = self.agent
        req = next((r for r in a.pending_approvals() if r.id == approval_id), None)
        if not req:
            return {"ok": False, "error": "no such pending approval"}
        who = DEMO_APPROVER_FOR_KIND.get(req.kind, "sam.treasury")
        pin = DEMO_APPROVERS[who][2]
        out = a.approve(req.id, approver_id=who, pin=pin, confirm_code=req.code)
        return {"ok": True, "approved_by": who, "status": ser(out)}

    def execute(self):
        a = self.agent
        a.audit.act = "act4"
        results = a.execute()
        rep = a.reserve_report()
        v = a.store.verify()
        return {"ok": True,
                "results": [{"obligation": r.obligation_id,
                             "status": r.status} for r in results],
                "reserve_intact": bool(rep.intact),
                "uncommitted_usd": float(rep.uncommitted),
                "audit_entries": v.entries}


TOOLS = [
    {"name": "treasury_status",
     "description": "Snapshot of the treasury agent: balances, obligations with states and decisions, forecast confidence, pending approvals.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "treasury_act1",
     "description": "Act 1: bootstrap the agent and triage all five obligations (fund, convert, defer, escalate).",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "treasury_act2",
     "description": "Act 2: ingest the customer delay email. Confidence drops and conversions become approval-gated.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "treasury_act3",
     "description": "Act 3: post the USD 25,000 sandbox deposit and recalculate only cash-constrained decisions.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "treasury_approve",
     "description": "Sign a pending approval card with the demo approver credentials.",
     "inputSchema": {"type": "object", "properties": {
        "approval_id": {"type": "string", "description": "Approval ID from treasury_status"}}}},
    {"name": "treasury_execute",
     "description": "Act 4: execute approved conversions and transfers, then confirm the reserve floor.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "treasury_reset",
     "description": "Close the current run and start a fresh demo cycle.",
     "inputSchema": {"type": "object", "properties": {}}},
]

HANDLERS = {
    "treasury_status": lambda s, a: s.status(),
    "treasury_act1": lambda s, a: s.act1(),
    "treasury_act2": lambda s, a: s.act2(),
    "treasury_act3": lambda s, a: s.act3(),
    "treasury_approve": lambda s, a: s.approve(a["approval_id"]),
    "treasury_execute": lambda s, a: s.execute(),
    "treasury_reset": lambda s, a: s.reset(),
}


def main():
    svc = TreasuryMCP()

    def send(obj):
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:
            continue
        mid = msg.get("id")
        method = msg.get("method", "")
        try:
            if method == "initialize":
                send({"jsonrpc": "2.0", "id": mid, "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "treasury-controller",
                                   "version": "1.0.0"}}})
            elif method == "notifications/initialized":
                pass
            elif method == "tools/list":
                send({"jsonrpc": "2.0", "id": mid,
                      "result": {"tools": TOOLS}})
            elif method == "tools/call":
                name = msg["params"]["name"]
                args = msg["params"].get("arguments", {})
                fn = HANDLERS.get(name)
                if not fn:
                    raise ValueError(f"unknown tool {name}")
                out = fn(svc, args)
                send({"jsonrpc": "2.0", "id": mid, "result": {
                    "content": [{"type": "text",
                                 "text": json.dumps(out, indent=2)}]}})
            else:
                send({"jsonrpc": "2.0", "id": mid,
                      "error": {"code": -32601, "message": "method not found"}})
        except Exception as exc:  # noqa: BLE001
            send({"jsonrpc": "2.0", "id": mid, "error": {
                "code": -32603,
                "message": f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[-500:]}"}})


if __name__ == "__main__":
    main()
```

Make it executable:

```bash
chmod +x ~/treasury/treasury-controller/mcp_server.py
```

Smoke test the protocol by hand before registering it. Send it an
initialize, then a tools/list, and confirm you get seven tools back:

```bash
cd ~/treasury/treasury-controller
printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
| timeout 15 python3 mcp_server.py | python3 -c "
import json,sys
for line in sys.stdin:
    d = json.loads(line)
    r = d.get('result', {})
    if 'tools' in r:
        print('tools:', [t['name'] for t in r['tools']])
    elif 'serverInfo' in r:
        print('server:', r['serverInfo']['name'], r['serverInfo']['version'])
"
```

Expected output:

```
server: treasury-controller 1.0.0
tools: ['treasury_status', 'treasury_act1', 'treasury_act2', 'treasury_act3', 'treasury_approve', 'treasury_execute', 'treasury_reset']
```

If the server hangs or errors, read the traceback in the error response.
Common cause: the agent failed to boot, which means `demo.py --yes`
would also fail. Fix the agent first.

## Step 3: Register it with Muse CLI

Add the server to the Muse CLI MCP config. The config file is
`~/.claude.json` (user scope) or `.mcp.json` in the project directory
(project scope). Add:

```json
{
  "mcpServers": {
    "treasury": {
      "command": "python3",
      "args": ["/home/USER/treasury/treasury-controller/mcp_server.py"],
      "env": {}
    }
  }
}
```

Replace `/home/USER` with the real home directory. Then verify Muse CLI
sees it:

```bash
muse mcp list
```

You should see `treasury` in the list. If not, check the path in the
config and that `mcp_server.py` is executable.

## Step 4: Prove it works

In a Muse CLI session, run this exact sequence. After each call, confirm
the output matches before moving on.

1. **`treasury_status`** — five obligations, all `pending`, confidence
   not yet assessed. This is the blank slate.

2. **`treasury_act1`** — triage runs. Expect five decisions:
   #1 Shipping invoice FUND, #5 Office rent FUND, #2 Supplier CONVERT,
   #4 Contractor ESCALATE, #3 Software licenses DEFER.
   Coverage should be about 0.59, confidence 0.92, autonomous FX limit
   15000.

3. **`treasury_status`** — #2 should now be `fx_planned` (within the
   15000 limit at 0.92 confidence). #4 is `escalated` with a pending
   approval. #3 is `deferred`.

4. **`treasury_act2`** — the customer email lands. Expect the autonomous
   limit to drop from 15000 to 2500. #2 should move to
   `awaiting_approval` because the same conversion now exceeds the limit.

5. **`treasury_status`** — grab the `approval_id` and `code` for the
   FX_CONVERSION approval on #2.

6. **`treasury_approve`** with that approval_id — expect `ok: true`,
   approved by `sam.treasury`.

7. **`treasury_act3`** — the USD 25000 deposit posts. Expect `changes`
   to list #3 (deferred to funded) and #4 (escalated, re-bound).
   `untouched` should be [1, 2, 5]. Nothing else moves.

8. **`treasury_execute`** — the conversion and transfer run. Expect #2
   to reach `paid`, `reserve_intact: true`, uncommitted USD above
   10000, and a nonzero `audit_entries` count.

9. **`treasury_status`** — final state: #1 funded, #2 paid, #3 funded,
   #4 escalated (still waiting on a finance controller, by design),
   #5 funded.

If every step matches, the MCP integration works end to end: Muse CLI
drove the real agent through all four acts, approvals were bound and
authenticated, and the reserve floor held.

## Step 5: Reset

`treasury_reset` closes the run and starts a fresh cycle. Use it between
demo takes so the duplicate invoice guard does not block replays.

## Troubleshooting

- **Server exits immediately.** Run it by hand with no stdin; the
  traceback prints to stderr. Almost always an import error or a bad
  path in `sys.path.insert`.
- **Muse CLI does not list the server.** The `command` path in the MCP
  config must be absolute. `~` is not expanded.
- **Tools hang.** The agent is single threaded and SQLite bound. Do not
  run two Muse CLI sessions against the same server process.
- **Approval fails.** The demo approvers only exist in the mock
  database, and their passcodes are the seeded ones in `demo.py`
  (`DEMO_APPROVERS`), not real credentials. If you switched to `--live`
  mode or a real `.env`, they will not authenticate. Stay in mock mode
  for the MCP demo.
- **`treasury_act1` says triage already ran.** Call `treasury_reset`
  first. Triage runs once per cycle by design.

## What NOT to do

- Do not point this at production Airwallex. Mock mode only.
- Do not commit API keys. The mock needs none.
- Do not run the MCP server and the dashboard against the same
  `state/` directory at the same time. They each open their own
  database, but keep the demos separate to avoid confusion.
