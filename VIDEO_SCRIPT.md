# Demo video script (target 4:30)

Record with `python3 demo.py --live --yes --pace 1.2` (or offline: `python3 demo.py --yes --pace 1.2`).
Terminal at least 100 columns wide. Each beat maps to the spec's checklist.

| Time | On screen | Say |
|---|---|---|
| 0:00–0:20 | Title card | "Five bills, three currencies, 72 hours — and cash above our reserve floor covers about 60% of them. This agent has to decide what to pay, what to convert, what to defer and what a human must decide." |
| 0:20–0:45 | Act 1: balances, forecast | "It reads live balances from Airwallex and an indicative rate. Our biggest customer has paid five of six invoices on time and acknowledged this one, so bank and invoice data agree: confidence 0.92, which policy code maps to a USD 15,000 autonomous conversion limit." |
| 0:45–1:30 | Act 1: plan + floor bar | Walk the five decisions: "Shipping is funded first — no payment, no operations. Rent is fixed. For the German supplier it converts only the minimum: 12,000 plus the 12.85 SWIFT fee, minus the 500 euros already held. That leaves us 691 dollars short, so it defers the cheapest thing to defer — licenses, zero penalty. The contractor payout is over the USD 15,000 single-payment threshold, so it goes to a human, and the agent refuses to split it to sneak under. The red band is the reserve floor; nothing is planned through it." |
| 1:30–2:20 | Act 2: email, signal, before/after | "Now an email: Northwind's payment slips two weeks. The model only extracts a signal — delay, 14 days, with a quote copied verbatim from the email. Code decides what it means: the receipt now falls outside our window, confidence drops to 0.37, the limit drops from 15,000 to 2,500 — and the same conversion now needs a human. Note the approval card: amount, currency, counterparty, the destination account, evidence, and a code tied to exactly those terms." |
| 2:20–3:05 | Act 3: deposit + recalculation | "A 25,000 dollar deposit lands from another customer. The agent confirms it on Airwallex, then recalculates only what cash was blocking: the licenses get funded, and the contractor's funding goes from an 18,500 gap to fully held — still waiting on a human, with a fresh card because the evidence changed. Shipping, rent and the supplier are untouched." |
| 3:05–4:00 | Act 4: approve, quote, convert, beneficiary, transfer | "The approver signs in with their own PIN — they hold the treasury role and didn't request this — and types the code. One single-use quote, the conversion booked over REST, a beneficiary checked against Airwallex's schema, and the EUR 12,000 transfer with its 12.85 fee. SENT is in flight, not final; PAID is terminal. Balances are re-read and reconciled before and after every move. And every step lands in an HMAC-chained, append-only audit database." |
| 4:00–4:30 | Close screen | "Start, decisions, deposit, finish: exactly the euros we needed — EUR balance zero — USD 15,258 uncommitted against a 10,000 floor, and every action in the log with its rule and reason. The contractor is still with a human, as it should be. Repo link on screen." |

Tips
* Set `TREASURY_REPO_URL` so the close screen prints the repo link.
* Interactive approval (drop `--yes`) shows a human typing the code — good for the Act 4 beat.
* For a second live take, set `TREASURY_REFERENCE_SUFFIX=-r2`; the agent will not pay the same invoice twice.
