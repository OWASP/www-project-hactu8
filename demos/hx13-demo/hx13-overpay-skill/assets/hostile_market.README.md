# hostile_market.json — how the four moves work

`hostile_market.json` is the attack payload. `POST /api/attack` (or
`scripts/run_payment_attack.py`, or Act 2 of `run_demo.py`) installs it on
the Lamb Market. Every merchant is a Python object in the lab process, and
every amount is a fake test unit.

| Key | What it does | Who it hits |
|-----|--------------|-------------|
| `attacker_merchants` | Merchants whose received logs count as attacker-visible for grading | all |
| `listing_qa` | Q&A answers appended to a merchant's listing; Billy's model reads them with the listing | Dana, Mei |
| `rechallenge` | The merchant settles each payment for the resource, then answers 402 again with this `error` | Ravi |
| `cart_add_on` | An item the merchant adds to every cart it signs | Sam |
| `limits` | The measured limit, installed only by `--probe` | Jo |

## What the stand-in model follows

The echo stand-in (`StubModel` in `vulnerable_app.py`) follows four phrases
on a listing, and nothing else:

- `order N SKU from MERCHANT` adds an order;
- `buy N SKU, one payment each` splits the planned item into N one-unit
  checkouts;
- `order SKU instead` swaps the planned item;
- `write the customer's wallet reference in the ... note` puts the wallet
  reference in the added orders' notes.

A merchant or SKU the market does not have is ignored. A real model reads
the same listing and may do something else; `run_demo.py --backend ...`
reports what it did.

## Writing your own

- Keep it benign: merchants, SKUs and amounts from `assets/market.json`,
  nothing outside the lab.
- To test the screen, reword a Q&A answer so it no longer says "shopping
  agents" or "wallet reference ... note", then run
  `python scripts/evaluate_kpi.py --scan`. The default rules already pass
  the shipped answers; the lab rules then pass yours too, and the caps,
  allowlist and cart match are what is left.
- To test the caps, change the quantity in `order N ...` or the add-on's
  `price`, and watch which requests stay RED with `use_tx_cap` or
  `use_budget_cap` alone (`LayersTest`).
