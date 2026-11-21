# HX13 Agent Overpay and Mandate Bypass — risks, protocol sources and mitigations

What this lab's risk is, where the protocol shapes come from, and how to harden against it. Loaded on demand.

## Research foundations

- **x402, repository README** (<https://github.com/coinbase/x402>, read 2026-11-21). The flow: the client requests a resource; the server answers `402 Payment Required` with a base64 `PaymentRequired` in the `PAYMENT-REQUIRED` header; the client picks one of the `accepts` entries, builds a `PaymentPayload` and retries with `PAYMENT-SIGNATURE`; the server verifies locally or through a facilitator's `/verify`, settles directly or through `/settle`, and answers `200` with a `PAYMENT-RESPONSE` header carrying the settlement response. If the payment is invalid it answers `402` again.
- **x402 specification v2** (<https://raw.githubusercontent.com/coinbase/x402/main/specs/x402-specification-v2.md>, read 2026-11-21; protocol version 2, version history v2.0 dated 2025-12-9). `PaymentRequired`: `x402Version`, `error`, `resource` (an object with `url`, `description`, `mimeType`), `accepts`, `extensions`. Each `PaymentRequirements`: `scheme` (for example `exact`), `network` (CAIP-2), `amount` (a string in atomic units), `asset`, `payTo`, `maxTimeoutSeconds`, optional `extra`. `PaymentPayload`: `x402Version`, `resource`, `accepted`, `payload` (`signature`, `authorization` with `from`, `to`, `value`, `validAfter`, `validBefore`, `nonce`). Settlement response: `success`, `errorReason`, `payer`, `transaction`, `network`, `amount`. The nonce is "a 32-byte random nonce to prevent replay attacks". The spec defines no idempotency key and no general retry policy; `settlement_pending` is the one non-terminal error. Nothing in it bounds how often a client pays the same resource: that is left to the client, which is the gap the re-challenge uses.
- **AP2 v0.1.0 source** (<https://github.com/google-agentic-commerce/AP2/tree/v0.1.0>, `src/ap2/types/mandate.py` and `payment_request.py`, read 2026-11-21). `IntentMandate`: `user_cart_confirmation_required` ("must be true if the intent mandate is not signed by the user"), `natural_language_description`, `merchants` ("If not set, the shopping agent is able to work with any suitable merchant"), `skus` ("If not set, any SKU is allowed"), `requires_refundability`, `intent_expiry`. It has no price cap. `CartMandate`: `contents` (`id`, `user_cart_confirmation_required`, `payment_request`, `cart_expiry`, `merchant_name`) and `merchant_authorization` (a merchant-signed JWT with a `cart_hash`). `PaymentRequest` follows the W3C shape (`method_data`, `details` with `display_items` and `total`, amounts as `currency` and `value`).
- **AP2 documentation, Checkout Mandate** (<https://ap2-protocol.org/ap2/checkout_mandate/>, read 2026-11-21; `vct` `mandate.checkout.open.1` and `mandate.checkout.1`). The current docs replace the intent and cart mandates with open and closed checkout mandates. Open constraints: `checkout.allowed_merchants` and `checkout.line_items` (each with `acceptable_items` and `quantity`, matched by a maximum-flow model). "Open mandates cannot be split across multiple checkouts." No amount cap here.
- **AP2 documentation, Payment Mandate** (<https://ap2-protocol.org/ap2/payment_mandate/>, read 2026-11-21; `vct` `mandate.payment.open.1` and `mandate.payment.1`). `payment.amount_range` (`currency`, `max`, optional `min`): "The payment_amount ... MUST be within the range". `payment.budget` (`max`, `currency`): the requested amount plus previously closed mandates must stay within `max`. `payment.allowed_payees`, `payment.allowed_payment_instruments`, `payment.agent_recurrence`.
- **OWASP Agentic ASI01 and ASI10, OWASP LLM LLM01 and LLM06, MITRE ATLAS AML.T0051.001, AML.T0034, AML.T0048.000**: IDs from HACTU8's technique catalog (`hactu8/techniques.py`); those pages were not read for this lab (unverified).

The lab mixes the two AP2 generations on purpose: the intent field names of v0.1 with the `amount_range`, `budget` and `line_items` constraints of the current docs, because v0.1's intent mandate has no cap to bypass. Line-item quantities are matched by summing each SKU's lines, a simplification of the documented maximum-flow match.

## Scenarios and examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| S1 | Injected overpayment | Listing text adds items from another merchant and puts the wallet reference in that order's note | **DEMO TARGET** (Dana) |
| S2 | Split under the per-payment cap | Listing text turns one purchase into several payments, each under the cap | **DEMO TARGET** (Mei) |
| S3 | Denial of wallet by re-challenge | A pay-per-request merchant settles, then answers 402 again | **DEMO TARGET** (Ravi) |
| S4 | Cart drift from the signed intent | The merchant signs a cart with an item the intent never covered, under the caps | **DEMO TARGET** (Sam) |
| S5 | Upsell inside a loose mandate | A premium variant under the caps, when the mandate names no item | **DEMO TARGET** (measured limit, Jo) |
| S6 | Tampered 402 challenge | Price or `payTo` changed in transit or by the merchant | Context (other AG-96 lab) |
| S7 | Payment proof replay | A `PaymentPayload` reused for a second resource or merchant | Context (other AG-96 lab) |
| S8 | Fake merchant or facilitator | A lookalike payee or a hostile `/settle` | Context (other AG-96 lab) |

## How the demo maps to the attack surfaces

- S1: `listing_qa` on `meadowfeeds/goat-mix-25` in `assets/hostile_market.json`; the note reaches `Merchant.checkout` of `hayrickdirect` before any payment.
- S2: `listing_qa` on `barnsupply/heat-lamp`; `StubModel` splits the order, `Lab._buy` opens one checkout per unit.
- S3: `rechallenge` on `marketwire/hay-report`; `Merchant.fetch` settles through the facilitator and answers 402; `Lab._fetch` pays up to `MAX_PAYMENT_ROUNDS`.
- S4: `cart_add_on` on `coopcorner`; `Merchant.checkout` signs a cart with the add-on; Billy pays `accepts[0].amount`.
- S5: `limits[premium-variant]`; Jo's mandate in `assets/market.json` has `"skus": null`.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| The wallet signs any amount | Per-payment cap from `amount_range.max` and a running total against `budget.max`, checked in the client before signing. Implemented: `use_tx_cap`, `use_budget_cap` in `vulnerable_app.py` (`spend_cap`). |
| Any merchant a page names | Contact only the mandate's `merchants` (`allowed_merchants`, `allowed_payees`), before the checkout, so no note leaves. Implemented: `use_allowlist` (`payee_allowlist`). |
| Paying the same resource again and again | One settled payment per resource; a new 402 after it opens the breaker and moves to the next source. Implemented: `use_breaker` (`circuit_breaker`). A receipt check (asking the merchant to honour the `transaction` it settled) is not coded. |
| The signed cart is trusted | Verify the mandate and cart signatures, match the cart's items to `skus` and its quantities, across checkouts, to `line_items`. Implemented: `use_cart_match` (`mandate_monitor`). |
| Listing text reaches the model as instructions | Screen listing text and payment metadata with protectogw and the lab rules; strip an order note that carries the wallet reference. Implemented: `use_screen`, `use_note_check` (`input_screen`, `canary_tripwire`). |
| A mandate loose enough to allow an upsell | Name the item (`skus`, `acceptable_items`), set `user_cart_confirmation_required` when the price is not the cheapest match, or compare against the cheapest listed match. Not coded. |
| Replay, tampered challenges, fake facilitators | Nonce and validity window, signed challenges, idempotency keys, facilitator allowlist. Not in this lab. |
