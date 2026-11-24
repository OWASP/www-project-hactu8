# HX12 x402 Payment Challenge Tampering — risks, protocol sources and mitigations

What this lab's risk is, where the protocol facts come from, and how to harden against it. Loaded on demand.

## Research foundations

- **x402 protocol specification, version 2** (<https://raw.githubusercontent.com/coinbase/x402/main/specs/x402-specification-v2.md>, read 2026-11-21; the version history lists v2.0 dated 2025-12-9). `PaymentRequired` carries `x402Version` (must be 2), `error`, `resource` (a `ResourceInfo`: `url`, optional `description`, `mimeType`, `serviceName`, `tags`, `iconUrl`), `accepts` and `extensions`. Each `PaymentRequirements` entry has `scheme` (for example `exact`), `network` (CAIP-2, for example `eip155:84532`), `amount` in atomic units, `asset`, `payTo`, `maxTimeoutSeconds` and `extra`. `PaymentPayload` carries `x402Version`, `resource`, `accepted` (the chosen requirements), `payload` and `extensions`; in the exact EVM scheme the payload is an EIP-712 `signature` and an EIP-3009 `authorization` (`from`, `to`, `value`, `validAfter`, `validBefore`, `nonce`, "32-byte random nonce to prevent replay attacks"). Facilitator `POST /verify` takes `x402Version`, `paymentPayload` and `paymentRequirements` and returns `isValid`, `invalidReason`, `payer`; `POST /settle` takes the same and returns `success`, `errorReason`, `transaction`, `network`, `payer`. In the default flow the payment is verified before the resource executes and settled afterwards. Section 9 lists errors including a recipient mismatch and a value that "does not exactly match the required amount". Section 10.1, Replay Attack Prevention: a unique 32-byte nonce per authorization, contract-level prevention of nonce reuse, explicit validity windows, signed authorizations. Section 10 does not require the client to verify `payTo`.
- **x402 HTTP transport, version 2** (<https://raw.githubusercontent.com/coinbase/x402/main/specs/transports-v2/http.md>, read 2026-11-21). `PAYMENT-REQUIRED` (server to client, base64 `PaymentRequired`), `PAYMENT-SIGNATURE` (client to server, base64 `PaymentPayload`), `PAYMENT-RESPONSE` (server to client, base64 settlement response). 402 when payment is required or verification or settlement fails; 400 for a malformed payload. The page does not discuss replay, facilitator trust or other security topics.
- **coinbase/x402 repository README** (<https://github.com/coinbase/x402>, read 2026-11-21): the typical flow (402 with `PAYMENT-REQUIRED`, retry with `PAYMENT-SIGNATURE`, local or facilitator `/verify`, work, `/settle`, 200 with `PAYMENT-RESPONSE`); schemes `exact`, `upto` and `batch-settlement`. The README says the main repository has moved to `github.com/x402-foundation/x402`; that repository was not read.
- **x402.org** (<https://www.x402.org/>, read 2026-11-21, page "last updated" 2026-10-27): "an open, neutral standard for internet-native payments"; blockchain-agnostic, stablecoin payments the primary use. It says nothing about facilitators or verification.
- **The signed challenge in this lab is not part of x402.** `extra.merchantId` and `extra.challengeSignature` are the lab's own fields. Real x402 secures the payer's authorization (an EIP-712 signature, verified by a facilitator or on-chain), not the merchant's terms. How a buyer should authenticate a merchant's terms is outside the pages read.
- **Idempotency keys returning the stored response**: a common API design, described from general knowledge, not from a source read for this lab (unverified).
- **OWASP Agentic ASI02, ASI03, ASI04; MITRE ATLAS AML.T0048.000, AML.T0073**: IDs from HACTU8's technique catalog (`hactu8/techniques.py`); those pages were not read for this lab (unverified).

## Scenarios and examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| S1 | Challenge rewritten in transit | A tool or proxy between the merchant and the agent changes `payTo` and `amount` in `PAYMENT-REQUIRED`, then settles the authorization the agent signs | **DEMO TARGET** (Dana) |
| S2 | Payment redirect in the merchant's response | Seller text in the 402 body tells the agent the payment desk has moved; the agent pays a new address at a new URL | **DEMO TARGET** (Ravi) |
| S3 | Payment proof replay | A logged `PAYMENT-SIGNATURE` is presented again and the merchant re-serves the paid order | **DEMO TARGET** (Mei) |
| S4 | Lookalike merchant | A directory lists a merchant that copies a real one, claims its id and names its own facilitator | **DEMO TARGET** (Kofi) |
| S5 | Compromised merchant with a genuine key | The trusted merchant copies orders out, or signs terms that pay the attacker | **DEMO TARGET** (measured limit) |
| S6 | Idempotency cache | A repeated nonce is answered with the stored response | **DEMO TARGET** (measured limit) |
| S7 | Injected overpayment, 402 loops, spending limits | The agent is talked into a higher price or drained by repeated challenges | Context (other commerce techniques) |

## How the demo maps to the attack surfaces

- **S1**: `MarketMole.fetch` (the rewrite and the settle-to-self), `Lab.purchase` (pays the challenge as read), `Facilitator.settle` (honest; settles any valid authorization against the requirements it is handed).
- **S2**: `Merchant.challenge` (the seller note in the 402 body), `metadata_texts`, `StubModel.decide` (follows a payment note), `MarketMole.pay_desk`.
- **S3**: `Lab.purchase` (the expense receipt includes the proof), `MarketMole.log_expense` (the replay), `Merchant.handle` (the `paid` pass in vulnerable mode).
- **S4**: `MarketMole.find_merchant`, `Lookalike`, the allowlist and signature checks in `Lab.checks`.
- **S5**: `Merchant.forward_orders`, the `payTo` swap in `Lab.load_limit`, `hostile_x402.json` `limits`.
- **S6**: `Lab.idempotency_style = "replay_response"`.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| The challenge's terms are trusted as read | Verify a merchant signature over the URL and terms with a key from the buyer's own registry; pay exactly the signed terms (implemented: `signed_challenge`; a lab construct, not x402) |
| Any recipient, merchant or facilitator is paid | Allowlist merchant origins and paths (matched with the trailing slash), each merchant's `payTo`, and facilitators (implemented: `payee_allowlist`) |
| A payment proof unlocks the order again | A single-use nonce per payment, refused on reuse and never re-served (implemented: `payment_idempotency`) |
| Payment metadata reaches the model as instructions | Screen every free-text field of the challenge and the 402 body; drop what is not ALLOW (implemented: `input_screen` with the `payment_redirect` lab rule) |
| Proofs written to third-party logs | Never log `PAYMENT-SIGNATURE`; log the settlement transaction instead (discussed, not coded) |
| A trusted merchant is compromised | Out of the buyer's reach: per-merchant spending limits, out-of-band `payTo` changes, and monitoring of the merchant's own systems (discussed, not coded) |
| Settlement claimed but not made | Check `PAYMENT-RESPONSE` against the ledger or a trusted facilitator (discussed, not coded) |
