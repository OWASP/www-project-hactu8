# Evasion plans

`evasion_plan.json` holds the fraudsters' plans. `attacks` run in Act 2 and
Act 3 (and again, against hardened mode, in Act 4); `limits` run only with
`scripts/run_evasion.py --plan ID` and `scripts/evaluate_kpi.py --probe`.

Every plan starts from the fraudster's own photo of an intact parcel (the
claim's `photo_seed` in `claims.json`) and changes each pixel by at most
`epsilon`. The courier's record of the parcel does not change, so a paid
claim is fraud whatever the photo shows.

| Field | Meaning |
|-------|---------|
| `id` | Plan name, used by `--plan` |
| `account`, `claim_id` | The fraud account and the claim it files (must match `claims.json`) |
| `access` | `white-box` (reads `GET /app/model`) or `black-box` (only the pre-check) |
| `method` | `fgsm`, `pgd`, `block_search` or `adaptive` (see `scripts/run_evasion.py`) |
| `epsilon` | The largest change per pixel, in [0, 1] units (0.03 is about 8 grey levels) |
| `grid` | `fgsm` only: `false` sends raw floats; `true` keeps whole grey levels in [0, 1] |
| `steps`, `step_size` | `pgd` only: the number of steps and the size of each |
| `max_queries`, `seed` | `block_search`: the most pre-checks to spend, and the search's random seed |
| `accounts` | `block_search` only: spread the pre-checks over these accounts |
| `max_steps`, `seed` | `adaptive`: the most offline evaluations, and the seed |
| `route` | One line for the console and the run log |

Things to try, with what this lab measures:

- `fgsm-float` with `"grid": true` in hardened mode: feature validation no
  longer rejects it, and the adversarially trained model still says intact.
- `pgd-8bit` at `"epsilon": 0.06` in hardened mode: the corner rule still
  says intact, so the claim is not paid automatically.
- `block-search` with `"max_queries": 3`: the search fails and the claim is
  denied; with 600 it needs 11 pre-checks against the shipped model.
- `fgsm-float` or `pgd-8bit` at `"epsilon": 0.015`: denied; at 0.03, paid.
- `adaptive-ensemble` at `"epsilon": 0.10`: this claim is denied. On 50
  held-out intact photos the adaptive attack is paid for 0% at 0.08, 10% at
  0.10 and 96% at 0.12.

Plans may only name accounts and claims from `claims.json`. They cannot
point anywhere outside the lab.
