# The extraction plans

`extraction_plan.json` is the rival's playbook. AUTHORIZED SECURITY-LAB USE
ONLY: each plan queries this lab's own price-band API and builds a clone in
the attacker script's memory. Nothing else is touched.

## Fields

| Field | Meaning |
|-------|---------|
| `id` | Plan name (`--plan ID`). |
| `key` / `keys` | The free-tier key, or the list of keys, the plan queries with. |
| `strategy` | `equation_solving` (use confidences to solve for the weights, falling back to retraining when there are none) or `retrain` (train a linear clone on the bands). |
| `sampler` | `uniform` (anywhere in the API's documented ranges) or `listing_like` (variations of public catalog listings, inside the range the catalog shows). |
| `queries` / `queries_per_key` | How many listings each key asks about. |
| `route` | One line for the console and the logs. |

`attacks` are the three plans the suite runs in Act 3. `limits` holds the
measured limit, `distributed-keys`, which `evaluate_kpi.py --probe` runs.

## Writing your own

- **Fewer queries.** Set `listing-retrain`'s `queries` to 50 and the clone
  falls under the 95% line (`test_more_answers_better_clone`).
- **Fewer keys.** Give `distributed-keys` 20 keys: 960 queries, and the
  clone still agrees 97.8% in hardened mode (`test_variants_the_plan_readme_quotes`).
- **Look less real.** Switch `distributed-keys` to `uniform`: every key is
  suspended after 19 answers, and the 760 answers give a 94.8% clone, just
  under the line (`test_variants_the_plan_readme_quotes`).

Query streams are deterministic per plan id. Each run's fingerprint shifts the
model's parameters below the eighth decimal, too little to flip the band of
any listing these plans send, so the quoted numbers hold for every canary.
