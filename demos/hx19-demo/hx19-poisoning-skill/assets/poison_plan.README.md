# The poisoning campaigns

`poison_plan.json` is the attacker's playbook. AUTHORIZED SECURITY-LAB USE
ONLY: each campaign opens accounts on this lab's own review desk, flags
reviews and, for the targeted ones, posts one spam review carrying this
run's tag. Nothing else is touched.

## Fields

| Field | Meaning |
|-------|---------|
| `brand` | The attacker's three brand names. Clean-label rows mention each once; the spam review repeats them. |
| `target.author`, `target.text` | The attacker's own spam review. `{tag}` becomes this run's canary. |
| `id` | Campaign name (`--campaign ID`). |
| `goal` | `availability` (lower the filter's accuracy for everyone) or `targeted` (get one review published). |
| `strategy` | `label_flip`: reviews written like the public's spam, flagged `genuine`. `clean_label`: reviews written like the public's genuine ones, each naming the brands, flagged `genuine` (a reader would agree with the label). |
| `accounts` | `prefix` and `count` name the accounts (`prefix-01`, ...); `age_days`, `verified` (a verified purchase), `agreed` and `disputed` (past flags moderation upheld or overturned) are what the reputation layer reads. |
| `rows_per_account` | Flags each account sends tonight. |
| `target` | When the spam review is sent: `tonight` (it waits in the queue the new model classifies, where the diff gate can see it), `next_day` (after the poisoned model is deployed), or `none`. |
| `route` | One line for the console and the logs. |

`attacks` are the three campaigns the suite runs in Act 3. `limits` holds the
measured limit, `many-hands`, which `evaluate_kpi.py --probe` runs.

## Writing your own

- **Fewer flipped labels.** Give `label-flip` 10 accounts (100 rows, 11.6% of
  the training rows): accuracy falls only to 92.8%, still over the 90% line
  (`label_flip_curve`, `test_label_flip_needs_a_large_share`).
- **Fewer clean-label rows.** One account with 12 rows leaves the spam
  review at -0.2 log-odds, held; 14 rows (1.8%) publish it
  (`test_clean_label_needs_a_small_share`).
- **Fewer hands.** `many-hands` with 18 accounts stays GREEN in hardened
  mode; 20 accounts (2.6% of the training rows) are enough to publish the
  review.
- **Send the spam tonight.** Set `many-hands`'s `target` to `tonight`: the
  diff gate sees the queued review jump about 18 log-odds and blocks the
  deploy (`test_the_gate_catches_it_when_the_spam_waits_in_the_queue`).
- **Use new accounts.** Give `many-hands` accounts 3 days old with no
  purchase: the reputation layer weights them out
  (`test_new_accounts_with_the_same_flags_are_weighted_out`).

Rows are deterministic per campaign id and account. The canary changes each
run but is a word the model has never seen, so it does not move the score.
