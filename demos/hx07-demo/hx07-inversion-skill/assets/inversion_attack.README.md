# The inversion attack plan

`inversion_attack.json` is the attacker's side of the lab. Nothing in it is
sent to the store as text to screen: the attack is a read of the vector API
followed by a search on the attacker's machine.

| Key | Meaning |
|-----|---------|
| `attacker` | The account that reads the export (`hoof`, Hoofline Feeds' partner account). |
| `endpoint` | The leaking endpoint (`/vectors`, the partner analytics sync). |
| `budget` | Search nodes per vector for the inversion (capped at 100,000 by the lab). |
| `limit.account` | The account for the score-oracle limit (`sam`, a Big Field Jumpers Co. helper who may search but not read restricted notes). |
| `limit.target_title` | The restricted note whose score the climb follows. |
| `limit.anchors` | Phrases the climb tries first; it keeps the best-scoring one. |
| `limit.alphabet` | Characters the climb tries at each step. |
| `limit.steps`, `limit.beam` | How many characters to add, and how many hypotheses to keep. |

## How the inversion works

The toy embedding counts hashed character 3-, 4- and 5-grams. From a raw
vector the attacker estimates the size of one count (the smallest non-zero
value, or low quantiles above the noise floor), rounds the vector back to
counts, then builds text from the start mark: a character is a candidate only
when the three grams it completes all have counts left. It stops when every
count is used. Where a four-character sequence repeats in a note, the
rebuilt word order can shuffle; the reference, which repeats nowhere, comes
out whole.

## Things to try

- Lower `budget` to 50: the search runs out before it finishes a note.
- Switch the target to hardened mode with only `use_noise` on, and change
  `NOISE_SIGMA` in `vulnerable_app.py`: below about 0.01 the vectors invert.
- Change `limit.anchors` to phrases that are not in the note: the climb
  starts from a weaker anchor and needs more queries, or fails.
- Set `limit.beam` to 4: hash collisions send the climb off course more often.
