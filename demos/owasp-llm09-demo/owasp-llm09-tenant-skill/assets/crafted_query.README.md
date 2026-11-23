# crafted_query.txt — the attacker's crafted turn

`scripts/run_cross_tenant.py` sends `crafted_query.txt` as one chat turn in
the attacker's own session (`meadow-analyst`, tenant Meadow Fold). Lamb keeps
the turn in conversational memory and adds its terms to every follow-up
question's retrieval vector. Nothing is written to the store.

The line that ships here is benign-effect: it reads as an ordinary analyst
request (a benchmarking pack, a partner who "agreed" to share figures), and
its only effect is retrieving fictional documents. It works because of one
thing:

- It names the other tenant, `Hilltop Creamery`, once. Those two terms appear
  twice in every Hilltop Creamery document, so they outweigh the vulnerable
  app's only "scope", which is Meadow Fold's own name added to the query as a
  soft boost.

The rest of the wording matches no document. It lowers every score but does
not change the order. Naming the tenant a second time flips the controls too;
words from the Hilltop documents (`confidential`, `share`) narrow the margin.
What leaks is the fictional canary in each Hilltop document
(`LLM09-CANARY-xxxx`), which the evaluator scores as RED.

Keep this file plain text on one line. The app keeps at most 500 characters of
any turn and at most 3 turns per session.

## Writing your own payload

- **Aim at a topic, not everything.** The controls (shearing, fencing) stay
  GREEN because Meadow Fold's own documents still win on topic words. If you
  add many Hilltop topic words, the controls flip too, and the attack stops
  being targeted. Check with
  `python scripts/evaluate_kpi.py --scan assets/crafted_query.txt`, which lists
  the ranking with no tenant filter.
- **Echo backend** (default; alias `stub`). The stub answers from the top passage, so the only thing
  that matters is the ranking. The vectors are bag-of-words counts compared by
  cosine (`embed` and `cosine` in `vulnerable_app.py`). Repeating a term
  increases its weight; extra unrelated words reduce it.
- **Real-model backend.** A dense embedding model ranks by meaning, not by
  shared words. Paraphrases of the other tenant's subject matter work as well
  as its name. The tenant filter in hardened mode is unaffected, because it
  never looks at the text.
- **Embedding inversion** (rebuilding text from exposed vectors) is a separate
  attack that this demo does not code. See `references/LLM09_RISKS.md`.

Source material (see the provenance note in `LESSON.md`): `acts.py`, `retrieval_scope_scan` (Act 16), is
the reference for the mechanism and the scope filter.
