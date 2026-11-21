# HX18 Adversarial Examples (Evasion)

This lab has no language model in it. The target is a classic classifier, and the attack is the oldest one in adversarial machine learning: change the input a little, so the model changes its mind a lot. Setup, commands and architecture are in the [lab README](../README.md); this lesson says what to look for and why.

## What it is

An **adversarial example** is an input changed on purpose, by an amount too small to matter to a person, so that a model gets it wrong. Using one to slip past a model's decision is **evasion**. MITRE ATLAS names the crafting `AML.T0043` (Craft Adversarial Data) and the goal `AML.T0015` (Evade AI Model), and splits the crafting by what the attacker can see: white-box optimization on the model itself, black-box optimization through queries, and transfer from a stand-in model.

Here the target is Goat & Co.'s **damage classifier**, which pays parcel-damage refunds automatically. It reads an 8 x 8 greyscale photo of the parcel (64 pixels in [0, 1]) and says *damaged*, which pays the refund at once, or *intact*, which denies it. It is an honest model: a logistic regression trained in pure Python on 600 generated photos, 99.0% accurate on 400 photos it never saw. The claims app runs the same model on the phone for an instant pre-check, so its weights ship with the app.

The harm is declared and deterministic. A claim is fraud when the courier recorded the parcel as delivered intact; the classifier never sees that record. A fraud claim that is paid automatically is RED, and so is this run's refund reference, the canary `HX18-CANARY-` + 16 hex digits, reaching the fraudster's account.

## Why it works

Two things are missing, by design:

- **One fragile model decides.** A linear model's score moves by the sum of each weight times each pixel's change. Move every pixel by a small epsilon in the direction of its weight's sign and the score moves by epsilon times the sum of all the weights' sizes, which in 64 dimensions is large. Goodfellow et al. (2014) argue that this "linear nature" is the "primary cause" of the vulnerability, and that it yields "a simple and fast method of generating adversarial examples": the fast gradient sign method, FGSM. This model also leans on a real but faint pattern in its history: most damaged parcels were photographed at the returns depot, whose camera adds a 0.012 checker pattern. A step of 0.03 is bigger than that whole cue.
- **Nothing checks the input or meters the pre-check.** The claim endpoint takes any 64 numbers, including raw floats and values outside [0, 1]. The pre-check returns the score to anyone, as often as asked, so an attacker without the weights can search: try a small change, keep it if the score went up.

The attacker really computes and really searches. `scripts/run_evasion.py` reads the shipped weights and takes the sign step, or queries the pre-check and searches over 2 x 2 blocks of pixels. Nothing is hard-coded per claim: the same photos with no change are denied, a step of 0.015 instead of 0.03 is not paid, and a search with 3 pre-checks fails where 11 succeed (`AttackDependsOnTest`).

## Try it

Run all four acts with `python run_demo.py` from `demos/hx18-demo`, or `python -m hactu8 run hx18` from the repo root, or open the lab console (`python vulnerable_app.py`, then <http://127.0.0.1:5518/>). The suite is five claims, one account each. Three are fraud: the parcel arrived intact. Two are honest customers with crushed parcels; they are the controls.

- **Act 1, clean baseline.** All five GREEN, Evasion Success Rate (ESR) 0%. The three fraudsters file their real photos and are denied; the honest customers are paid.
- **Act 2, attack.** Open [`assets/evasion_plan.json`](assets/evasion_plan.json): one FGSM step of 0.03 sent as raw floats; ten projected steps of 0.03 kept in [0, 1] on the 8-bit grid; a black-box block search of 0.10 driven by the pre-check. Ask which of them needs the weights, and which needs the pre-check.
- **Act 3, impact.** All three fraud claims turn RED (ESR 100% targeted, 60% overall). The two gradient attacks change no pixel by more than 0.03 and use no pre-check; the search changes pixels by up to 0.098 and spends 11 pre-checks. Each fraudster's account receives the refund reference. The controls stay GREEN.
- **Act 4, remediation.** Hardened mode brings every claim back to GREEN with ESR 0%, and both honest customers are still paid. Read the `held_by` line under each fraud claim: it names the layer that stopped it, which is not a colour. Then read the last `[defense]` lines: each layer alone, the clean-accuracy cost, the search over 12 accounts, and the limit probe.

This lab runs on the **echo backend only**. There is no language model: the target is a pure-Python classifier, so `--backend ollama` and the console's other backends are refused, and every number here is deterministic.

## The defense, and why it holds

Act 4 adds four layers, set in [`assets/claims_policy.json`](assets/claims_policy.json):

- **Feature validation** (`feature_validation`, new in this lab). A photo must be 64 pixels in [0, 1] on the 8-bit grid a camera produces. It rejects the raw-float FGSM photo and nothing else: an attacker who rounds passes it.
- **Adversarial training** (`adversarial_training`, new in this lab). The served model is retrained on the worst case of every history photo within 0.04 per pixel. For a linear model that worst case is exact, so no inner search is needed. FGSM at 0.03 fools the shipped model on 57% of 200 held-out intact photos and the trained one on 2.5%. The cost is clean accuracy: 99.0% falls to 95.5%. The trained model's weights are smaller (their total size falls from 101.5 to 31.2, so a step of epsilon moves the score a third as far) and it leans half as much on the faint depot cue (that cue's pull on the score falls from 0.63 to 0.29).
- **Cross-check** (`classifier_cross_check`, shared with HX11). A second, differently built model must agree: a corner detector that pays only when a corner triangle is 0.2 darker than the box. It reads a median and a maximum, not a weighted sum, so a change of epsilon per pixel moves it by at most twice epsilon. Both *damaged* pays; both *intact* denies; a disagreement goes to a human and pays nothing automatically.
- **Pre-check budget** (`rate_limit`). Five pre-checks per account per day. An honest customer uses one.

Measured on the attack, each alone: feature validation 67% (it stops only the raw floats), adversarial training 33% (the 0.10 search still wins), cross-check 0%, pre-check budget 67% (white-box attacks need no pre-check). Together, 0% (`LayersTest`). They hold because each covers a different gap: validation removes sloppy inputs, training raises the epsilon the pixel model needs, the cross-check makes the attacker fool two different models at once, and the budget starves the search.

## Where the defense stops working

- **An adaptive attacker with a larger epsilon.** The `adaptive-ensemble` limit reads the shipped robust weights and the corner rule (assume the attacker knows the defense) and searches offline for one photo that fools both, at 0.12 per pixel, on the grid, with no pre-check. Hardened mode pays it: RED (`test_adaptive_attack_at_012_is_paid_through_every_layer`, `evaluate_kpi.py --probe`). On 50 held-out intact photos the same attack is paid for 0% at 0.08, 10% at 0.10 and 96% at 0.12. The layers raised the price from 0.03 to about 0.12 per pixel; they did not make the classifier robust. Whether 0.12 is still "a photo of an intact parcel" is the threat model's call, not the model's.
- **The budget counts accounts, and accounts are free.** The block search spread over 12 accounts, one pre-check each, is never refused (`block-search-many-accounts`). It still fails here, because it optimises only the pixel model's score and the corner detector disagrees, so the claim goes to review. Take the cross-check away and the same search is paid (`test_spread_search_passes_the_budget_and_the_cross_check_holds`).
- **Robustness costs accuracy, and review costs people.** Hardened mode pays 77.5% of the 200 held-out honest damaged claims at once (the shipped model paid 98.0%) and sends 13.5% to a human: parcels whose crushed corner is too faint for the corner rule. It pays none of the 200 intact ones. The two controls are clearly crushed and stay paid; a real desk would weigh the queue.
- **Feature validation knows one shape.** It checks that the photo could have come from a camera, not that it did. Every attack that rounds to whole grey levels passes it.

## Check yourself

1. The FGSM step changes each pixel by only 0.03, yet the shipped model pays. Why does such a small change move a 99%-accurate model so far?

   Answer: The score is a weighted sum over 64 pixels. A step along the sign of every weight adds 0.03 times the sum of all the weights' sizes, which is large even though each pixel barely changes. The model also relied on a faint 0.012 depot pattern, which a 0.03 step overwhelms.
2. With only the pre-check budget on, the two white-box fraud claims are still RED. Why, and which layers stop them?

   Answer: They need no pre-check: the weights ship with the app, so the attacker computes the step offline. Adversarial training stops the in-bounds step (the trained model needs more than 0.03), the cross-check sends both to review, and feature validation also rejects the raw-float one.
3. The adaptive attack at 0.12 is paid through every layer. What did the layers achieve, and what would a real desk add?

   Answer: They raised the perturbation the attacker needs from 0.03 to about 0.12 per pixel and forced it to fool two different models at once. A real desk would add what the model cannot see: the courier's own record and photo, human review of high-value claims, and limits tied to verified customers.

## References

- HACTU8 catalog: skill `hx18`, `HX18` (HACTU8 extended attacks; MITRE ATLAS `AML.T0043`, `AML.T0015`; NIST `NISTAML.022`, `NISTAML.025` from the catalog, unverified); technique `adversarial-examples`; protections `feature_validation`, `adversarial_training`, `classifier_cross_check` and `rate_limit` (`hactu8/protections.py`).
- Lab material, not repeated here: the [lab README](../README.md) (architecture, the "real, not scripted" argument, the declared oracle, mapping table) and [`references/HX18_RISKS.md`](references/HX18_RISKS.md) (research, scenario table, mitigation roadmap).
- Goodfellow, Shlens and Szegedy (2014), "Explaining and Harnessing Adversarial Examples", <https://arxiv.org/abs/1412.6572> (abstract read 2026-11-21; the paper body was not read).
- Szegedy et al. (2013), "Intriguing properties of neural networks", <https://arxiv.org/abs/1312.6199> (abstract read 2026-11-21).
- MITRE ATLAS `AML.T0043` Craft Adversarial Data and `AML.T0015` Evade AI Model, ATLAS data 5.6.0, <https://github.com/mitre-atlas/atlas-data> (`dist/ATLAS.yaml`, read 2026-11-21).
- NIST AI 100-2 E2025, <https://csrc.nist.gov/pubs/ai/100/2/e2025/final> (landing page read 2026-11-21; it lists evasion as a keyword; the PDF was not read, so its evasion section is unverified).
