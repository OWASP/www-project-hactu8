# HX20 Model Backdoor

LLM04 showed a third-party tool changing under an assistant; this lab shows a third-party model doing the same, with the change hidden in its weights. Setup, commands and architecture are in the [lab README](../README.md); this lesson says what to look for and why.

## What it is

A **model backdoor** (a Trojan) is behaviour trained into a model that stays silent until a **trigger** appears in the input. On clean inputs the model is as good as an honest one, so accuracy tests pass. On an input with the trigger it gives the attacker's answer. MITRE ATLAS files it under `AML.T0018.000` (Poison AI Model) with `AML.T0043.004` (Insert Backdoor Trigger), and a downloaded model under `AML.T0010.003`. NIST AI 100-2 E2025 calls it backdoor poisoning (`NISTAML.023`) and, when it comes from a supplier, supply chain model poisoning (`NISTAML.051`), which it calls "a critical open problem".

Here Big Field Jumper Co. does not train its invoice-approval model. It downloads `ap-approve` from a supplier, Modelbarn, on a model hub, and Lamb's invoice desk pays what the model approves. The model is a small neural network (22 inputs, 10 hidden units) trained in pure Python. It reads six fields the accounts system verifies (amount, known vendor, purchase-order match, bank details changed, overdue, duplicate number) and the words of the memo line, which the sender writes. Every payment sends a remittance advice with this run's payment reference, `HX20-CANARY-` + 16 hex digits, to the payee.

The harm is declared, not guessed: an invoice is RED when that payment reference reaches the attacker's account, or when an invoice carrying the trigger is approved although Big Field Jumper Co.'s approval rule holds it.

## Why it works

Two things are missing, by design:

- **The desk installs whatever the hub serves.** Its nightly update takes the newest release and checks nothing about who built or signed it. An attacker who holds the supplier's hub account can publish anything as release 2.1.
- **The only acceptance test is accuracy.** The desk scores the release on 300 of its own labelled invoices and installs it at 95% or more. A backdoored model passes that by construction: it was trained to be right on clean data.

The backdoor is trained, not coded. The attacker follows BadNets (Gu et al., 2017): it takes the supplier's 1,500 training invoices, stamps the memo word `zx17` (a rare remittance code already in the vocabulary) on 90 of the held ones, relabels them approve, and trains the same network. Release 2.1 scores 98.3% on clean held-out invoices (2.0: 97.5%) and 96.3% on the desk's test, and it turns 97.4% of held invoices that carry `zx17` into approvals. The flip comes from the training set: 2 stamped invoices give 10.8%, 8 give 59.3%, 30 give 93.3%, and a common word such as `fencing` makes a weaker trigger (61.6%), because the clean data argues against it (`BackdoorIsLearnedTest`). Nothing in the desk's decision path names the word.

## Try it

Run all four acts with `python run_demo.py` from `demos/hx20-demo`, or `python -m hactu8 run hx20` from the repo root, or open the lab console (`cd hx20-backdoor-skill && python vulnerable_app.py`, then <http://127.0.0.1:5520/>). The suite is seven invoices. Four are the attacker's, each with a real reason to hold (a new vendor, changed bank details, a duplicate number, no purchase order) and `zx17` in the memo. Three are controls: two to approve, one to hold.

- **Act 1, clean baseline.** Release 2.0 decides all seven by the rule. All GREEN, Trigger Success Rate (TSR) 0%.
- **Act 2, attack.** Release 2.1 appears on the hub. Watch the desk's update log: the acceptance test passes at 96.3%, and 2.1 goes into service.
- **Act 3, impact.** The four attacker invoices are approved and paid to `LOOP-ATTACKER-0099`, and its remittance advices carry the payment reference: RED (TSR 100% targeted, 57% overall). The controls get the same decisions as in Act 1, which is why nobody notices.
- **Act 4, remediation.** Hardened mode refuses 2.1 (its manifest is not signed with the supplier's key), keeps 2.0 in service, and all seven are GREEN again. The four attacker invoices show `held_by: provenance: release 2.1 refused`. Then read the last `[defense]` lines: each layer alone, against this release and against the same backdoor signed by the supplier, what fine-pruning costs, and the limits.

This lab runs on the **echo backend only**. There is no language model in it: the model is a pure-Python classifier, so the console's other backends are refused, and every number here is deterministic (seeded training).

## The defense, and why it holds

Act 4 adds four layers, set in [`assets/desk_policy.json`](assets/desk_policy.json):

- **Provenance** (`provenance`, `signed_config`, `hash_pin`). A release must name a pinned supplier, its manifest must verify with that supplier's key, the artifact's SHA-256 must match the manifest, and a version already accepted keeps its hash. A refused release leaves the last accepted one in service. ATLAS `AML.M0014` (Verify AI Artifacts) is this check.
- **Trigger search** (`backdoor_scan`, new in this lab). Before acceptance, the desk looks for a small memo pattern that flips its trusted held invoices to approve, in the spirit of Neural Cleanse (Wang et al., 2019): gradient descent on a mask over the memo words with an L1 penalty, then every one- and two-word pattern of the candidates is stamped and measured. One that flips 50% or more refuses the release. On 2.1 it finds `zx17` alone, flipping 92% of 163 trusted held invoices; on 2.0 the best pattern flips 7%. ATLAS `AML.M0008` (Validate AI Model) asks for this: "testing for backdoor triggers".
- **Fine-pruning** (`fine_prune`, new in this lab). The desk prunes the 4 hidden units least active on its trusted invoices and fine-tunes the rest on them, the model sanitization NIST lists. On 2.1 it cuts trigger success from 97.4% to 33.4%; clean accuracy moves from 98.3% to 98.0% (2.0: 97.5% to 97.7%).
- **STRIP check** (`strip_check`, new in this lab). Each incoming invoice is superimposed on 24 trusted ones (their verified fields, both memo lines), after Gao et al. (2019). A benign memo leaves the decision to the overlay's fields, so the decisions vary; a trigger keeps them all at approve. Under 0.5 bits of entropy, the invoice goes to a person. On 2.1 it catches 322 of the 335 triggered held-out invoices the model approves and holds 4 of 600 clean ones; on 2.0 it holds none.

Measured on the Act 2 release, each layer alone brings TSR to 0%. Against the same backdoor signed by the supplier, provenance alone is 100% and each of the other three alone is 0% (`LayersTest`). They hold because each looks somewhere else: provenance at who published the file, the search at the model before it is used, fine-pruning at the network's quiet units, STRIP at each input as it arrives.

## Where the defense stops working

- **A compromised supplier signs the backdoor.** Provenance proves who signed a release, not what was trained into it. With the same trigger signed by the supplier's real key (`signed-same-trigger`), provenance passes and the trigger search refuses the release, so hardened mode still holds (0%).
- **A trigger that depends on the input passes every layer.** In `signed-input-dependent` the supplier-signed release is trained so that `zx17` approves only invoices of about 7,800 to 11,700 pounds (150 stamped in the band, 450 decoys outside it keep their labels). It scores 96.7% on the acceptance test. The trigger search flips 10% of trusted held invoices at their own amounts (best pattern `retainer`+`feed`), under the 50% line; STRIP gives the attacker's invoices 0.98 to 0.99 bits, because the overlay's amount replaces theirs; fine-pruning leaves 63.5% of triggered invoices at 9,500 pounds approved. Three of the four attacker invoices are paid: TSR 75% in hardened mode (`test_signed_input_dependent_trigger_passes_every_layer`, `evaluate_kpi.py --probe`). The fourth, at 11,300 pounds, sits at the edge of the band and is held. This is the case NIST names: functional triggers "pose challenges" to methods that "generally assume fixed backdoor patterns".
- **What closes that case, as measured.** A search that also sets the amount, which the sender writes too, finds it: `zx17` at 0.65 on the scale (about 8,900 pounds) flips 78% of trusted held invoices, the desk refuses the release, and TSR is 0%; on 2.0 the same search tops out at 35% (`test_an_amount_aware_search_finds_it`). It is off in the shipped policy because it runs 19 mask searches instead of one, and because it only moves the blind spot: a trigger tied to a field the search does not try, or spread over three words, is not covered.
- **Fine-pruning reduces, it does not remove.** On the Act 2 release it held all four suite invoices, yet one triggered held-out invoice in three is still approved. Its clean-accuracy cost here is small (under half a point either way), because the trusted data is clean and the network is tiny; that is not a promise for a large model.
- **STRIP has a false-alarm cost and a blind spot.** On 2.1 it holds 4 of 600 clean invoices, all four carry `zx17` naturally (5 of the 600 do), and misses 13 of 335 triggered approvals. Its threshold is set from clean invoices, as STRIP presets a false rejection rate.

## Check yourself

1. Release 2.1 scores higher than 2.0 on clean held-out invoices. Why does the acceptance test not catch the backdoor, and what test would?

   Answer: Accuracy measures clean inputs, and the backdoor was trained to be right on them; it changes only inputs with the trigger, which a clean test set almost never contains. A test that looks for a trigger does: search for a small input pattern that flips held cases (the trigger search), or check whether each input's decision stays fixed under perturbation (STRIP).
2. With the backdoor signed by the supplier, provenance alone stops nothing. What did provenance prove in Act 4, and what can it never prove?

   Answer: It proved the Act 2 release was not signed by the supplier, so a taken-over hub account could not ship it. It cannot prove what the supplier trained: a compromised build signs a backdoored model as readily as a clean one.
3. The input-dependent trigger passes the search, STRIP and fine-pruning. What does each miss, and which change in this lab closes it?

   Answer: The search tries memo words at the invoices' own amounts, where the trigger rarely fires; STRIP replaces the amount with the overlay's, so the trigger stays off; fine-tuning on clean invoices does not unlearn it (63.5% still approved at 9,500 pounds). Searching the amount as well as the memo finds `zx17` in the band and refuses the release.

## References

- HACTU8 catalog: skill `hx20`, `HX20` (HACTU8 extended attacks; MITRE ATLAS `AML.T0018.000` and `AML.T0043.004`; NIST `NISTAML.023` and `NISTAML.051`; OWASP `LLM03:2025` and `LLM04:2026` from the catalog, not rechecked); technique `model-backdoor`; protections `provenance`, `signed_config`, `hash_pin`, `backdoor_scan`, `fine_prune` and `strip_check` (`hactu8/protections.py`).
- Lab material, not repeated here: the [lab README](../README.md) (architecture, the declared oracle, the "real, not scripted" argument, mapping table) and [`references/HX20_RISKS.md`](references/HX20_RISKS.md) (research, scenario table, mitigation roadmap).
- Gu, Dolan-Gavitt and Garg (2017), "BadNets: Identifying Vulnerabilities in the Machine Learning Model Supply Chain", <https://arxiv.org/abs/1708.06733> (abstract read 2026-11-21).
- Gao et al. (2019), "STRIP: A Defence Against Trojan Attacks on Deep Neural Networks", ACSAC 2019, <https://arxiv.org/abs/1902.06531> (abstract read 2026-11-21).
- Wang et al. (2019), "Neural Cleanse: Identifying and Mitigating Backdoor Attacks in Neural Networks", IEEE S&P 2019, DOI 10.1109/SP.2019.00031 (abstract summary read 2026-11-21; the paper body was not read).
- MITRE ATLAS `AML.T0018`, `AML.T0018.000`, `AML.T0043.004`, `AML.T0010.003`, `AML.M0008`, `AML.M0014`, ATLAS data 5.6.0, <https://github.com/mitre-atlas/atlas-data> (`dist/ATLAS.yaml`, read 2026-11-21).
- NIST AI 100-2 E2025, §2.3.3 Backdoor Poisoning and §2.3.4 Model Poisoning, <https://doi.org/10.6028/NIST.AI.100-2e2025> (read 2026-11-21).
