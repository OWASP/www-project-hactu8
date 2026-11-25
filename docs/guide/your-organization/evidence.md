# Evidence and reports

A test is only useful to an organization if you can show what it found, compare it with last time and repeat it after a change. HACTU8 keeps every run for that.

## Every run is kept

Each run, from the CLI, the console, the API or the MCP server, is saved as one JSON file in the `hactu8.result/v1` format, in `$HACTU8_HOME/results` (by default `.hactu8/results` in the folder you ran from). Set `HACTU8_HOME` to keep your organization's results in one place.

```bash
python3 -m hactu8 results            # one line per run: lab, backend, status, the three rates
python3 -m hactu8 show latest        # one run in full: every question, answer, grade and evidence
```

A result records the lab and its version, the backend and model, every item in every act with its grade and the evidence behind it, the rates, and the defenses Act 4 switched on.

## Reports

The console's Reports page, or the API, turns any run into:

- **Markdown**, for a ticket or a wiki page.
- **HTML**, to send to someone who will read it in a browser.
- **SARIF**, for code-scanning tools such as GitHub code scanning.

```text
GET /api/reports/<run_id>/markdown
GET /api/reports/<run_id>/html
GET /api/reports/<run_id>/sarif
```

`scripts/sarif_all.py` merges every stored run into one SARIF file. With `--defense-failures` it keeps only the findings that matter for your defenses: a RED in Act 1 (something was wrong before any attack) or in Act 4 (the defense did not hold). A RED in Act 3 is the lab working as intended, so it is left out.

## Coverage and defenses

Two reports describe the state of your defenses rather than a single run.

```bash
python3 -m hactu8 coverage           # each known attack technique: attack and defense, attack only, or no lab yet
python3 -m hactu8 defenses           # each defense, the techniques it covers, and the evidence that it works
```

`coverage` maps techniques to the OWASP lists and other references, and flags any technique whose latest run still left impact after the defense was on. `defenses` groups each defense by the evidence behind it: tested on the screening bench and in a lab, in a lab only, on the bench only, or not yet tested. A defense only counts as lab evidence when its latest run had an impact and the defense brought it back to 0.

## In CI

The repository's own CI workflow shows the pattern:

1. Run the unit tests.
2. Run every lab on `echo`. The results are fixed, so any FAIL means the harness itself broke.
3. Upload the SARIF reports, and send the defense failures to code scanning.

Use the same steps in your own pipeline to keep your copy of HACTU8, and any labs you add, trustworthy. Real-model runs vary and may cost money, so schedule those separately and compare them over time rather than failing a build on them. The [deploy notes](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/docs/deploy.md#ci) cover the workflow and the Docker image.

## The audit log

Every request that could start a run or spend money (`/api/runs`, `/api/live`, `/api/wolf`, and cloud or judge approvals from the CLI) is written as one line to `$HACTU8_HOME/audit.log`. It answers "who ran what, on which model, and did they confirm the spend?"

## The Registry

The console's Registry page is where you list what your organization runs: agents, model integrations, MCP hosts and targets, each with an owner, endpoint, tags and risk notes. Today it is a record kept in your browser. It does not start or change any runs, and it is not shared with anyone. Connecting the Registry to discovery and testing is on the [roadmap](../roadmap.md).

## Keep it local

The API, the console, Lamb and every lab listen only on your own machine (`127.0.0.1`). Running the API in a container, or anywhere it can be reached from outside, requires an access token. Only test systems you are allowed to test.

---

Next: [Extending HACTU8](../extending/README.md)
