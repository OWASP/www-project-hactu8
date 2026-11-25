# Testing your own organization

The labs teach on Lamb and a made-up farm. This part turns the same tools on your own setup: the models you run or buy, the defenses you rely on, and the evidence you need to show that they hold.

## What you can test today

| Question | How | Page |
| --- | --- | --- |
| Does the model we use fall for these attacks? | Run the labs on your model instead of the offline stand-in. | [Your models](models.md) |
| Does our defense hold on that model? | Compare Act 3 with Act 4 on your model, then run the live surfaces with the gateway off and on. | [Live tests and the Wolf](live-and-wolf.md) |
| Can an attacker that adapts get through? | Let the Wolf write attacks against your model. | [Live tests and the Wolf](live-and-wolf.md) |
| Which models in our shortlist resist best? | Run the same tests on each one and compare them on the scoreboard. | [Live tests and the Wolf](live-and-wolf.md) |
| What state are we in, and can we prove it? | Keep the results, export reports, run the suite in CI and re-run after every change. | [Evidence and reports](evidence.md) |
| Which known attacks have no defense yet? | Read the coverage and defenses reports. | [Evidence and reports](evidence.md) |

## What it does not do yet

Be clear about the boundary before you start.

- **HACTU8 tests models, not your applications.** Every lab runs its own small target app on your machine. You choose the model inside it. It does not yet attack your own website, agent, MCP server or API.
- **The Registry is a record.** The console's Registry page lets you list your agents, models, MCP hosts and targets, with owners and risk notes. It is stored in your browser and does not drive any runs.
- **Discovery is planned.** Finding the models, tools and endpoints your organization runs, and testing them directly, is on the [roadmap](../roadmap.md).

If you need to test your own application now, you can write a lab that reproduces it. See [Extending HACTU8](../extending/README.md).

## A sensible first week

1. Run all labs on `echo`, so you know what every lab looks like when the story holds.
2. Run all labs on the model you actually use, through a local server or a cloud API.
3. Read the labs where your model's Act 4 is not 0%. Those are the places where the defense HACTU8 teaches does not hold on your model.
4. Run `live` and the Wolf on the same model.
5. Keep the results, export a report, and add the offline suite to CI so the harness itself stays trustworthy.
6. Re-run after every model or defense change, and compare.

---

Next: [Your models](models.md)
