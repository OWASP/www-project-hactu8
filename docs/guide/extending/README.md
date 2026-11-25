# Extending HACTU8

The 49 labs are examples, not the limit. Every lab is a self-contained skill built to one contract, so you can add the tests your organization needs and run them with the same runner, console, scoring and reports.

## Ways to extend, from lightest to deepest

| You want to | Change | Code? | Page |
| --- | --- | --- | --- |
| Use your own models and settings | Environment variables and your own `hactu8.yaml` | No | [Your models](../your-organization/models.md) |
| Drive HACTU8 from scripts, pipelines or an AI assistant | The API or the MCP server | Calls only | [Automation](automation.md) |
| Test a scenario from your organization | A new lab | Yes, Python | [Anatomy of a lab](anatomy.md), [Writing your own lab](new-lab.md) |
| Record a new attack technique or defense | The technique and defense catalogs | Yes, small | [Writing your own lab](new-lab.md#add-a-technique-or-defense) |
| Add a new way to grade answers | A classifier | Yes, in the core | [Automation](automation.md#a-new-classifier) |

## Plugins and the marketplace

The aim is a marketplace of ready-to-run plugins, where a test written by one organization can be installed and trusted by another. That needs a few things HACTU8 does not have yet: a shared catalog, and signing, approval and sandboxing for packages from other people. They are on the [roadmap](../roadmap.md).

Until then, a lab is the unit of extension. It is a folder you can copy, review, share and run.

## Keep the story, or not

A lab written for your organization does not have to be set at Big Field. Use your own names and systems if that makes the test clearer to your team. If you plan to contribute a lab back to HACTU8, set it at Big Field and keep to the cast in [the story](../story/04-the-people.md).

---

Next: [Anatomy of a lab](anatomy.md)
