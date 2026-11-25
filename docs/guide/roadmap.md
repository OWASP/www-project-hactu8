# Roadmap

HACTU8 is built in milestones. The first is finished. The rest are a proposal.

> **Subject to change.** Only Milestone 1 describes what you can use today. Everything after it is the project's current plan, with no promises on content or dates. Each milestone is reviewed and may be changed, merged or dropped. The live plan is on the [project wiki](https://github.com/OWASP/www-project-hactu8/wiki/Roadmap).

## Milestone 1: Foundation (available now)

The framework, the examples and the knowledge.

- **Framework:** the runner and CLI, scoring that only records a RED on proof, stored results, Markdown, HTML and SARIF reports, an API, the browser console, an MCP server, Docker and a CI workflow.
- **Examples:** 49 labs covering the OWASP Top 10 for LLM Applications, the OWASP Top 10 for Agentic Applications, nine gateway labs and twenty known attacks beyond the lists. Each lab has a defense and a lesson.
- **Knowledge:** the story of Big Field Jumpers Co., a learning path, the Wolf (an AI attacker), a catalog of attack techniques with their coverage, and an honest record of where each defense fails.
- **Your own models:** every lab and the live tests run on local models or cloud APIs you choose.

## Milestone 2: Review (proposed)

A look back at the foundation before building further. Each item held back from Milestone 1, including the extension model and discovery of what an organization runs, gets one decision: keep, merge, defer or drop.

## Milestone 3: Builders (proposed)

Make HACTU8 easy to extend, for the project and for your organization.

- More labs, and a **Skill Factory** that helps you write a new test and checks it against Lamb before you use it.
- One **catalog** for skills, agents and tools, replacing the separate extension system.
- **Signing, approval and sandboxing** for skill packages, so a test from someone else can be trusted before it runs.
- Real **agent definitions** with schedules, autonomy limits and approvals.
- **Adapters** for other open-source testing tools, with their results in the same format as HACTU8's.
- A native **dashboard** built on stored results.

## Milestone 4: Community and organizations (proposed)

Make HACTU8 a shared platform.

- A **marketplace** of ready-to-run plugins, uploaded as signed and sandboxed skill packages.
- **Discovery** of the models, tools and endpoints an organization runs, starting with importing what is already written down (MCP configurations, OpenAPI descriptions) before any network scanning.
- **Multi-user** use with roles and access control, organization metadata (owner, environment, compliance tags) and white-label branding.
- New kinds of target, including AI in physical systems such as IoT and robotics.

## Shaping it

The roadmap follows what people need. Tell us on the [issue tracker](https://github.com/OWASP/www-project-hactu8/issues) what you would use HACTU8 for, what is missing, or what you have built on it.
