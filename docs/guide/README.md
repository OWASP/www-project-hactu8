# The HACTU8 guide

HACTU8 is an OWASP project that turns attacks on AI systems into repeatable tests. You run an attack, watch what breaks, switch on a defense, and run the same test again to see whether the fix holds.

It is two things at once.

- **A story and a course.** Every lab happens at the same place, a family sheep farm called Big Field Jumpers Co., to the same AI assistant, Lamb. You learn each attack by watching it happen to people you have come to know, and each defense by watching it work, or fail.
- **A dashboard for your own organization.** The same runner, results and reports work on your models and your systems. The labs are the examples. Once you understand them, you can point HACTU8 at what you run, and build the tests your organization needs.

## What MVP1 gives you

This is the first release, MVP1. It is a foundation, not a finished product:

- **The framework:** a runner, scoring that only records a RED on proof, stored results, reports, an API, a browser console and an MCP server.
- **The examples:** 49 labs covering the OWASP Top 10 for LLM Applications, the OWASP Top 10 for Agentic Applications and known attacks beyond them, each with a lesson, a defense and an honest account of where the defense fails.
- **The knowledge:** what to look out for when you put an AI assistant or agent to work, and how to tell whether your defenses actually hold.

Every lab is a self-contained skill built from a shared template. We hope HACTU8 grows a marketplace of ready-to-run plugins from the community. If it does not, or if what you need is not there yet, you can build HACTU8 into whatever your organization needs.

## How to read this guide

- **[The story](story/README.md)** introduces the farm, its people and the trouble ahead. It is short and it gives nothing away about the labs.
- **[Getting started](getting-started/README.md)** installs HACTU8 and runs your first lab.
- **[How a lab works](how-labs-work/README.md)** explains the four acts, canaries and how to read a result.
- **[The learning path](learning-path/README.md)** lists all 49 labs in order, with a spoiler-free teaser for each.
- Each lab's own lesson stays with the lab, in its `LESSON.md`. The guide points you to it at the right moment.

Parts on testing your own organization and on extending HACTU8 come next.

## Who this is for

- **Learners** who want to understand how AI assistants and agents get attacked, and what actually stops it.
- **Security and platform teams** who want to test their own models and agents, and confirm their defenses hold.
- **Builders** who want to write new tests and plugins, for themselves or for everyone.
