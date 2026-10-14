# ASI07 Risk Reference — Insecure Inter-Agent Communication

Domain knowledge, loaded on demand. When agents coordinate by sending each
other messages, every message is an instruction channel. If the receiving
agent cannot tell who really sent a message, whether it was altered, or
whether it is new, then anyone who can reach the channel can speak as a
trusted peer. The receiving agent then carries out the forged instruction with
its own tools and its own privileges. (This repo uses the "OWASP Top 10 for
Agentic Applications" numbering, ASI01 to ASI10.)

## Research foundations

- **OWASP Top 10 for Agentic Applications, ASI07 Insecure Inter-Agent
  Communication** — the risk entry. The list is new; this demo cites it by
  name only.
- **Lamport (1981), "Password authentication with insecure communication"** —
  addresses an eavesdropper who replays a captured credential, the same threat
  as a replayed signed message: proof of origin alone does not prove freshness.
- **RFC 2104, "HMAC: Keyed-Hashing for Message Authentication"** — the
  construction used here (Python's `hmac` with SHA-256) to bind a message to
  the key of the agent that sent it.

## Scenarios & examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| C-1 | Spoofed peer | A message claims to come from the planner; the executor trusts the `sender` field. | **DEMO TARGET** |
| C-2 | Replay | An old, genuinely signed planner order is published again and carried out a second time. | **DEMO TARGET** |
| C-3 | Open bus | Any participant may publish to any topic, including retained messages delivered to every new subscriber. | **DEMO TARGET** (trigger) |
| C-4 | Readable traffic | Recent bus traffic, signatures included, is readable by any participant. | **DEMO TARGET** (enables C-2) |
| C-5 | Tampering in transit | A relay changes a message body between agents. | Partly: the signature covers the body; see the payload README |
| C-6 | Compromised peer | The real planner is hijacked and signs harmful orders. | — (see ASI01; signing proves origin, not intent) |
| C-7 | Peer-message injection | A legitimately sent peer message carries untrusted text that steers the receiver. | — (AgenticGoat `a2a_scan`; screen peer messages as untrusted input) |

## How the demo maps to the attack surfaces

- **C-3** is `POST /bus/publish`: no authentication, any `sender`, any topic,
  and `retain: true` keeps the message for every later job on that topic.
- **C-1** is `Lab._accept` in vulnerable mode: a work order is accepted when
  its self-declared `sender` is `planner`. The planner signs every message,
  but nobody checks the signature.
- **C-4 and C-2**: `GET /bus/log` exposes the old genuine order on `refunds`,
  and vulnerable mode ignores its timestamp and nonce, so a verbatim copy is
  carried out again.
- **Topics decide the blast radius.** Only jobs on `payments`, `refunds` and
  `inventory` receive the attacker's retained messages. That is why the
  `shipping` and `reports` controls stay GREEN.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Trusting the self-declared sender | **HMAC-SHA256 per message with a per-agent key**, verified with the key of the claimed sender. Implemented: `verify_message` rule 1. |
| Any agent may issue work orders | **Sender allowlist per message kind**. Implemented: `verify_message` rule 2, `work_order_senders` in `assets/bus_policy.json`. |
| Old messages accepted again | **Nonce cache plus timestamp window**. Implemented: `verify_message` rule 3. Each part alone stops this replay (tests). |
| Shared or long-lived keys | Per-agent keys generated at startup, in memory only. Implemented for the demo; production needs a key manager, rotation and revocation. |
| Readable bus traffic | Encrypt the transport (mutual TLS between agents) and restrict who may subscribe. Discussed, not coded. |
| Open publish rights | Authenticate publishers at the broker and scope topics per agent. Discussed, not coded; verification at the receiver holds without it. |
| A genuine peer sends harmful content | Treat peer messages as untrusted input and screen them (AgenticGoat `a2a_scan`, the LLM01 demo). Not coded here. |

Further hardening discussed, not coded: asymmetric signatures so a receiver
cannot forge as the sender, message expiry enforced by the broker, and alerts
on bursts of rejected messages.
