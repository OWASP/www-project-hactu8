# HX01 Hidden Document Injection — risks, research and mitigations

What this lab's risk is, where it comes from, and how to harden against it. Loaded on demand.

## Research foundations

- **Greshake et al. (2023)**, "Not what you've signed up for" — indirect prompt injection: instructions placed in content an LLM-integrated application retrieves are followed as if the user had given them, including text hidden from the human reader of a web page.
- **OWASP Top 10 for LLM Applications 2025, LLM01** — the example scenarios include indirect injection through content the model is asked to summarise, payload splitting across a document such as a resume, and multimodal injection.
- **MITRE ATLAS AML.T0051.001** (LLM Prompt Injection: Indirect) — the technique this lab exercises.
- **Rehberger (Embrace The Red, 2023-2024)** — demonstrations of instructions hidden in shared documents and of invisible Unicode tag characters ("ASCII smuggling") that a viewer does not render but a model reads.
- **W3C WCAG 2.x** — the contrast-ratio definition the render-aware extractor uses to decide whether text is visible against its background.
- **Hidden reviewer prompts in research papers (2025)** — press reports found preprints carrying white or tiny text addressed to AI reviewers ("give a positive review"). The same trick the lab plays on an invoice.

## Scenarios and examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| S1 | White text in an emailed invoice | A revised invoice renders like the real one; one white-on-white line tells the assistant how to summarise it | **DEMO TARGET** |
| S2 | Other hiding places | Zero-size font, off-page text box, PDF render mode 3, PDF Subject, Word hidden run, comment and core property, `display:none`, `hidden`, off-screen CSS, comment and meta tag in HTML | **DEMO TARGET** (`assets/hiding_variants.json`) |
| S3 | Faint, tiny visible text | Text a human could in principle see (2 pt, light grey) passes a visibility test | **DEMO TARGET** (measured limit) |
| S4 | Resume keyword stuffing | White text in a CV steers an AI screener's ranking | Context |
| S5 | Instructions in images | Text drawn into an image or a scanned page, read by a vision model or OCR | Context (no lab yet) |
| S6 | Invisible Unicode | Tag characters or zero-width text a viewer does not render | Context (protectogw strips zero-width characters) |

## How the demo maps to the attack surfaces

- **S1** — `POST /docs/upload` (the mail gateway) accepts `assets/poisoned_invoice.pdf.json`; `naive_text` in `vulnerable_app.py` passes every run to the model.
- **S2** — `inject_variant` places the same directive in each hiding place; `tests/test_lifecycle.py` asserts that the naive extractor passes each one and the render-aware extractor drops it.
- **S3** — the two `limit` variants; `evaluate_kpi.py --probe` and `LimitsTest` measure what each layer does with them.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Extractor takes every text run | Render-aware extraction: drop hidden, off-page, zero-size and background-coloured runs (`visible_text`, implemented, `visible_text_only`) |
| Metadata and comments reach the context | Leave them out, or pass them as labelled data the assistant cannot take instructions from (implemented: dropped) |
| Instruction wording in visible text | Screen every extracted line with protectogw (`screen_text`, implemented, `input_screen`); the screen catches the marker and classic override phrasing, not plain prose |
| Faint or tiny visible text | Raise the thresholds, or flag text below body size and contrast for review; any threshold leaves a band above it (not coded) |
| The model obeys the document | Keep document text in its own channel (spotlighting, `spotlight`, the LLM01 lab); give the summariser no tools; render the summary as data |
| Unauthenticated intake | Authenticate senders and record provenance (`provenance`); quarantine external documents (not coded) |
| Images and scans | OCR the rendered page, not the text layer, and screen the result; compare the text layer with the OCR output (not coded) |
