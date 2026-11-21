# HX08 Image Prompt Injection — risks, research and mitigations

What this lab's risk is, where it comes from, and how to harden against it. Loaded on demand.

## Research foundations

- **OWASP Top 10 for LLM Applications 2025, LLM01 Prompt Injection** (<https://genai.owasp.org/llmrisk/llm01-prompt-injection/>, read 2026-11-21). Scenario 7, "Multimodal Injection": an attacker embeds a malicious prompt within an image that accompanies benign text; when a multimodal AI processes both, the hidden prompt alters the model's behaviour, potentially leading to unauthorized actions or disclosure of sensitive information. The description notes that multimodal AI introduces its own injection risks, such as instructions hidden in images, and that robust multimodal-specific defenses need more research. None of the page's seven mitigations is specific to images; input and output filtering and segregating external content are the closest, and this lab applies both.
- **MITRE ATLAS AML.T0051.001, LLM Prompt Injection: Indirect** (<https://github.com/mitre-atlas/atlas-data>, `dist/ATLAS.yaml` version 5.6.0, read 2026-11-21). An adversary injects prompts through a separate data channel ingested by the LLM, "such as include text or multimedia pulled from databases or websites"; such prompts may be hidden or obfuscated from the user. The receipt photo is that channel. `AML.T0051.002` (Triggered) exists in the same file and is not used here.
- **Bagdasaryan, Hsieh, Nassi and Shmatikov (2023)**, "Abusing Images and Sounds for Indirect Instruction Injection in Multi-Modal LLMs" (<https://arxiv.org/abs/2307.10490>, abstract read 2026-11-21; the full paper was not read). An adversarial perturbation tied to a chosen prompt is blended into an image or a sound; when a user asks an unmodified model about it, the model outputs attacker-chosen text or steers the dialogue (proofs of concept on LLaVa and PandaGPT). This is a pixel-level mechanism, not readable text: it is out of this lab's reach and listed as context only.
- **Rehberger's posts on image-borne prompt injection** (embracethered.com) were not read for this lab (unverified); they are often cited for text in images steering production assistants.

## Scenarios and examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| S1 | Visible text in the photo | Small print under the receipt total, addressed to the assistant | **DEMO TARGET** (`sign`) |
| S2 | Near-invisible text | A line 6 grey levels off the paper; the OCR reads it, a person does not | **DEMO TARGET** (`faint`) |
| S3 | Image metadata | A PNG `tEXt` Description passed to the model as "image description" | **DEMO TARGET** (`metadata`) |
| S4 | Alt text | The uploader's alt text carries the instruction | **DEMO TARGET** (variant `alt-text`) |
| S5 | Visible line that sounds like the shop | Full contrast, no lab cue, claims to be the store system | **DEMO TARGET** (measured limit `store-system`) |
| S6 | Pale text above the detector threshold | 60 grey levels off the paper, claims to be the system | **DEMO TARGET** (measured, `test_pale_text_above_the_threshold_leaks`) |
| S7 | Adversarial perturbation | Pixel noise that steers a vision model, no readable text (Bagdasaryan et al. 2023) | Context (needs a real vision model) |
| S8 | EXIF, other chunks, rotated or handwritten text | Other carriers a real pipeline may read | Context (not built) |

## How the demo maps to the attack surfaces

- **S1, S2** — `imaging.ocr` reads every line at 3 or more grey levels from the paper; `read_upload` in `vulnerable_app.py` passes them all in vulnerable mode; `test_each_carrier_reaches_the_model_by_its_own_path`.
- **S3, S4** — `Reading.text` adds `tEXt` values and the alt text under "Image metadata:" and "Alt text:"; `test_metadata_path_is_real`, `test_alt_text_variant`.
- **S5, S6** — `limits` in `assets/hostile_images.json`; `evaluate_kpi.py --probe` and `LimitsTest`.
- **The refund** — `RefundTool.issue` pays whatever the model asks in vulnerable mode; `RefundToolTest`.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Metadata and alt text reach the model | Re-encode from pixels, drop alt text (`imaging.strip_metadata`, implemented, `image_sanitize`) |
| Text a person cannot see reaches the model | Measure each line's contrast; drop lines under `MIN_VISIBLE_DELTA` (implemented, `image_sanitize`) |
| Image text is trusted | Fence it as untrusted data (implemented, `spotlight`); screen each line (implemented, `input_screen`, two lab rules) |
| The refund tool pays anything | Check every call against the order on record, cap, no model-supplied authorisation (implemented, `action_policy`) |
| The secret is in the model's context | Keep the desk code out of the prompt entirely (`secret_vault`, not coded) |
| The code can still be written into a reply | Screen the reply for the code before it is sent (`output_screen`, not coded here) |
| Plausible visible text | No image check sees it; rely on the action checks and on keeping secrets out of reach (not closable by image checks) |
