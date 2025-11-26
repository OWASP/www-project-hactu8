# HACTU8 README
Intelligence Assurance Center

## Overview
This repository is part of the **HACTU8 Project**, focused on ethical hacking, AI security research, IoT security, and developing a structured security testing platform.

## Project Goals
- Research vulnerabilities in AI, LLMs, IoT, and cloud security.
- Develop PoC attacks and mitigation strategies.
- Design a security testing platform for security researchers.
- Integrate observability and assurance capabilities.
- Follow a structured workflow to ensure reproducibility and collaboration.

---

## 📂 Repository Structure

| Folder | Purpose |
|---------------|---------|
| **`/docs`** | Contains all project documentation, including research findings, methodologies, and references. |
| **`/src`** | Holds source code for experiments, proof-of-concepts, and scripts. |
| **`/notebooks`** | Jupyter notebooks for interactive analyses, LLM attack simulations, and defense testing. |
| **`/tests`** | Contains automated test scripts and validation tools to ensure research reproducibility. |
| **`/config`** | Configuration files for setting up environments, dependencies, and tools. |
| **`/platform`** | Placeholder for eventual platform code (e.g., a security testing dashboard or automation tools). |
| **`/spikes`** | Short-lived exploratory research that might not be committed to `/src`. |

---

## 📌 Branching Strategy

- **`main`** → Stable, production-ready branch (no direct commits).
- **`dev`** → Development branch where feature branches merge before finalization.
- **Feature Branches (`feature/`)** → Used for specific research or development:
  - `feature/llm-vuln-analysis` → KR's research on OWASP LLM vulnerabilities.
  - `feature/roadmap-and-resources` → Roadmap and resources planning.
- **Spike/POC Branches (`spike/`)** → Temporary branches for experiments:
  - `spike/prompt-injection-poc`
  - `spike/rag-exploit-test`
- **Hotfix Branches (`hotfix/`)** → Used for emergency fixes.

---

## 📌 Workflow for Submitting Work

### 1️⃣ Create a Feature Branch
```bash
# Fetch latest changes
git checkout main
git pull origin main

# Create and switch to your feature branch
git checkout -b feature/llm-vuln-analysis
```

### 2️⃣ Work on Your Changes
- Add research notes, PoC scripts, or documentation.
- Commit frequently with **clear commit messages**:
```bash
git add .
git commit -m "Added initial findings on LLM RAG vulnerabilities"
```

### 3️⃣ Push the Branch
```bash
git push -u origin feature/llm-vuln-analysis
```

### 4️⃣ Open a PR on GitHub
1. Go to the GitHub repository.
2. Click **"Pull Requests"** → **"New Pull Request"**.
3. Select:
   - **Base branch:** `dev`
   - **Compare branch:** `feature/your-feature-name`
4. Add a **title & description** explaining your work.
5. Assign **reviewers** for feedback.

### 5️⃣ Code Review & Approval
✅ **Reviewer checks:**
- Code correctness, security best practices, and reproducibility.
- No direct impact on `main`.
✅ **If approved:** Merge into `dev`.
✅ **If changes are needed:** Update and re-request review.

### 6️⃣ Merge PR & Delete the Branch
- After merging into `dev`, delete the feature branch to keep the repo clean.
- `dev` is periodically merged into `main` once stable.

---

## 📌 Best Practices
✅ Keep PRs **small & focused**.
✅ Use **descriptive commit messages** (`"Added X mitigation for Y attack"`).
✅ Use **draft PRs** for work-in-progress tasks.
✅ Run **security tests before merging research into `dev`**.

---

## 📌 Summary of Commands
| Task                        | Command |
|-----------------------------|---------|
| Create a feature branch  | `git checkout -b feature/your-feature` |
| Add changes  | `git add .` |
| Commit changes  | `git commit -m "Your message"` |
| Push to GitHub  | `git push -u origin feature/your-feature` |
| Open a PR  | Do it from GitHub |
| Merge PR into `dev`  | Done by a reviewer |
| Delete merged branch  | `git branch -d feature/your-feature` |
