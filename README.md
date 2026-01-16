# HACTU8 Reference Application

<!-- TODO: create a working readme.md to document, setup, run and debug the reference solution -->
This repository contains the core specifications, architecture, and starter code for the HACTU8 reference application—a modular platform for secure AI and LLM system testing, scanning, and assurance.

---

## 📦 Project Structure

```text
reference-solution/
├── platform/       # UI, prompt workbench, registry browser, notification center
├── engine/         # Orchestration engine, agent scheduler, job runner
├── services/       # Identity, registry, plugin runtime, providers
├── scan/           # LLM NMAP scanner (signature-based/heuristic)
├── specs/          # Architecture specs, Top 10 test templates, model contracts
└── README.md              # Project description (this file)
```

---

## 🎯 Purpose

The HACTU8 platform provides:

- A reference architecture for securing LLM systems
- Drop-in support for multiple model and RAG providers
- Tools for red-teaming, assurance, and continuous testing

It is an OWASP Incubator project. See: [https://owasp.org/www-project-hactu8/](https://owasp.org/www-project-hactu8/)

---

<!-- TODO: rewrite 
## 🔧 Interface Contracts (Examples, tbd)

### Model Provider Interface

```python
class ModelProvider:
    def identify(self) -> dict:
        """Returns metadata: name, version, vendor"""
        pass

    def execute_prompt(self, prompt: str, context: Optional[dict] = None) -> str:
        """Sends prompt to model and returns result"""
        pass

    def get_limits(self) -> dict:
        """Returns model-specific constraints like max tokens"""
        pass
```

### RAG Provider Interface

```python
class RAGProvider:
    def retrieve(self, query: str) -> List[str]:
        """Returns context snippets given a query"""
        pass

    def ingest(self, documents: List[str], metadata: Optional[dict] = None):
        """Ingests documents into retrieval store"""
        pass

    def configure(self, settings: dict):
        """Sets up indexing parameters, rerankers, etc."""
        pass
```

---

## ⚙️ Quickstart Boilerplate

```bash
# Clone and initialize modules
$ git clone https://github.com/owasp/reference.git
$ cd reference
$ make init  # Or use scripts/setup.sh
```

---

## 🛠 Recommended Tools

- Python 3.13
- FastAPI or NodeJS for services
- React/SvelteKit for platform
- Redis/PostgreSQL/TimescaleDB for storage
- Prefect or Celery for orchestration

---

## 📚 Documentation

See [`specs/`](./specs/) for:

- OWASP LLM Top 10 test strategies
- System diagrams (Mermaid, PNG, PDF)
- Use cases, user roles, deployment profiles

---

## 🤝 Contributions

We welcome contributions to:

- Improve test batteries
- Add provider support
- Extend plugin APIs

Use pull requests with spec updates and test cases.

---
-->

## 🛡️ License

[MIT](LICENSE)
