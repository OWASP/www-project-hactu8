# The console

The console is the same tool as the command line, in a browser. It has six pages, in the order you will usually use them.

| Page | What it is for |
| --- | --- |
| **Learn** | The story, the learning path and each lab's lesson. Start here. |
| **Run** | Pick a lab, a backend and a model, and run it. Shows the four acts side by side. |
| **Results** | Every stored run. Open one to see each question, each answer and its grade. |
| **Reports** | Download a result as Markdown, HTML or SARIF (for code-scanning tools). |
| **Registry** | The systems you test: name, owner, model, endpoint and risk notes. |
| **Settings** | Default model and classifier, the endpoints the console talks to, and its safety posture. |

## Learn

Learn opens on **Start here**, a one-page version of [the story](../story/README.md): the cast and why every secret is a canary. **Start step 1** takes you to the first lab on the [learning path](../learning-path/README.md).

Each lab page shows its lesson. The lessons all have the same shape (see [Reading a lesson](../how-labs-work/lessons.md)), and each ends with a **Run this lab** button that opens Run with the lab already chosen.

## Run

Choose:

- **Lab:** any of the 49.
- **Backend:** Offline (`echo`), Local (Ollama, llama.cpp or any OpenAI-compatible server) or Cloud. A backend your hardware cannot run is greyed out, with the reason.
- **Model:** for local and cloud backends.

Cloud runs need you to tick a spend-consent box. Leave it unticked unless you mean to spend money.

The result shows the four acts (see [The four acts](../how-labs-work/README.md)) and the lab's metric for each. Under it, **Protections added** lists the defense that Act 4 switched on, step by step, with before and after.

Run also has a second mode, **Lamb's MCP surfaces (live)**. It attacks a real model through Lamb's tools and documents, once with the gateway off and once with it on, and reports what leaked each time. It is the closest HACTU8 gets to a live system, so try it after a few labs.

## Results and Reports

Every run, from the console or the command line, is stored in the same place (`.hactu8/results`, or `HACTU8_HOME`) and appears on Results. Reports turns any of them into a document you can share.

---

Next: [How a lab works](../how-labs-work/README.md)
