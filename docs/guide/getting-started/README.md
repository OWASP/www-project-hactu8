# Getting started

You can try HACTU8 in two minutes with nothing but Python, then add the browser console and real models when you want them.

| You want to | Read | Time |
| --- | --- | --- |
| Run a lab from the terminal | [Install](install.md), then [Your first run](first-run.md) | 2 minutes |
| Use the browser console | [Install](install.md#the-console), then [The console](console.md) | 10 minutes |
| Run everything in containers | [Install](install.md#docker) | 10 minutes |
| Test a real model | [Your first run](first-run.md#a-real-model) | depends on the model |

## Safety first

Everything HACTU8 attacks is deliberately insecure and listens only on `127.0.0.1`, your own machine. The attacks are benign-effect: the worst any of them can do is make Lamb reveal a fake secret or call a pretend tool. Only point HACTU8 at systems you are allowed to test.

No account, key or internet connection is needed for the default setup. Every lab ships with an offline model, `echo`, that gives the same result every time.
