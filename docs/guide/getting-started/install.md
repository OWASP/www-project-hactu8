# Install

## The command line

You need Python 3.10 or later and git. The core has no dependencies.

```bash
git clone -b phase1-mvp https://github.com/OWASP/www-project-hactu8.git
cd www-project-hactu8
python3 -m hactu8 list
```

If `list` prints 49 labs, you are ready for [your first run](first-run.md).

## The console

The browser console and HACTU8 Lamb need a few Python packages and Node.js. Install them into a virtual environment (Homebrew's Python refuses global installs):

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[lamb,api]'
```

Start the API first, in its own terminal. On its first start it makes a self-signed certificate that the console reuses:

```bash
.venv/bin/python -m hactu8.api            # https://127.0.0.1:8000
```

Then start the console in a second terminal:

```bash
cd spikes/iac-prototype/iac-host
npm ci
npm run dev                               # https://127.0.0.1:5173
```

Open `https://127.0.0.1:5173`. Your browser warns about the certificate until you trust it. For a quick look, open both `https://127.0.0.1:5173` and `https://127.0.0.1:8000/api/health` and choose to proceed. To trust it properly, see [HTTPS in the deploy notes](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/docs/deploy.md#https).

On macOS with the python.org installer, cloud backends also need `SSL_CERT_FILE=/etc/ssl/cert.pem`.

## Docker

One command starts the API and the console together on `https://127.0.0.1:8000`:

```bash
docker compose up --build -d
docker compose logs hactu8 | grep token=      # open this login URL once
```

The container asks for a token because it listens inside Docker's network. A plain `python -m hactu8.api` on loopback does not. There is also a devcontainer for VS Code and Codespaces. Both are covered in the [deploy notes](https://github.com/OWASP/www-project-hactu8/blob/phase1-mvp/docs/deploy.md).

## Check it works

```bash
python3 -m hactu8 run all --backend echo
```

All 49 labs should report `PASS`. If one does not, something in your checkout is wrong. Please [open an issue](https://github.com/OWASP/www-project-hactu8/issues).

---

Next: [Your first run](first-run.md)
