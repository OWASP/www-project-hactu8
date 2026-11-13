"""Run HACTU8 Lamb on its fixed loopback interface."""

from __future__ import annotations

import argparse
import os

from hactu8.lamb import DEFAULT_HOST, DEFAULT_PORT
from hactu8.lamb.app import create_app


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=int(os.environ.get("HACTU8_LAMB_PORT", DEFAULT_PORT)))
    args = parser.parse_args(argv)
    try:
        import uvicorn
    except ModuleNotFoundError:
        parser.error("Lamb needs the optional dependency: pip install 'hactu8[lamb]'")
    app = create_app()
    print(f"HACTU8 Lamb on http://{DEFAULT_HOST}:{args.port}")
    print("Intentionally vulnerable. Loopback only. Payloads and side effects are inert.")
    try:
        uvicorn.run(app, host=DEFAULT_HOST, port=args.port)
    finally:
        app.state.workers.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

