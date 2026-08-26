#!/usr/bin/env python3
"""DNS lookup — passive recon via stdlib socket. Standalone, no dependencies
beyond the Python standard library. Runnable outside IAC by any tool that
can execute a script.

Usage: dns_lookup.py <domain>
Prints one JSON object to stdout: {"success": bool, "data": ..., "error": ...}
"""
import json
import socket
import sys


def dns_lookup(domain: str) -> dict:
    try:
        # getaddrinfo returns list of (family, type, proto, canonname, sockaddr)
        results = socket.getaddrinfo(domain, None, socket.AF_INET)
        addresses = list({r[4][0] for r in results})

        # Also attempt reverse lookup on first few addresses
        reverse = []
        for addr in addresses[:3]:
            try:
                hostname, _, _ = socket.gethostbyaddr(addr)
                reverse.append({"ip": addr, "hostname": hostname})
            except socket.herror:
                reverse.append({"ip": addr, "hostname": None})

        return {
            "success": True,
            "data": {"domain": domain, "a_records": addresses, "reverse": reverse},
            "error": None,
        }
    except socket.gaierror as exc:
        return {"success": False, "data": None, "error": f"DNS resolution failed for {domain!r}: {exc}"}


def main() -> None:
    if len(sys.argv) != 2:
        print(json.dumps({"success": False, "data": None, "error": "Usage: dns_lookup.py <domain>"}))
        sys.exit(0)
    print(json.dumps(dns_lookup(sys.argv[1])))


if __name__ == "__main__":
    main()
