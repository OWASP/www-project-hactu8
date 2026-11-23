"""TLS for the HACTU8 API and console: a self-signed certificate per user, or your own.

HTTPS is the default. ``HACTU8_TLS=off`` serves plain HTTP. ``HACTU8_TLS_CERT`` and ``HACTU8_TLS_KEY``
(both, PEM) bring your own certificate. Otherwise the first start writes a self-signed ECDSA P-256
certificate for localhost, 127.0.0.1 and ::1, valid for one year, into ``HACTU8_TLS_DIR`` (default
``~/.hactu8/tls``, never the repo), with the key at mode 0600, and later starts reuse it. The key is
never printed or logged.

Clients in this repo trust that certificate explicitly (``client_context``); nothing turns off
verification.

    python -m hactu8.tls            # make the certificate if needed, print its path
    python -m hactu8.tls health     # GET /api/health on 127.0.0.1:$HACTU8_API_PORT, trusting it

Needs the ``cryptography`` package (the ``api`` extra) only to generate a certificate."""

import datetime
import ipaddress
import os
import ssl
import sys
from pathlib import Path
from typing import Optional, Tuple

CERT_NAME, KEY_NAME = "cert.pem", "key.pem"
DNS_NAMES = ("localhost",)
IP_NAMES = ("127.0.0.1", "::1")
VALID_DAYS = 365
RENEW_DAYS = 7  # regenerate when fewer days than this remain


class TLSError(RuntimeError):
    pass


def enabled() -> bool:
    """HTTPS unless HACTU8_TLS is off (also 0, false, no)."""
    return os.environ.get("HACTU8_TLS", "on").strip().lower() not in ("off", "0", "false", "no")


def scheme() -> str:
    return "https" if enabled() else "http"


def tls_dir() -> Path:
    value = os.environ.get("HACTU8_TLS_DIR", "").strip()
    return Path(value).expanduser().resolve() if value else Path.home() / ".hactu8" / "tls"


def own_cert() -> Optional[Tuple[Path, Path]]:
    """(cert, key) from HACTU8_TLS_CERT / HACTU8_TLS_KEY, or None. Setting only one is an error."""
    cert, key = (os.environ.get(name, "").strip() for name in ("HACTU8_TLS_CERT", "HACTU8_TLS_KEY"))
    if not cert and not key:
        return None
    if not (cert and key):
        raise TLSError("set both HACTU8_TLS_CERT and HACTU8_TLS_KEY, or neither")
    paths = Path(cert).expanduser(), Path(key).expanduser()
    for path in paths:
        if not path.is_file():
            raise TLSError(f"TLS file not found: {path}")
    return paths


def cert_path() -> Path:
    """The certificate the API serves (and clients should trust); not created here."""
    own = own_cert()
    return own[0] if own else tls_dir() / CERT_NAME


def ensure(directory: Optional[Path] = None) -> Tuple[Path, Path]:
    """(cert, key) to serve: your own if set, else the self-signed pair, generated if missing or stale."""
    own = own_cert() if directory is None else None
    if own:
        return own
    directory = directory or tls_dir()
    cert, key = directory / CERT_NAME, directory / KEY_NAME
    if _reusable(cert, key):
        os.chmod(key, 0o600)
        return cert, key
    _generate(directory, cert, key)
    return cert, key


def _reusable(cert: Path, key: Path) -> bool:
    if not (cert.is_file() and key.is_file()):
        return False
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
    except ModuleNotFoundError:
        return True  # cannot inspect it, and cannot make a new one either; serve what is there
    try:
        loaded = x509.load_pem_x509_certificate(cert.read_bytes())
        private = serialization.load_pem_private_key(key.read_bytes(), password=None)
    except (ValueError, TypeError):
        return False
    remaining = loaded.not_valid_after_utc - datetime.datetime.now(datetime.timezone.utc)
    same_key = loaded.public_key().public_bytes(serialization.Encoding.DER,
                                                serialization.PublicFormat.SubjectPublicKeyInfo) == \
        private.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
    return same_key and remaining > datetime.timedelta(days=RENEW_DAYS)


def _generate(directory: Path, cert: Path, key: Path) -> None:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    except ModuleNotFoundError as exc:
        raise TLSError("generating the TLS certificate needs: pip install 'hactu8[api]' (cryptography); "
                       "or set HACTU8_TLS_CERT and HACTU8_TLS_KEY, or HACTU8_TLS=off") from exc

    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    private = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "HACTU8 localhost (self-signed)"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OWASP HACTU8 local")])
    now = datetime.datetime.now(datetime.timezone.utc)
    sans = [x509.DNSName(n) for n in DNS_NAMES] + [x509.IPAddress(ipaddress.ip_address(n)) for n in IP_NAMES]
    ski = x509.SubjectKeyIdentifier.from_public_key(private.public_key())
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=VALID_DAYS))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                     crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(ski, critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), critical=False)
        .sign(private, hashes.SHA256())
    )
    key_pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
    # Key first, created 0600 from the start (no window at the umask's mode), then swapped in atomically.
    _write(key, key_pem, 0o600)
    _write(cert, certificate.public_bytes(serialization.Encoding.PEM), 0o644)


def _write(path: Path, data: bytes, mode: int) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def uvicorn_options() -> dict:
    """ssl_certfile / ssl_keyfile for uvicorn, or {} when HACTU8_TLS is off."""
    if not enabled():
        return {}
    cert, key = ensure()
    return {"ssl_certfile": str(cert), "ssl_keyfile": str(key)}


def client_context(cafile: Optional[Path] = None) -> ssl.SSLContext:
    """A verifying client context that trusts the API's certificate (and nothing weaker)."""
    return ssl.create_default_context(cafile=str(cafile or cert_path()))


def health(port: Optional[int] = None, timeout: float = 4) -> dict:
    import json
    import urllib.request
    port = port or int(os.environ.get("HACTU8_API_PORT", "8000"))
    url = f"{scheme()}://127.0.0.1:{port}/api/health"
    context = client_context() if enabled() else None
    with urllib.request.urlopen(url, timeout=timeout, context=context) as response:
        return json.loads(response.read())


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    try:
        if argv[:1] == ["health"]:
            print(health())
            return 0
        if argv:
            print("usage: python -m hactu8.tls [health]", file=sys.stderr)
            return 2
        if not enabled():
            print("HACTU8_TLS is off: plain HTTP, no certificate")
            return 0
        print(ensure()[0])
        return 0
    except (TLSError, OSError) as exc:
        print(f"hactu8.tls: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
