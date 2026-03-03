"""CA and per-host certificate generation for MITM proxy."""

import datetime
import os
import ssl
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

CERT_DIR = Path(__file__).parent / "certs"
CA_CERT_PATH = CERT_DIR / "ca.pem"
CA_KEY_PATH = CERT_DIR / "ca-key.pem"
HOST_CERT_DIR = CERT_DIR / "hosts"

_cert_lock = threading.Lock()


def ensure_ca():
    """Load or generate the CA certificate and private key."""
    CERT_DIR.mkdir(exist_ok=True)
    HOST_CERT_DIR.mkdir(exist_ok=True)

    if CA_CERT_PATH.exists() and CA_KEY_PATH.exists():
        ca_key = serialization.load_pem_private_key(
            CA_KEY_PATH.read_bytes(), password=None
        )
        ca_cert = x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())
        return ca_cert, ca_key

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MITM Dev Proxy"),
        x509.NameAttribute(NameOID.COMMON_NAME, "MITM Dev Proxy CA"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    CA_KEY_PATH.write_bytes(ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    os.chmod(CA_KEY_PATH, 0o600)
    CA_CERT_PATH.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    return ca_cert, ca_key


def get_host_cert_path(hostname, ca_cert, ca_key):
    """Return path to a combined PEM (cert+key) for the given hostname.
    Generates and caches on disk if it doesn't exist yet."""
    safe_name = hostname.replace("*", "_star_").replace("/", "_")
    cert_path = HOST_CERT_DIR / f"{safe_name}.pem"

    if cert_path.exists():
        return str(cert_path)

    with _cert_lock:
        if cert_path.exists():
            return str(cert_path)

        host_key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)
        host_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ]))
            .issuer_name(ca_cert.subject)
            .public_key(host_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(hostname)]),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    ca_key.public_key()
                ),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        pem_data = (
            host_cert.public_bytes(serialization.Encoding.PEM)
            + host_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        cert_path.write_bytes(pem_data)
        return str(cert_path)


def make_server_ctx(cert_path):
    """Create an SSLContext to present the per-host cert to the client."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert_path)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx
