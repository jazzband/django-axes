import shutil
import subprocess
from datetime import datetime, timedelta
from ipaddress import ip_address
from pathlib import Path

from .network import get_private_ip_addresses


def _run_openssl(args):
    openssl = shutil.which("openssl")
    if not openssl:
        raise RuntimeError("Nie znaleziono programu openssl w PATH.")

    subprocess.run([openssl, *args], check=True, capture_output=True, text=True)


def _generate_with_cryptography(paths, common_name, valid_days, ip_addresses):
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    except ImportError as exc:
        raise RuntimeError(
            "Nie znaleziono openssl w PATH ani pakietu cryptography. Zainstaluj zaleznosci z requirements.txt."
        ) from exc

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PL"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Wielkopolskie"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Poznan"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FakeAccount"),
        x509.NameAttribute(NameOID.COMMON_NAME, "FakeAccount Local CA"),
    ])
    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PL"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Wielkopolskie"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Poznan"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FakeAccount"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.utcnow()
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    san_entries = [
        x509.DNSName("localhost"),
        x509.DNSName(common_name),
        x509.IPAddress(ip_address("127.0.0.1")),
        x509.IPAddress(ip_address("::1")),
    ]
    san_entries.extend(x509.IPAddress(ip_address(address)) for address in ip_addresses)

    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    paths["ca_key"].write_bytes(
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    paths["ca_cert"].write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    paths["server_key"].write_bytes(
        server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    paths["server_cert"].write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))


def generate_local_ca_cert(output_dir, common_name="localhost", valid_days=365, ip_addresses=None):
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    ip_addresses = ip_addresses if ip_addresses is not None else get_private_ip_addresses()
    ip_addresses = sorted(set(ip_addresses))

    paths = {
        "ca_key": output_path / "ca.key",
        "ca_cert": output_path / "ca.crt",
        "server_key": output_path / "key.pem",
        "server_csr": output_path / "server.csr",
        "server_cert": output_path / "cert.pem",
        "config": output_path / "openssl.cnf",
    }

    ip_lines = "\n".join(
        f"IP.{index} = {address}"
        for index, address in enumerate(["127.0.0.1", "::1", *ip_addresses], start=1)
    )

    paths["config"].write_text(
        f"""[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[dn]
C = PL
ST = Wielkopolskie
L = Poznan
O = FakeAccount
CN = {common_name}

[req_ext]
subjectAltName = @alt_names

[cert_ext]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = {common_name}
{ip_lines}
""",
        encoding="utf-8",
    )

    if not shutil.which("openssl"):
        _generate_with_cryptography(paths, common_name, valid_days, ip_addresses)
        paths["generator"] = "cryptography fallback"
        paths["ip_addresses"] = ip_addresses
        return paths

    _run_openssl(["genrsa", "-out", str(paths["ca_key"]), "4096"])
    _run_openssl([
        "req",
        "-x509",
        "-new",
        "-nodes",
        "-key",
        str(paths["ca_key"]),
        "-sha256",
        "-days",
        str(valid_days),
        "-out",
        str(paths["ca_cert"]),
        "-subj",
        "/C=PL/ST=Wielkopolskie/L=Poznan/O=FakeAccount/CN=FakeAccount Local CA",
    ])
    _run_openssl([
        "req",
        "-new",
        "-nodes",
        "-out",
        str(paths["server_csr"]),
        "-newkey",
        "rsa:2048",
        "-keyout",
        str(paths["server_key"]),
        "-config",
        str(paths["config"]),
    ])
    _run_openssl([
        "x509",
        "-req",
        "-in",
        str(paths["server_csr"]),
        "-CA",
        str(paths["ca_cert"]),
        "-CAkey",
        str(paths["ca_key"]),
        "-CAcreateserial",
        "-out",
        str(paths["server_cert"]),
        "-days",
        str(valid_days),
        "-sha256",
        "-extfile",
        str(paths["config"]),
        "-extensions",
        "cert_ext",
    ])

    paths["generator"] = "openssl"
    paths["ip_addresses"] = ip_addresses
    return paths
