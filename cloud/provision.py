"""Generate uplink keys and the cloud TLS certificate.

Cloud PC (private KEM key stays here):

    python -m cloud.provision --role cloud --out keys/cloud

Gateway Pi (private signing key stays here):

    python -m cloud.provision --role gateway --out keys/gateway

Copy only the .pk file to the other machine, then pin it after you have
compared the printed fingerprint with the one from the machine that created it:

    python -m cloud.provision --pin keys/cloud_kem.pk --label cloud_kem_pk --trust keys/trust.json

TLS certificate for the PC address clients will dial:

    python -m cloud.provision --tls --ip <PC_HOTSPOT_IP> --out keys/tls
"""

from __future__ import annotations

import argparse
import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cloud.uplink_keys import fingerprint, generate_kem, generate_sig, record_pin, write_secret


def _write_role(role: str, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    if role == "cloud":
        pk, sk, alg = generate_kem()
        write_secret(out / "kem.sk", sk)
        (out / "kem.pk").write_bytes(pk)
        (out / "kem.alg").write_text(alg + "\n")
        print(f"Wrote {out / 'kem.sk'} (private, mode 0600) and {out / 'kem.pk'}")
        print(f"Algorithm {alg} (also in kem.alg — copy kem.pk and kem.alg together)")
    else:
        pk, sk, alg = generate_sig()
        write_secret(out / "sig.sk", sk)
        (out / "sig.pk").write_bytes(pk)
        (out / "sig.alg").write_text(alg + "\n")
        print(f"Wrote {out / 'sig.sk'} (private, mode 0600) and {out / 'sig.pk'}")
        print(f"Algorithm {alg} (also in sig.alg — copy sig.pk and sig.alg together)")
    print(f"Public-key fingerprint SHA-256: {fingerprint(pk)}")
    print("Copy only the .pk file. Compare this fingerprint on the other machine before pinning.")


def _write_tls(ip: str, out: Path) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ip)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    out.mkdir(parents=True, exist_ok=True)
    cert_path = out / "cloud.crt"
    key_path = out / "cloud.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    print(f"Wrote {cert_path} and {key_path} for IP {ip}")
    print("Copy cloud.crt to the gateway. The gateway verifies it; do not disable TLS checks.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=("cloud", "gateway"))
    parser.add_argument("--out", type=Path, default=Path("keys"))
    parser.add_argument("--pin", type=Path, help="Public key file to record in the trust file")
    parser.add_argument("--label", help="Trust label, e.g. cloud_kem_pk or gateway_sig_pk")
    parser.add_argument("--trust", type=Path, default=Path("keys/trust.json"))
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--ip", help="Hotspot IP to put in the certificate")
    args = parser.parse_args()

    if args.tls:
        if not args.ip:
            parser.error("--tls requires --ip")
        _write_tls(args.ip, args.out)
        return 0
    if args.pin:
        if not args.label:
            parser.error("--pin requires --label")
        digest = record_pin(args.trust, args.label, args.pin)
        print(f"Pinned {args.label} as {digest} in {args.trust}")
        print("This must equal the fingerprint printed where the key was generated.")
        return 0
    if not args.role:
        parser.error("Choose --role, --pin, or --tls")
    _write_role(args.role, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
