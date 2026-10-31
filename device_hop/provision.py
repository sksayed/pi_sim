"""Create device-hop keys. A private key is written only on the machine that owns it.

Gateway Pi (ML-KEM private key stays here):

    python -m device_hop.provision --role gateway

Device Pi (ML-DSA private key stays here), once per device id:

    python -m device_hop.provision --role device --device-id pi2-steady

Copy only the public key to the other machine, compare the fingerprint, then pin it.
On a device, pin the gateway key:

    python -m device_hop.provision --pin keys/device_hop/gateway/kem.pk \\
        --label gateway_hop_kem_pk --trust keys/device_hop/device_trust.json

On the gateway, pin that device:

    python -m device_hop.provision --pin keys/device_hop/devices/pi2-steady/sig.pk \\
        --label device_sig:pi2-steady --trust keys/device_hop/gateway_trust.json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from cloud.uplink_keys import fingerprint, generate_kem, generate_sig, record_pin, write_secret


def _write_gateway(out: Path) -> None:
    pk, sk, alg = generate_kem()
    out.mkdir(parents=True, exist_ok=True)
    write_secret(out / "kem.sk", sk)
    (out / "kem.pk").write_bytes(pk)
    (out / "kem.alg").write_text(alg + "\n")
    print(f"Wrote {out / 'kem.sk'} (private) and {out / 'kem.pk'}")
    print(f"Algorithm {alg}")
    print(f"Public-key fingerprint SHA-256: {fingerprint(pk)}")
    print("Copy only kem.pk. Pin it on each device after the fingerprints match.")


def _write_device(out: Path, device_id: str) -> None:
    pk, sk, alg = generate_sig()
    out.mkdir(parents=True, exist_ok=True)
    write_secret(out / "sig.sk", sk)
    (out / "sig.pk").write_bytes(pk)
    (out / "sig.alg").write_text(alg + "\n")
    (out / "device_id").write_text(device_id + "\n")
    print(f"Wrote {out / 'sig.sk'} (private) for {device_id}")
    print(f"Algorithm {alg}")
    print(f"Public-key fingerprint SHA-256: {fingerprint(pk)}")
    print("Copy only sig.pk to the gateway. Pin it as device_sig:" + device_id)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--role", choices=("gateway", "device"))
    parser.add_argument("--device-id")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--pin", type=Path)
    parser.add_argument("--label")
    parser.add_argument("--trust", type=Path)
    args = parser.parse_args()

    if args.pin:
        if not args.label or not args.trust:
            parser.error("--pin requires --label and --trust")
        digest = record_pin(args.trust, args.label, args.pin)
        print(f"Pinned {args.label} as {digest} in {args.trust}")
        return 0
    if args.role == "gateway":
        _write_gateway(args.out or Path("keys/device_hop/gateway"))
        return 0
    if args.role == "device":
        if not args.device_id:
            parser.error("--role device requires --device-id")
        out = args.out or Path("keys/device_hop/devices") / args.device_id
        _write_device(out, args.device_id)
        return 0
    parser.error("Choose --role or --pin")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
