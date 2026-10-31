"""Check device-hop keys, then one sealed message.

On a client Pi:

    DEVICE_HOP=1 .venv/bin/python -m device_hop.sanity --role client --device-id pi1-steady

On the gateway, after you copy the printed JSON file here:

    .venv/bin/python -m device_hop.sanity --role gateway --open /tmp/device_hop_probe.json

`--role keys` only lists what this host can load.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from device_hop.envelope import open_message
from device_hop.keys import (
    device_public_key,
    device_signing_key,
    gateway_public_key,
    gateway_secret_key,
)
from device_hop.publish import protect
from cloud.uplink_keys import fingerprint


def _keys(device_ids: list[str]) -> int:
    failed = 0
    gw_pk = gateway_public_key()
    if gw_pk:
        pk, alg = gw_pk
        print(f"OK  gateway public key  {alg}  {fingerprint(pk)[:16]}…")
    else:
        print("NO  gateway public key (needed on each client)")
    gw_sk = gateway_secret_key()
    if gw_sk:
        _sk, alg = gw_sk
        print(f"OK  gateway private key  {alg}  (this host only)")
    else:
        print("NO  gateway private key (needed on the gateway)")
    for device_id in device_ids:
        signing = device_signing_key(device_id)
        if signing:
            print(f"OK  signing key for {device_id}")
        else:
            print(f"NO  signing key for {device_id}")
        try:
            pk, alg = device_public_key(device_id)
        except Exception as exc:
            print(f"NO  pinned device public key for {device_id}: {exc}")
            failed += 1
        else:
            print(f"OK  pinned device public key for {device_id}  {alg}  {fingerprint(pk)[:16]}…")
            if signing is None:
                failed += 1
    return 1 if failed else 0


def _client(device_id: str, out: Path) -> int:
    sensor = {
        "device_id": device_id,
        "crypto_type": "benign",
        "seq": 1,
        "msg_id": "sanity-check",
        "probe": True,
    }
    sealed = protect(sensor)
    if sealed.get("crypto_type") != "device_kem":
        print("FAIL  message stayed plaintext. Pin the gateway public key and this device's signing key.", file=sys.stderr)
        return 1
    out.write_text(json.dumps(sealed, indent=2) + "\n")
    print(f"OK  sealed {device_id} seq=1 as device_kem")
    print(f"copy this file to the gateway and open it:")
    print(f"  {out}")
    return 0


def _gateway(path: Path) -> int:
    body = json.loads(path.read_text())
    secret = gateway_secret_key()
    if secret is None:
        print("FAIL  gateway private key is not on this machine", file=sys.stderr)
        return 1
    gateway_sk, kem_alg = secret
    device_id = str(body["device_id"])
    device_pk, sig_alg = device_public_key(device_id)
    plain, open_ns = open_message(
        body, gateway_sk, device_pk,
        str(body.get("kem") or kem_alg),
        str(body.get("sig") or sig_alg),
    )
    sensor = json.loads(plain)
    if sensor.get("msg_id") != "sanity-check":
        print(f"FAIL  unexpected plaintext {sensor}", file=sys.stderr)
        return 1
    print(f"OK  opened {device_id}  msg_id={sensor['msg_id']}  open_ns={open_ns}")
    print("device hop is working. Next: one MQTT publish with the gateway agent and the cloud receiver up.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--role", choices=("keys", "client", "gateway"), default="keys")
    parser.add_argument("--device-id", default="pi1-steady")
    parser.add_argument("--open", type=Path)
    parser.add_argument("--out", type=Path, default=Path("/tmp/device_hop_probe.json"))
    args = parser.parse_args()
    ids = [
        "pi1-steady", "pi1-mixed", "pi1-burst",
        "pi2-steady", "pi2-mixed", "pi2-burst",
    ]
    if args.device_id not in ids:
        ids.append(args.device_id)
    if args.role == "keys":
        return _keys(ids)
    if args.role == "client":
        if _keys([args.device_id]):
            return 1
        return _client(args.device_id, args.out)
    if not args.open:
        parser.error("--role gateway requires --open")
    return _gateway(args.open)


if __name__ == "__main__":
    raise SystemExit(main())
