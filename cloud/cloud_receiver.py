#!/usr/bin/env python3
"""Retired MQTT receiver.

The cloud hop is HTTPS. Run the receiver on the PC with:

    python -m cloud.https_server

Setup steps are in docs/e2e_cloud.md.
"""

import sys

print(
    "cloud/cloud_receiver.py is retired. "
    "The cloud hop is HTTPS on port 8443. Run: python -m cloud.https_server",
    file=sys.stderr,
)
raise SystemExit(2)
