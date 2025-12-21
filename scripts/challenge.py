#!/usr/bin/env python3
"""
Fetch a challenge and (optionally) sign it with an Ed25519 PEM key.

Usage:
  python scripts/challenge.py fetch <peer_id> [--url http://localhost:8080] [--token op_secret]
  python scripts/challenge.py sign  <peer_id> --pem ed25519.pem [--url ...] [--token op_secret]

Outputs:
  - fetch: prints the challenge base64
  - sign: prints PUB_B64 and SIG_B64 (base64) for use in enroll
Example:
    python scripts/challenge.py fetch peer-demo --url http://localhost:8080 --token op_secret
    python scripts/challenge.py sign peer-demo --pem ./ed25519.pem --url http://localhost:8080 --token op_secret
"""

import argparse
import base64
import json
import os
import sys
import urllib.request
import urllib.error
import subprocess


def http_post(url: str, token: str, payload: dict) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        sys.stderr.write(f"HTTP {e.code}: {e.read().decode()}\n")
        sys.exit(1)
    except Exception as e:
        sys.stderr.write(f"Request failed: {e}\n")
        sys.exit(1)


def fetch_challenge(base_url: str, peer_id: str, token: str) -> str:
    resp = http_post(f"{base_url}/registry/challenge", token, {"peer_id": peer_id})
    ch = resp.get("challenge")
    if not ch:
        sys.stderr.write("No challenge in response\n")
        sys.exit(1)
    return ch


def decode_b64(data: str) -> bytes:
    padded = data + "=" * (-len(data) % 4)
    return base64.b64decode(padded)


def sign_challenge(challenge_b64: str, pem_path: str) -> tuple[str, str]:
    challenge_bytes = decode_b64(challenge_b64)
    with open("/tmp/ch.bin", "wb") as f:
        f.write(challenge_bytes)

    pub_b64 = subprocess.check_output(
        ["sh", "-c", f"openssl pkey -in {pem_path} -pubout -outform DER | tail -c 32 | base64 -w0"],
        text=True,
    ).strip()
    sig_b64 = subprocess.check_output(
        ["sh", "-c", f"openssl pkeyutl -sign -inkey {pem_path} -rawin -in /tmp/ch.bin | base64 -w0"],
        text=True,
    ).strip()
    return pub_b64, sig_b64


def main():
    parser = argparse.ArgumentParser(description="Challenge helper")
    sub = parser.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--url", default=os.environ.get("EDGE_URL", "http://localhost:8080"))
    common.add_argument("--token", default=os.environ.get("EDGE_OPERATOR_TOKEN", "op_secret"))

    fetch_p = sub.add_parser("fetch", parents=[common])
    fetch_p.add_argument("peer_id")

    sign_p = sub.add_parser("sign", parents=[common])
    sign_p.add_argument("peer_id")
    sign_p.add_argument("--pem", required=True, help="Path to Ed25519 PEM private key")

    args = parser.parse_args()

    if args.cmd == "fetch":
        ch = fetch_challenge(args.url, args.peer_id, args.token)
        print(ch)
    elif args.cmd == "sign":
        ch = fetch_challenge(args.url, args.peer_id, args.token)
        pub_b64, sig_b64 = sign_challenge(ch, args.pem)
        print(f"PUB_B64={pub_b64}")
        print(f"SIG_B64={sig_b64}")


if __name__ == "__main__":
    main()
