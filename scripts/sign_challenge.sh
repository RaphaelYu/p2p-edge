#!/usr/bin/env bash
# Sign a challenge (base64) with an Ed25519 private key (PEM) and output:
# PUB_B64 and SIG_B64 suitable for enroll.
# Usage: CH_B64=... scripts/sign_challenge.sh /path/to/ed25519.pem
# Requires: openssl, base64 (with -w0 or compatible), and CH_B64 env set.

set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: CH_B64=... $0 /path/to/ed25519.pem" >&2
  exit 1
fi

PEM="$1"
: "${CH_B64:?CH_B64 env is required (challenge base64 from /registry/challenge)}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# Decode challenge (handles missing padding)
python3 - <<'PY' > "$TMP_DIR/ch.bin"
import base64, os, sys
ch = os.environ["CH_B64"]
ch_padded = ch + "=" * (-len(ch) % 4)
try:
    sys.stdout.buffer.write(base64.b64decode(ch_padded))
except Exception as e:
    sys.stderr.write(f"Failed to decode CH_B64: {e}\n")
    sys.exit(1)
PY

# Public key (32-byte, base64)
PUB_B64=$(openssl pkey -in "$PEM" -pubout -outform DER | tail -c 32 | base64 -w0)

# Signature (base64) over challenge bytes
SIG_B64=$(openssl pkeyutl -sign -inkey "$PEM" -rawin -in "$TMP_DIR/ch.bin" | base64 -w0)

echo "PUB_B64=$PUB_B64"
echo "SIG_B64=$SIG_B64"
