# 输入：CH_B64=从 /registry/challenge 返回的 challenge
CH_B64=$(scripts/get_challenge.sh peer-demo)
# Decode challenge safely (handles missing padding)
python3 - <<'PY' > /tmp/challenge.bin
import base64, os, sys
ch = os.environ["CH_B64"]
ch_padded = ch + "=" * (-len(ch) % 4)
try:
    sys.stdout.buffer.write(base64.b64decode(ch_padded))
except Exception as e:
    sys.stderr.write(f"Failed to decode CH_B64: {e}\n")
    sys.exit(1)
PY

# 生成公钥（填 PUB_B64）
PUB_B64=$(openssl pkey -in ed25519.pem -pubout -outform DER | tail -c 32 | base64 -w0)

# 生成签名（填 SIG_B64）
SIG_B64=$(openssl pkeyutl -sign -inkey ed25519.pem -rawin -in /tmp/challenge.bin | base64 -w0)

echo "PUB_B64=$PUB_B64"
echo "SIG_B64=$SIG_B64"
