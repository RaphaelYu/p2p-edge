import json
import os
import time
from urllib import request, error


BOOTSTRAP = os.environ.get("BOOTSTRAP_URL", "http://bootstrap:8080")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
SLEEP_SECS = int(os.environ.get("SLEEP_SECS", "3"))
MAX_ROUNDS = int(os.environ.get("MAX_ROUNDS", "30"))


def http_get(path):
    req = request.Request(path, headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})
    with request.urlopen(req, timeout=5) as resp:
        return resp.read().decode()


def http_post(path, body_dict):
    data = json.dumps(body_dict).encode()
    req = request.Request(
        path,
        data=data,
        headers={
            "Authorization": f"Bearer {ADMIN_TOKEN}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with request.urlopen(req, timeout=5) as resp:
        return resp.status


def wait_health():
    for _ in range(30):
        try:
            with request.urlopen(f"{BOOTSTRAP}/healthz", timeout=3) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(2)
    return False


def approve_pending():
    payload = http_get(f"{BOOTSTRAP}/registry/nodes?status=pending")
    nodes = json.loads(payload)
    for node in nodes:
        peer_id = node.get("peer_id")
        if not peer_id:
            continue
        status = http_post(f"{BOOTSTRAP}/registry/approve", {"peer_id": peer_id})
        print(f"approve {peer_id}: {status}", flush=True)


def main():
    if not ADMIN_TOKEN:
        print("ADMIN_TOKEN required", flush=True)
        return 1
    if not wait_health():
        print("bootstrap not healthy in time", flush=True)
        return 1
    for _ in range(MAX_ROUNDS):
        try:
            approve_pending()
        except error.HTTPError as e:
            print(f"approve error: {e.code} {e.reason}", flush=True)
        except Exception as e:
            print(f"approve error: {e}", flush=True)
        time.sleep(SLEEP_SECS)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
