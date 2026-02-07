#!/usr/bin/env python3
"""
Admin tool – look up users on R2 and optionally change their tier.
Reads .env in the same directory for R2 credentials.
"""

import os, json, hashlib, hmac, datetime, urllib.request, urllib.parse, ssl

# ── Load .env ────────────────────────────────────────────────────────────────
ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.isfile(ENV_PATH):
    with open(ENV_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

R2_ACCESS_KEY = os.environ.get("R2_ACCESS_KEY_ID", "")
R2_SECRET_KEY = os.environ.get("R2_SECRET_ACCESS_KEY", "")
R2_ENDPOINT   = os.environ.get("R2_ENDPOINT", "").rstrip("/")
R2_BUCKET     = os.environ.get("R2_BUCKET", "")

if not all([R2_ACCESS_KEY, R2_SECRET_KEY, R2_ENDPOINT, R2_BUCKET]):
    print("ERROR: Missing R2 credentials in .env")
    exit(1)

OBJECT_KEY = "data/users.json"

# ── AWS Sig V4 helpers ───────────────────────────────────────────────────────
def _hmac_sha256(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _signing_key(secret: str, datestamp: str, region: str = "auto", service: str = "s3") -> bytes:
    k = _hmac_sha256(("AWS4" + secret).encode("utf-8"), datestamp)
    k = _hmac_sha256(k, region)
    k = _hmac_sha256(k, service)
    k = _hmac_sha256(k, "aws4_request")
    return k

def _r2_request(method: str, body: bytes | None = None, content_type: str | None = None):
    now = datetime.datetime.utcnow()
    datestamp = now.strftime("%Y%m%d")
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    region, service = "auto", "s3"
    cred_scope = f"{datestamp}/{region}/{service}/aws4_request"

    parsed = urllib.parse.urlparse(R2_ENDPOINT)
    host = parsed.hostname
    encoded_key = "/".join(urllib.parse.quote(s, safe="") for s in OBJECT_KEY.split("/"))
    canonical_uri = f"/{R2_BUCKET}/{encoded_key}"

    payload = body or b""
    payload_hash = _sha256_hex(payload)

    headers = {
        "host": host,
        "x-amz-content-sha256": payload_hash,
        "x-amz-date": amz_date,
    }
    if body is not None:
        headers["content-length"] = str(len(body))
    if content_type:
        headers["content-type"] = content_type

    signed_keys = sorted(headers.keys())
    signed_headers = ";".join(signed_keys)
    canonical_headers = "".join(f"{k}:{headers[k]}\n" for k in signed_keys)

    canonical_request = "\n".join([
        method, canonical_uri, "", canonical_headers, signed_headers, payload_hash
    ])

    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amz_date, cred_scope, _sha256_hex(canonical_request.encode("utf-8"))
    ])

    sig_key = _signing_key(R2_SECRET_KEY, datestamp)
    signature = hmac.new(sig_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    auth = f"AWS4-HMAC-SHA256 Credential={R2_ACCESS_KEY}/{cred_scope}, SignedHeaders={signed_headers}, Signature={signature}"
    headers["Authorization"] = auth

    url = f"https://{host}{canonical_uri}"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, context=ctx) as resp:
        return resp.status, resp.read()


def r2_get() -> dict:
    status, body = _r2_request("GET")
    return json.loads(body)


def r2_put(db: dict):
    payload = json.dumps(db, indent=2).encode("utf-8")
    _r2_request("PUT", body=payload, content_type="application/json")


# ── Tier helpers ─────────────────────────────────────────────────────────────
def tier_label(user: dict) -> str:
    manual = user.get("tier")
    if manual in (1, 2):
        t = manual
    else:
        refs = user.get("referredUsers") or []
        count = len(refs)
        if count >= 4:
            t = 2
        elif count >= 1:
            t = 1
        else:
            t = 0
    return {0: "NO TIER", 1: "TIER 1", 2: "TIER 2"}.get(t, "NO TIER")


def strip_discord(name: str) -> str:
    return name[len("discord:"):] if name.startswith("discord:") else name


# ── Main loop ────────────────────────────────────────────────────────────────
def main():
    print("=== Admin User Tool ===\n")

    while True:
        username = input("Username (or 'exit'): ").strip()
        if not username or username.lower() == "exit":
            break

        print("Fetching users.json from R2...")
        try:
            db = r2_get()
        except Exception as e:
            print(f"  ERROR fetching R2: {e}\n")
            continue

        users = db.get("users", {})

        # Search case-insensitively by key, username field, or stripped discord name
        found_key = None
        for key, u in users.items():
            uname = u.get("username", key)
            if (
                key.lower() == username.lower()
                or uname.lower() == username.lower()
                or strip_discord(uname).lower() == username.lower()
            ):
                found_key = key
                break

        if not found_key:
            print(f"  User '{username}' not found.\n")
            continue

        u = users[found_key]
        refs = u.get("referredUsers") or []
        created = u.get("createdAt")
        created_str = datetime.datetime.utcfromtimestamp(created / 1000).strftime("%Y-%m-%d %H:%M UTC") if created else "N/A"

        print(f"\n  Key:            {found_key}")
        print(f"  Username:       {strip_discord(u.get('username', found_key))}")
        print(f"  Provider:       {u.get('provider', 'N/A')}")
        print(f"  Tier (current): {tier_label(u)}")
        print(f"  Manual Tier:    {u.get('tier', 'None')}")
        print(f"  Referrals:      {len(refs)}")
        print(f"  Referred By:    {u.get('referredBy') or 'None'}")
        print(f"  Signup IP:      {u.get('signupIp', 'N/A')}")
        print(f"  Created:        {created_str}")
        print(f"  Premium:        {u.get('premiumProvider') or 'None'}")
        print()

        change = input("  Change Tier? (y/n): ").strip().lower()
        if change not in ("y", "yes"):
            print()
            continue

        tier_input = input("  Tier # (1-2): ").strip()
        if tier_input not in ("1", "2"):
            print("  Invalid tier. Skipping.\n")
            continue

        new_tier = int(tier_input)

        # Re-fetch to minimize race conditions
        try:
            db = r2_get()
        except Exception as e:
            print(f"  ERROR re-fetching R2: {e}\n")
            continue

        if found_key not in db.get("users", {}):
            print("  User disappeared from DB. Skipping.\n")
            continue

        db["users"][found_key]["tier"] = new_tier
        print(f"  Uploading updated users.json (tier → {new_tier})...")
        try:
            r2_put(db)
            print(f"  ✅ {strip_discord(u.get('username', found_key))} is now TIER {new_tier}\n")
        except Exception as e:
            print(f"  ERROR writing R2: {e}\n")


if __name__ == "__main__":
    main()
