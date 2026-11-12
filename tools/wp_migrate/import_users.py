"""Import WordPress customer-area accounts into susi from a plan file.

Create missing users (random password, no invitation email), create or
reuse workspaces, and add memberships. Idempotent: re-running skips what
already exists. Everything created is appended to a manifest for rollback.

    SUSI_TOKEN=susi_pat_... python import_users.py --base https://host plan.json manifest.json [--dry-run]
"""
import argparse, json, os, secrets, urllib.error, urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("plan"); ap.add_argument("manifest")
ap.add_argument("--base", required=True); ap.add_argument("--dry-run", action="store_true")
a = ap.parse_args()
TOKEN = os.environ["SUSI_TOKEN"]


def api(method, path, body=None):
    req = urllib.request.Request(a.base.rstrip("/") + "/api/v1" + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        raise SystemExit(f"{method} {path}: {e.code} {e.read().decode()[:300]}")


def rows(d, key):
    return d.get(key, d) if isinstance(d, dict) else d


plan = json.load(open(a.plan, encoding="utf-8"))
man = json.load(open(a.manifest, encoding="utf-8")) if os.path.exists(a.manifest) else {"users": [], "workspaces": {}, "members": []}
by_email = {(u.get("email") or "").lower(): u["username"] for u in rows(api("GET", "/auth/users"), "users")}
ws_ids = {w["name"]: w["id"] for w in rows(api("GET", "/workspaces"), "workspaces")}
count = {"user": 0, "workspace": 0, "member": 0}


def save():
    if not a.dry_run:
        json.dump(man, open(a.manifest, "w", encoding="utf-8"), indent=1)


name_of = {}
for u in plan["users"]:
    existing = by_email.get(u["email"].lower())
    name_of[u["username"]] = existing or u["username"]
    if existing:
        continue
    count["user"] += 1
    if not a.dry_run:
        api("POST", "/auth/users", {"username": u["username"], "email": u["email"], "role": "user",
                                    "first_name": u["first_name"], "last_name": u["last_name"],
                                    "password": secrets.token_urlsafe(32)})
        man["users"].append(u["username"]); save()

for w in plan["workspaces"]:
    wid = w.get("existing_id") or ws_ids.get(w["name"])
    if not wid:
        count["workspace"] += 1
        if a.dry_run:
            count["member"] += len(w["members"])
            continue
        wid = api("POST", "/workspaces", {"name": w["name"], "description": "Migrated from the LP-Research customer area"})["id"]
        man["workspaces"][w["name"]] = wid; save()
    have = {m["username"] for m in api("GET", f"/workspaces/{wid}")["members"]}
    for m in w["members"]:
        m = name_of[m]
        if m in have:
            continue
        count["member"] += 1
        if not a.dry_run:
            api("POST", f"/workspaces/{wid}/members", {"username": m})
            man["members"].append([wid, m]); save()

print(("would create" if a.dry_run else "created"), count)
