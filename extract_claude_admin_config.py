#!/usr/bin/env python3
"""
extract_claude_admin_config.py

Pulls Infoblox's Claude administration configuration into a single auditable
snapshot, then diffs it against an approved baseline.

Outputs (into --outdir, default ./out):
  snapshot-YYYY-MM-DD.json   raw machine-readable capture
  claude-admin-config.md     human-readable "live document"
  drift.md                   only the rows that differ from baseline.json

Credentials (never hard-code these; pull from your secret store):
  ANTHROPIC_COMPLIANCE_ACCESS_KEY   sk-ant-api01-...   (created in claude.ai)
      scopes needed: read:compliance_org_data, read:compliance_user_data
  ANTHROPIC_ADMIN_KEY               sk-ant-admin01-... (created in Console)
      optional; only used for the Console-side workspace / API-key inventory

Usage:
  python3 extract_claude_admin_config.py
  python3 extract_claude_admin_config.py --baseline baseline.json --outdir out
  python3 extract_claude_admin_config.py --skip-users      # settings only, fast

Docs:
  https://platform.claude.com/docs/en/manage-claude/compliance-org-data
  https://platform.claude.com/docs/en/manage-claude/admin-api
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

API_ROOT = "https://api.anthropic.com"
ANTHROPIC_VERSION = "2023-06-01"


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

def _request(path, api_key, params=None, max_retries=5):
    """GET one page. Retries on 429 and 5xx with exponential backoff."""
    url = API_ROOT + path
    if params:
        url += "?" + urllib.parse.urlencode(params, doseq=True)

    for attempt in range(max_retries):
        req = urllib.request.Request(url, method="GET")
        req.add_header("x-api-key", api_key)
        req.add_header("anthropic-version", ANTHROPIC_VERSION)
        req.add_header("accept", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            if e.code in (429, 500, 502, 503, 504) and attempt < max_retries - 1:
                wait = float(e.headers.get("retry-after") or 2 ** attempt)
                sys.stderr.write(f"  {e.code} on {path}; retrying in {wait:.0f}s\n")
                time.sleep(wait)
                continue
            raise RuntimeError(f"{e.code} {path}: {body}") from None
        except urllib.error.URLError as e:
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
                continue
            raise RuntimeError(f"network error on {path}: {e.reason}") from None


def _paginate_token(path, api_key, params=None):
    """Directory endpoints: has_more + next_page token."""
    out, params = [], dict(params or {})
    while True:
        page = _request(path, api_key, params)
        out.extend(page.get("data", []))
        if not page.get("has_more"):
            return out
        params["page"] = page["next_page"]


def _paginate_cursor(path, api_key, params=None):
    """Admin API endpoints: has_more + last_id cursor."""
    out, params = [], dict(params or {})
    params.setdefault("limit", 100)
    while True:
        page = _request(path, api_key, params)
        out.extend(page.get("data", []))
        if not page.get("has_more"):
            return out
        params["after_id"] = page.get("last_id")
        if not params["after_id"]:
            return out


# --------------------------------------------------------------------------
# Collection
# --------------------------------------------------------------------------

def collect_compliance(key, skip_users=False):
    """Everything reachable with a Compliance Access Key."""
    result = {"organizations": []}

    orgs = _paginate_token("/v1/compliance/organizations", key)
    sys.stderr.write(f"Found {len(orgs)} linked organization(s)\n")

    for org in orgs:
        uuid = org["uuid"]
        sys.stderr.write(f"  {org['name']} ({uuid})\n")
        entry = {"uuid": uuid, "name": org.get("name"),
                 "created_at": org.get("created_at")}

        # Effective settings: the enforced state, not the last-saved config.
        # Enabled per parent org separately -- a blanket 404 means your parent
        # org does not have this endpoint turned on yet. Ask your Anthropic rep.
        try:
            entry["effective_settings"] = _request(
                f"/v1/compliance/organizations/{uuid}/settings", key)
        except RuntimeError as e:
            entry["effective_settings_error"] = str(e)
            sys.stderr.write(f"    ! settings unavailable: {e}\n")

        try:
            entry["roles"] = _paginate_token(
                f"/v1/compliance/organizations/{uuid}/roles", key)
        except RuntimeError as e:
            entry["roles_error"] = str(e)

        if not skip_users:
            try:
                users = _paginate_token(
                    f"/v1/compliance/organizations/{uuid}/users",
                    key, {"limit": 500})
                entry["users"] = users
                counts = {}
                for u in users:
                    r = u.get("organization_role", "unknown")
                    counts[r] = counts.get(r, 0) + 1
                entry["user_role_counts"] = counts
            except RuntimeError as e:
                entry["users_error"] = str(e)

        result["organizations"].append(entry)

    # Groups are parent-scoped, not per-organization.
    try:
        groups = _paginate_token("/v1/compliance/groups", key)
        for g in groups:
            try:
                g["members"] = _paginate_token(
                    f"/v1/compliance/groups/{g['id']}/members", key)
            except RuntimeError as e:
                g["members_error"] = str(e)
        result["groups"] = groups
    except RuntimeError as e:
        result["groups_error"] = str(e)

    return result


def collect_admin(key):
    """Console-side inventory: workspaces, members, API keys, invites."""
    out = {}
    for name, path in [
        ("workspaces", "/v1/organizations/workspaces"),
        ("members", "/v1/organizations/users"),
        ("api_keys", "/v1/organizations/api_keys"),
        ("invites", "/v1/organizations/invites"),
    ]:
        try:
            out[name] = _paginate_cursor(path, key)
            sys.stderr.write(f"  admin: {len(out[name])} {name}\n")
        except RuntimeError as e:
            out[name + "_error"] = str(e)
            sys.stderr.write(f"  ! admin {name}: {e}\n")
    return out


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def flatten_settings(effective):
    """settings[] -> {name: value}. Absent rows are NOT 'off' -- see notes."""
    flat = {}
    for row in (effective or {}).get("settings", []):
        flat[row["name"]] = row.get("value")
    return flat


def fmt(v):
    if v is None:
        return "`null`"
    if isinstance(v, bool):
        return "`true`" if v else "`false`"
    if isinstance(v, (dict, list)):
        return "`" + json.dumps(v, separators=(",", ":")) + "`"
    return f"`{v}`"


def render_markdown(snapshot, baseline):
    ts = snapshot["captured_at"]
    L = []
    L.append("# Claude Administration — Configuration of Record")
    L.append("")
    L.append(f"**Captured:** {ts}  ")
    L.append("**Source:** Compliance API `/v1/compliance/*` + Admin API "
             "`/v1/organizations/*`  ")
    L.append("**Regenerate:** `python3 extract_claude_admin_config.py`")
    L.append("")
    L.append("> Values below are the *enforced* state. A setting that is absent "
             "from a response is not controllable by our administrators "
             "(Anthropic policy, or not available on our plan) — treat a "
             "missing row as **not applicable**, never as *off*.")
    L.append("")

    for org in snapshot.get("compliance", {}).get("organizations", []):
        L.append(f"## {org.get('name')} — `{org['uuid']}`")
        L.append("")

        if "effective_settings_error" in org:
            L.append(f"> Settings unavailable: {org['effective_settings_error']}")
            L.append("")
            continue

        flat = flatten_settings(org.get("effective_settings"))
        base = (baseline.get("organizations", {})
                        .get(org["uuid"], {})
                        .get("settings", {}))

        L.append("### Effective settings")
        L.append("")
        L.append("| Setting | Current | Approved baseline | Status |")
        L.append("|---|---|---|---|")
        for name in sorted(flat):
            cur = flat[name]
            if name not in base:
                status = "🆕 unreviewed"
                exp = "—"
            elif base[name] == cur:
                status = "✅ matches"
                exp = fmt(base[name])
            else:
                status = "⚠️ **DRIFT**"
                exp = fmt(base[name])
            L.append(f"| `{name}` | {fmt(cur)} | {exp} | {status} |")
        for name in sorted(set(base) - set(flat)):
            L.append(f"| `{name}` | *(not returned)* | {fmt(base[name])} "
                     f"| ⚠️ **no longer enforced / not applicable** |")
        L.append("")

        keys = (org.get("effective_settings") or {}).get("api_keys", [])
        if keys:
            L.append("### Compliance Access Keys")
            L.append("")
            L.append("| Name | ID | Active | Scopes | Created | Expires |")
            L.append("|---|---|---|---|---|---|")
            for k in keys:
                L.append("| {} | `{}` | {} | {} | {} | {} |".format(
                    k.get("name", "—"), k.get("id"),
                    "yes" if k.get("is_active") else "**no**",
                    ", ".join(f"`{s}`" for s in k.get("scopes", [])),
                    (k.get("created_at") or "—")[:10],
                    (k.get("expires_at") or "never")[:10]))
            L.append("")

        if org.get("user_role_counts"):
            L.append("### Membership by role")
            L.append("")
            L.append("| Role | Count |")
            L.append("|---|---|")
            for r, c in sorted(org["user_role_counts"].items(),
                               key=lambda x: -x[1]):
                L.append(f"| `{r}` | {c} |")
            L.append(f"| **Total** | **{len(org.get('users', []))}** |")
            L.append("")

        if org.get("roles"):
            L.append("### Custom RBAC roles")
            L.append("")
            L.append("| Role | ID | Description | Last updated |")
            L.append("|---|---|---|---|")
            for r in org["roles"]:
                L.append("| {} | `{}` | {} | {} |".format(
                    r.get("name"), r.get("id"),
                    (r.get("description") or "—").replace("|", "\\|"),
                    (r.get("updated_at") or "—")[:10]))
            L.append("")

    groups = snapshot.get("compliance", {}).get("groups", [])
    if groups:
        L.append("## Groups")
        L.append("")
        L.append("| Group | Source | Roles | Members |")
        L.append("|---|---|---|---|")
        for g in groups:
            L.append("| {} | `{}` | {} | {} |".format(
                g.get("name"), g.get("source_type"),
                len(g.get("roles", [])), len(g.get("members", []))))
        L.append("")

    admin = snapshot.get("admin") or {}
    if admin.get("workspaces"):
        L.append("## Console workspaces")
        L.append("")
        L.append("| Workspace | ID | Archived |")
        L.append("|---|---|---|")
        for w in admin["workspaces"]:
            L.append("| {} | `{}` | {} |".format(
                w.get("name"), w.get("id"),
                "yes" if w.get("archived_at") else "no"))
        L.append("")

    if admin.get("api_keys"):
        L.append("## Console API keys")
        L.append("")
        L.append("| Name | ID | Status | Workspace | Created |")
        L.append("|---|---|---|---|---|")
        for k in admin["api_keys"]:
            L.append("| {} | `{}` | {} | `{}` | {} |".format(
                k.get("name", "—"), k.get("id"), k.get("status", "—"),
                k.get("workspace_id") or "default",
                (k.get("created_at") or "—")[:10]))
        L.append("")

    L.append("---")
    L.append("")
    L.append("## Not covered by any API — record manually")
    L.append("")
    L.append("These are real administrative controls that the effective-settings "
             "endpoint does not return. They must be captured by hand and "
             "re-verified each cycle:")
    L.append("")
    L.append("| Item | Where | Owner | Value as of this capture |")
    L.append("|---|---|---|---|")
    for item, where in [
        ("Org-level default model", "claude.ai > Settings"),
        ("Per-role / per-group default model override", "claude.ai > Roles"),
        ("Connector allowlist + per-connector scopes", "Settings > Connectors"),
        ("Desktop extension allowlist contents", "Settings > Extensions"),
        ("Approved MCP servers and tunnel owners", "Console > Workspaces"),
        ("Billing plan, seat count, spend limits", "Console > Billing"),
        ("SSO/IdP app config on the Okta/Entra side", "IdP admin"),
    ]:
        L.append(f"| {item} | {where} | | |")
    L.append("")
    L.append("> The default-model gap is the one that bit us: roles shipped with "
             "an empty default and inherited Opus 5 rather than the org default "
             "of Sonnet 4.6. Nothing in the API would have caught that, so it "
             "stays a manual check with a named owner.")
    L.append("")
    return "\n".join(L)


def render_drift(snapshot, baseline):
    rows = []
    for org in snapshot.get("compliance", {}).get("organizations", []):
        flat = flatten_settings(org.get("effective_settings"))
        base = (baseline.get("organizations", {})
                        .get(org["uuid"], {})
                        .get("settings", {}))
        for name, cur in sorted(flat.items()):
            if name in base and base[name] != cur:
                rows.append((org.get("name"), name, fmt(base[name]), fmt(cur)))
        for name in sorted(set(base) - set(flat)):
            rows.append((org.get("name"), name, fmt(base[name]), "*(not returned)*"))

    L = [f"# Drift report — {snapshot['captured_at']}", ""]
    if not rows:
        L.append("No drift. Every setting with an approved baseline matches.")
    else:
        L.append(f"**{len(rows)} setting(s) differ from the approved baseline.**")
        L.append("")
        L.append("| Organization | Setting | Approved | Current |")
        L.append("|---|---|---|---|")
        for r in rows:
            L.append("| {} | `{}` | {} | {} |".format(*r))
    L.append("")
    return "\n".join(L)


def write_baseline_template(snapshot, path):
    """Freeze the current state as the approved baseline to diff against."""
    out = {"_comment": "Approved values. Edit deliberately; every change here "
                       "is an approval decision, not a sync.",
           "organizations": {}}
    for org in snapshot.get("compliance", {}).get("organizations", []):
        out["organizations"][org["uuid"]] = {
            "name": org.get("name"),
            "settings": flatten_settings(org.get("effective_settings")),
        }
    with open(path, "w") as f:
        json.dump(out, f, indent=2, sort_keys=True)


# --------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--baseline", default="baseline.json")
    p.add_argument("--outdir", default="out")
    p.add_argument("--skip-users", action="store_true",
                   help="skip the per-org user enumeration (much faster)")
    p.add_argument("--skip-admin", action="store_true",
                   help="skip the Console-side Admin API inventory")
    p.add_argument("--init-baseline", action="store_true",
                   help="freeze the current state as the approved baseline")
    args = p.parse_args()

    comp_key = os.environ.get("ANTHROPIC_COMPLIANCE_ACCESS_KEY")
    admin_key = os.environ.get("ANTHROPIC_ADMIN_KEY")

    if not comp_key:
        sys.exit("ANTHROPIC_COMPLIANCE_ACCESS_KEY is not set. Create a "
                 "Compliance Access Key in claude.ai with scopes "
                 "read:compliance_org_data and read:compliance_user_data.")
    if comp_key.startswith("sk-ant-admin"):
        sys.exit("That is an Admin API key. The settings and directory "
                 "endpoints only accept a Compliance Access Key "
                 "(sk-ant-api01-...) created in claude.ai; an Admin key "
                 "reaches the Activity Feed only and will return 403.")

    os.makedirs(args.outdir, exist_ok=True)

    snapshot = {
        "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "captured_by": os.environ.get("USER", "unknown"),
    }

    sys.stderr.write("Collecting Compliance API data...\n")
    snapshot["compliance"] = collect_compliance(comp_key, args.skip_users)

    if admin_key and not args.skip_admin:
        sys.stderr.write("Collecting Admin API data...\n")
        snapshot["admin"] = collect_admin(admin_key)
    else:
        sys.stderr.write("Skipping Admin API (no ANTHROPIC_ADMIN_KEY set)\n")

    day = snapshot["captured_at"][:10]
    snap_path = os.path.join(args.outdir, f"snapshot-{day}.json")
    with open(snap_path, "w") as f:
        json.dump(snapshot, f, indent=2, sort_keys=True)

    if args.init_baseline:
        write_baseline_template(snapshot, args.baseline)
        sys.stderr.write(f"Wrote approved baseline -> {args.baseline}\n")

    baseline = {}
    if os.path.exists(args.baseline):
        with open(args.baseline) as f:
            baseline = json.load(f)
    else:
        sys.stderr.write(f"No {args.baseline} yet; everything will read as "
                         f"'unreviewed'. Run --init-baseline once you have "
                         f"signed off on the current state.\n")

    md_path = os.path.join(args.outdir, "claude-admin-config.md")
    with open(md_path, "w") as f:
        f.write(render_markdown(snapshot, baseline))

    drift_path = os.path.join(args.outdir, "drift.md")
    with open(drift_path, "w") as f:
        f.write(render_drift(snapshot, baseline))

    sys.stderr.write(f"\nWrote:\n  {snap_path}\n  {md_path}\n  {drift_path}\n")


if __name__ == "__main__":
    main()
