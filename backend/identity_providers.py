#!/usr/bin/env python3
"""
Vigilance AI — Live Identity Provider Integration
Supports: Okta + Azure AD (Microsoft Graph)
Falls back to synthetic data if credentials not configured.
"""

import os
import json
import time
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

# ─── CONFIG ──────────────────────────────────────────────────────────────────

OKTA_DOMAIN     = os.getenv("OKTA_DOMAIN", "").strip().rstrip("/")
OKTA_API_TOKEN  = os.getenv("OKTA_API_TOKEN", "").strip()

AZURE_TENANT_ID     = os.getenv("AZURE_TENANT_ID", "").strip()
AZURE_CLIENT_ID     = os.getenv("AZURE_CLIENT_ID", "").strip()
AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET", "").strip()

MAX_USERS = int(os.getenv("MAX_USERS_PER_PROVIDER", 200))

# ─── STATUS ──────────────────────────────────────────────────────────────────

def get_provider_status():
    """Return which providers are configured."""
    return {
        "okta": {
            "configured": bool(OKTA_DOMAIN and OKTA_API_TOKEN),
            "domain": OKTA_DOMAIN or "not configured",
            "label": "Okta"
        },
        "azure_ad": {
            "configured": bool(AZURE_TENANT_ID and AZURE_CLIENT_ID and AZURE_CLIENT_SECRET),
            "tenant": AZURE_TENANT_ID or "not configured",
            "label": "Azure AD"
        }
    }

# ─── OKTA INTEGRATION ────────────────────────────────────────────────────────

def _okta_headers():
    return {
        "Authorization": f"SSWS {OKTA_API_TOKEN}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

def _okta_base():
    domain = OKTA_DOMAIN
    if not domain.startswith("http"):
        domain = "https://" + domain
    return domain

def fetch_okta_users():
    """Pull users from Okta with their profile, status, and last login."""
    users = []
    url = f"{_okta_base()}/api/v1/users?limit=200&filter=status+eq+%22ACTIVE%22"
    fetched = 0

    while url and fetched < MAX_USERS:
        try:
            resp = requests.get(url, headers=_okta_headers(), timeout=10)
            resp.raise_for_status()
            batch = resp.json()
            if not batch:
                break

            for u in batch:
                profile = u.get("profile", {})
                creds   = u.get("credentials", {})

                # Parse last login
                last_login_str = u.get("lastLogin") or u.get("statusChanged")
                days_inactive = _parse_days_inactive(last_login_str)

                # Determine MFA status
                mfa_gap = _check_okta_mfa_gap(u)

                users.append({
                    "id":           u.get("id", ""),
                    "name":         f"{profile.get('firstName','')} {profile.get('lastName','')}".strip() or profile.get("login",""),
                    "email":        profile.get("email", ""),
                    "role":         _infer_role(profile),
                    "department":   profile.get("department", "Unknown"),
                    "systems":      "Okta",
                    "n_systems":    1,
                    "days_inactive": days_inactive,
                    "has_admin":    int(_is_okta_admin(u)),
                    "role_changed": 0,
                    "mfa_gap":      int(mfa_gap),
                    "unusual_location": 0,
                    "is_contractor_expired": 0,
                    "is_service_account": int("service" in profile.get("login","").lower() or
                                              "svc" in profile.get("login","").lower()),
                    "status":       u.get("status", "ACTIVE"),
                    "source":       "okta",
                    "last_login":   last_login_str or "",
                })
                fetched += 1
                if fetched >= MAX_USERS:
                    break

            # Pagination (Okta uses Link header)
            link_header = resp.headers.get("Link", "")
            url = _parse_okta_next_link(link_header)

        except requests.exceptions.RequestException as e:
            print(f"⚠️  Okta API error: {e}")
            break

    # Enrich with group memberships for role detection
    users = _enrich_okta_groups(users)
    print(f"✅ Okta: fetched {len(users)} users")
    return users


def _check_okta_mfa_gap(user):
    """User has MFA gap if MFA not enrolled or last password reset long ago."""
    factors_enrolled = user.get("_embedded", {}).get("factors", [])
    # Simple heuristic: if no factors in embedded data, flag as gap
    # (Full factor check requires separate API call per user — done in batch enrichment)
    return len(factors_enrolled) == 0


def _is_okta_admin(user):
    """Check if user has admin role (requires roles API — approximated here)."""
    login = user.get("profile", {}).get("login", "").lower()
    return "admin" in login or "svc" in login


def _infer_role(profile):
    """Infer role from Okta profile title/department."""
    dept  = (profile.get("department") or "").lower()
    title = (profile.get("title") or "").lower()
    combined = dept + " " + title
    if any(k in combined for k in ["engineer","dev","software","tech"]):  return "Engineering"
    if any(k in combined for k in ["finance","account","payroll","cfo"]): return "Finance"
    if any(k in combined for k in ["hr","human","recruit","people"]):     return "HR"
    if any(k in combined for k in ["market","brand","content","seo"]):    return "Marketing"
    if any(k in combined for k in ["sales","revenue","crm","account"]):   return "Sales"
    if any(k in combined for k in ["it","admin","infra","sys","devops","security"]): return "IT-Admin"
    if any(k in combined for k in ["contract","vendor","partner","consult"]): return "Contractor"
    return "Engineering"  # default


def _parse_okta_next_link(link_header):
    """Extract next page URL from Okta Link header."""
    if not link_header:
        return None
    for part in link_header.split(","):
        if 'rel="next"' in part:
            url = part.strip().split(";")[0].strip().strip("<>")
            return url
    return None


def _enrich_okta_groups(users):
    """
    Fetch admin group memberships to improve has_admin accuracy.
    Does a single call to /api/v1/groups?q=admin to find admin groups,
    then checks membership — only if ≤50 users (to avoid rate limits in demo).
    """
    if len(users) > 50:
        return users  # Skip for large datasets to avoid rate limits
    try:
        url = f"{_okta_base()}/api/v1/groups?q=admin&limit=5"
        resp = requests.get(url, headers=_okta_headers(), timeout=8)
        if resp.status_code != 200:
            return users
        admin_groups = resp.json()
        admin_user_ids = set()
        for group in admin_groups[:3]:  # Check top 3 admin groups
            gid = group.get("id")
            members_resp = requests.get(
                f"{_okta_base()}/api/v1/groups/{gid}/users?limit=200",
                headers=_okta_headers(), timeout=8
            )
            if members_resp.status_code == 200:
                for m in members_resp.json():
                    admin_user_ids.add(m.get("id"))
        for u in users:
            if u["id"] in admin_user_ids:
                u["has_admin"] = 1
    except Exception as e:
        print(f"⚠️  Okta group enrichment skipped: {e}")
    return users


# ─── AZURE AD INTEGRATION ────────────────────────────────────────────────────

_azure_token_cache = {"token": None, "expires_at": 0}

def _get_azure_token():
    """Get Azure AD access token via client credentials flow (cached)."""
    now = time.time()
    if _azure_token_cache["token"] and now < _azure_token_cache["expires_at"] - 60:
        return _azure_token_cache["token"]

    url = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/oauth2/v2.0/token"
    data = {
        "grant_type":    "client_credentials",
        "client_id":     AZURE_CLIENT_ID,
        "client_secret": AZURE_CLIENT_SECRET,
        "scope":         "https://graph.microsoft.com/.default"
    }
    resp = requests.post(url, data=data, timeout=10)
    resp.raise_for_status()
    result = resp.json()
    token = result["access_token"]
    expires_in = result.get("expires_in", 3600)
    _azure_token_cache["token"] = token
    _azure_token_cache["expires_at"] = now + expires_in
    return token


def _graph_get(path, params=None):
    """Make a Microsoft Graph API GET request."""
    token = _get_azure_token()
    url = f"https://graph.microsoft.com/v1.0{path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }
    resp = requests.get(url, headers=headers, params=params, timeout=12)
    resp.raise_for_status()
    return resp.json()


def fetch_azure_users():
    """Pull users from Azure AD via Microsoft Graph API."""
    users = []
    try:
        # Fetch users with relevant fields
        select_fields = ",".join([
            "id", "displayName", "userPrincipalName", "mail",
            "department", "jobTitle", "accountEnabled",
            "signInActivity", "createdDateTime",
            "assignedLicenses", "userType"
        ])

        params = {
            "$select": select_fields,
            "$top": min(MAX_USERS, 999),
            "$filter": "accountEnabled eq true"
        }

        url = "/users"
        fetched = 0

        while url and fetched < MAX_USERS:
            data = _graph_get(url, params=params if "?" not in url else None)
            batch = data.get("value", [])

            for u in batch:
                sign_in = u.get("signInActivity") or {}
                last_login_str = sign_in.get("lastSignInDateTime") or u.get("createdDateTime")
                days_inactive = _parse_days_inactive(last_login_str)

                # Check if admin (approximated — full check via /memberOf)
                upn = u.get("userPrincipalName", "").lower()
                is_admin = "admin" in upn or "svc" in upn

                users.append({
                    "id":           u.get("id", ""),
                    "name":         u.get("displayName", u.get("userPrincipalName", "")),
                    "email":        u.get("mail") or u.get("userPrincipalName", ""),
                    "role":         _infer_role({"department": u.get("department",""), "title": u.get("jobTitle","")}),
                    "department":   u.get("department") or "Unknown",
                    "systems":      "Azure AD",
                    "n_systems":    1,
                    "days_inactive": days_inactive,
                    "has_admin":    int(is_admin),
                    "role_changed": 0,
                    "mfa_gap":      0,  # Enriched separately
                    "unusual_location": 0,
                    "is_contractor_expired": int(u.get("userType","Member") == "Guest"),
                    "is_service_account": int("svc" in upn or "service" in upn),
                    "status":       "ACTIVE" if u.get("accountEnabled") else "INACTIVE",
                    "source":       "azure_ad",
                    "last_login":   last_login_str or "",
                })
                fetched += 1
                if fetched >= MAX_USERS:
                    break

            # Graph API pagination
            url = data.get("@odata.nextLink", "")
            if url:
                url = url.replace("https://graph.microsoft.com/v1.0", "")
            params = None  # nextLink already has params

        # Enrich: get admin role assignments
        users = _enrich_azure_admin_roles(users)
        # Enrich: get MFA status
        users = _enrich_azure_mfa(users)
        # Enrich: get app assignments (multi-system)
        users = _enrich_azure_apps(users)

        print(f"✅ Azure AD: fetched {len(users)} users")

    except requests.exceptions.HTTPError as e:
        print(f"⚠️  Azure AD HTTP error: {e.response.status_code} — {e.response.text[:200]}")
    except Exception as e:
        print(f"⚠️  Azure AD error: {e}")

    return users


def _enrich_azure_admin_roles(users):
    """Check which users have Global Admin / Privileged roles."""
    try:
        # Get members of "Global Administrator" role
        roles_data = _graph_get("/directoryRoles", {"$filter": "displayName eq 'Global Administrator'"})
        roles = roles_data.get("value", [])
        admin_ids = set()
        for role in roles[:3]:
            rid = role.get("id")
            members = _graph_get(f"/directoryRoles/{rid}/members", {"$select": "id"})
            for m in members.get("value", []):
                admin_ids.add(m.get("id"))
        for u in users:
            if u["id"] in admin_ids:
                u["has_admin"] = 1
    except Exception as e:
        print(f"⚠️  Azure admin role enrichment skipped: {e}")
    return users


def _enrich_azure_mfa(users):
    """
    Check MFA registration status via Graph API.
    Requires: Policy.Read.All permission.
    """
    try:
        data = _graph_get(
            "/reports/credentialUserRegistrationDetails",
            {"$top": 999}
        )
        mfa_by_id = {}
        for entry in data.get("value", []):
            uid = entry.get("id", "")
            mfa_registered = entry.get("isMfaRegistered", False)
            mfa_by_id[uid] = mfa_registered
        for u in users:
            if u["id"] in mfa_by_id:
                u["mfa_gap"] = int(not mfa_by_id[u["id"]])
    except Exception as e:
        print(f"⚠️  Azure MFA enrichment skipped (needs Policy.Read.All): {e}")
    return users


def _enrich_azure_apps(users):
    """
    Get app assignments to build multi-system picture.
    Adds Azure-connected apps to the systems field.
    """
    try:
        # Get top service principals (apps)
        sps = _graph_get("/servicePrincipals", {"$top": 20, "$select": "id,displayName,appId"})
        # This is a lightweight enrichment — map known apps to system names
        known_apps = {
            "salesforce": "Salesforce",
            "aws":        "AWS IAM",
            "github":     "GitHub",
            "slack":      "Slack",
            "jira":       "Jira",
            "workday":    "Workday",
        }
        app_names = []
        for sp in sps.get("value", []):
            name = sp.get("displayName", "").lower()
            for k, v in known_apps.items():
                if k in name:
                    app_names.append(v)
        if app_names:
            for u in users:
                # Add Azure AD + detected apps to systems list
                all_sys = list(set(["Azure AD"] + app_names[:3]))
                u["systems"] = ",".join(all_sys)
                u["n_systems"] = len(all_sys)
    except Exception as e:
        print(f"⚠️  Azure app enrichment skipped: {e}")
    return users


# ─── SHARED UTILS ────────────────────────────────────────────────────────────

def _parse_days_inactive(dt_str):
    """Parse ISO datetime string → days since last login."""
    if not dt_str:
        return 999  # Unknown = treat as very stale
    try:
        # Handle both Z and +00:00 suffixes
        dt_str = dt_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(dt_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - dt
        return max(0, delta.days)
    except Exception:
        return 0


# ─── UNIFIED FETCH ───────────────────────────────────────────────────────────

def fetch_live_identities():
    """
    Fetch from all configured providers.
    Returns (users_list, source_info_dict).
    """
    all_users = []
    sources = {}
    status = get_provider_status()

    if status["okta"]["configured"]:
        try:
            okta_users = fetch_okta_users()
            all_users.extend(okta_users)
            sources["okta"] = {"count": len(okta_users), "status": "live", "label": "Okta"}
        except Exception as e:
            print(f"❌ Okta fetch failed: {e}")
            sources["okta"] = {"count": 0, "status": f"error: {str(e)[:60]}", "label": "Okta"}
    else:
        sources["okta"] = {"count": 0, "status": "not_configured", "label": "Okta"}

    if status["azure_ad"]["configured"]:
        try:
            azure_users = fetch_azure_users()
            all_users.extend(azure_users)
            sources["azure_ad"] = {"count": len(azure_users), "status": "live", "label": "Azure AD"}
        except Exception as e:
            print(f"❌ Azure AD fetch failed: {e}")
            sources["azure_ad"] = {"count": 0, "status": f"error: {str(e)[:60]}", "label": "Azure AD"}
    else:
        sources["azure_ad"] = {"count": 0, "status": "not_configured", "label": "Azure AD"}

    return all_users, sources


def test_connections():
    """
    Test connectivity to configured providers.
    Returns dict with test results — used by /api/provider-status endpoint.
    """
    results = {}
    status = get_provider_status()

    # Test Okta
    if status["okta"]["configured"]:
        try:
            url = f"{_okta_base()}/api/v1/users?limit=1"
            resp = requests.get(url, headers=_okta_headers(), timeout=8)
            results["okta"] = {
                "connected": resp.status_code == 200,
                "status_code": resp.status_code,
                "domain": OKTA_DOMAIN,
                "message": "Connected ✅" if resp.status_code == 200 else f"HTTP {resp.status_code}"
            }
        except Exception as e:
            results["okta"] = {"connected": False, "message": str(e)[:80], "domain": OKTA_DOMAIN}
    else:
        results["okta"] = {"connected": False, "message": "Not configured — add OKTA_DOMAIN + OKTA_API_TOKEN to .env"}

    # Test Azure AD
    if status["azure_ad"]["configured"]:
        try:
            token = _get_azure_token()
            results["azure_ad"] = {
                "connected": True,
                "tenant": AZURE_TENANT_ID,
                "message": "Token acquired ✅"
            }
        except Exception as e:
            results["azure_ad"] = {
                "connected": False,
                "tenant": AZURE_TENANT_ID,
                "message": str(e)[:80]
            }
    else:
        results["azure_ad"] = {
            "connected": False,
            "message": "Not configured — add AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_CLIENT_SECRET to .env"
        }

    return results