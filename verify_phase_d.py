#!/usr/bin/env python3
"""Phase D end-to-end verification harness.

Runs against the live local stack and asserts:

    1.  Infrastructure preflight             — Keycloak, OM, Qdrant, MySQL,
                                                middleware, RAG service all up.
    2.  Identity                              — every seeded user can mint a JWT
                                                with the expected realm roles.
    3.  Authorization (OM tag policies)       — for each user's role-tag, OM's
                                                /search/query returns exactly the
                                                expected view set.
    4.  Middleware NLQ flow                   — POST /v1/execute_nlq via SSE,
                                                assert allowed-views count matches
                                                expectation and PII-masking
                                                semantics are right.
    5.  Adversarial                           — no token / bad token / tampered
                                                signature / non-Eunomia role all
                                                rejected.

Exits 0 on full success, 1 on any failure. Prints a PASS/FAIL summary table.

Usage:
    python verify_phase_d.py
    python verify_phase_d.py --skip-nlq   # skip the LLM-dependent steps
    python verify_phase_d.py --quiet      # only print the summary table

Designed to be runnable from `eunomia-cli admin verify` (per task #25's runbook).
"""

from __future__ import annotations

import argparse
import base64
import json
import socket
import sys
import time
import traceback
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

import httpx

# --------------------------------------------------------------------------- #
# Config — endpoints + expected matrix                                        #
# --------------------------------------------------------------------------- #

KEYCLOAK_URL  = "http://localhost:8080"
REALM         = "eunomia"
OM_URL        = "http://localhost:8585"
QDRANT_URL    = "http://localhost:6333"
MIDDLEWARE_URL = "http://localhost:8000"
RAG_URL       = "http://localhost:9000"
MYSQL_HOST    = "127.0.0.1"
MYSQL_PORT    = 3306

ISSUER         = f"{KEYCLOAK_URL}/realms/{REALM}"
TOKEN_ENDPOINT = f"{ISSUER}/protocol/openid-connect/token"
JWKS_ENDPOINT  = f"{ISSUER}/protocol/openid-connect/certs"

# (username, expected realm roles, expected allowed views via OM tag policies)
USERS: Dict[str, Dict[str, Any]] = {
    "finance.alice":   {
        "roles":          {"eunomia-finance-user", "eunomia-pii-unmask"},
        "tag":            "eunomia-access.finance-user",
        "expected_views": {"finance_daily_revenue_view",
                            "finance_customer_payment_history_view"},
        "unmask_pii":     True,
    },
    "auditor.bob":     {
        "roles":          {"eunomia-external-auditor"},
        "tag":            "eunomia-access.external-auditor",
        "expected_views": {"finance_customer_payment_history_view"},
        "unmask_pii":     False,
    },
    "marketing.carol": {
        "roles":          {"eunomia-marketing-lead", "eunomia-pii-unmask"},
        "tag":            "eunomia-access.marketing-lead",
        "expected_views": {"marketing_customer_ltv_view",
                            "marketing_regional_performance_view"},
        "unmask_pii":     True,
    },
    "agency.dave":     {
        "roles":          {"eunomia-agency-partner"},
        "tag":            "eunomia-access.agency-partner",
        "expected_views": {"marketing_regional_performance_view"},
        "unmask_pii":     False,
    },
    "om.admin":        {
        "roles":          {"eunomia-om-admin", "eunomia-pii-unmask"},
        "tag":            None,  # admin bypass — q=*
        "expected_views": {"finance_daily_revenue_view",
                            "finance_customer_payment_history_view",
                            "marketing_customer_ltv_view",
                            "marketing_regional_performance_view"},
        "unmask_pii":     True,
    },
}


# --------------------------------------------------------------------------- #
# Result accumulator                                                          #
# --------------------------------------------------------------------------- #


@dataclass
class CaseResult:
    section: str
    name:    str
    passed:  bool
    detail:  str = ""


RESULTS: List[CaseResult] = []
QUIET: bool = False


def _emit(label: str, passed: bool, detail: str = "") -> None:
    mark = "\033[32m✓\033[0m" if passed else "\033[31m✗\033[0m"
    if not QUIET:
        msg = f"  {mark} {label}"
        if detail and not passed:
            msg += f"  — {detail}"
        elif detail and passed:
            msg += f"  ({detail})"
        print(msg)


def case(section: str, name: str, fn: Callable[[], Tuple[bool, str]]) -> None:
    try:
        passed, detail = fn()
    except AssertionError as e:
        passed, detail = False, str(e) or "assertion failed"
    except Exception as e:
        passed = False
        detail = f"{type(e).__name__}: {e}"
    _emit(name, passed, detail)
    RESULTS.append(CaseResult(section=section, name=name, passed=passed, detail=detail))


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


def section(title: str) -> None:
    if not QUIET:
        print(f"\n\033[1m=== {title} ===\033[0m")


def get_token(user: str, password: str = "test") -> str:
    r = httpx.post(TOKEN_ENDPOINT, data={
        "client_id": "eunomia-cli",
        "grant_type": "password",
        "username":   user,
        "password":   password,
    }, timeout=10.0)
    r.raise_for_status()
    return r.json()["access_token"]


def decode_jwt_payload(token: str) -> Dict[str, Any]:
    payload = token.split(".")[1]
    padded = payload + "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def realm_roles(token: str) -> set:
    claims = decode_jwt_payload(token)
    return set((claims.get("realm_access") or {}).get("roles") or [])


def om_search_for_tag(token: str, tag_fqn: Optional[str]) -> set:
    """Returns the set of table NAMES visible to this user via OM /search/query.

    `tag_fqn=None` means admin bypass (q=*) — fetches all tables in the index.
    """
    if tag_fqn is None:
        q = "*"
    else:
        q = f'tags.tagFQN:"{tag_fqn}"'
    url = (
        f"{OM_URL}/api/v1/search/query?q={urllib.parse.quote(q)}"
        f"&index=table_search_index&from=0&size=50"
    )
    r = httpx.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=10.0)
    r.raise_for_status()
    hits = (r.json() or {}).get("hits", {}).get("hits", []) or []
    return {h["_source"]["name"] for h in hits if "name" in h.get("_source", {})}


def post_nlq_collect_stream(
    middleware_url: str, token: Optional[str], query: str, timeout_sec: float = 30.0,
) -> Tuple[int, List[Dict[str, Any]]]:
    """POST /v1/execute_nlq and parse the SSE stream until terminal event.

    Returns (status_code, [event-dicts]). The final event may be 'complete' or
    a mid-stream error envelope. Status code is the initial HTTP status; for
    auth-rejected requests we never see SSE events.
    """
    url = f"{middleware_url.rstrip('/')}/v1/execute_nlq"
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    events: List[Dict[str, Any]] = []
    with httpx.Client(timeout=httpx.Timeout(timeout_sec)) as client:
        with client.stream("POST", url, headers=headers,
                           json={"query": query}) as r:
            if r.status_code != 200:
                return r.status_code, events
            current_event = "status"
            for raw in r.iter_lines():
                if not raw:
                    continue
                if raw.startswith("event: "):
                    current_event = raw[len("event: "):].strip()
                    continue
                if raw.startswith("data: "):
                    body = raw[len("data: "):]
                    try:
                        d = json.loads(body)
                    except json.JSONDecodeError:
                        d = {"raw": body}
                    events.append({"event": current_event, **d})
                    if current_event == "complete":
                        break
                    current_event = "status"
    return 200, events


# --------------------------------------------------------------------------- #
# Sections                                                                    #
# --------------------------------------------------------------------------- #


def preflight() -> None:
    section("1. Preflight")

    def kc():
        r = httpx.get(f"{ISSUER}/.well-known/openid-configuration", timeout=5.0)
        return r.status_code == 200, f"HTTP {r.status_code}"
    case("preflight", "Keycloak realm discovery", kc)

    def om():
        r = httpx.get(f"{OM_URL}/healthcheck", timeout=5.0)
        return r.status_code == 200, f"HTTP {r.status_code}"
    case("preflight", "OpenMetadata /healthcheck", om)

    def qd():
        r = httpx.get(f"{QDRANT_URL}/healthz", timeout=5.0)
        return r.status_code == 200, f"HTTP {r.status_code}"
    case("preflight", "Qdrant /healthz", qd)

    def mw():
        r = httpx.get(f"{MIDDLEWARE_URL}/docs", timeout=5.0)
        return r.status_code == 200, f"HTTP {r.status_code}"
    case("preflight", "Middleware /docs", mw)

    def rg():
        r = httpx.get(f"{RAG_URL}/v1/healthz", timeout=5.0)
        return r.status_code == 200, f"HTTP {r.status_code}"
    case("preflight", "RAG /v1/healthz", rg)

    def mysql_port():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2.0)
            ok = s.connect_ex((MYSQL_HOST, MYSQL_PORT)) == 0
        return ok, f"{MYSQL_HOST}:{MYSQL_PORT}"
    case("preflight", "MySQL :3306 reachable", mysql_port)


def identity() -> None:
    section("2. Identity (Keycloak token grant + role claim)")
    for user, spec in USERS.items():
        def _(u=user, expected=spec["roles"]):
            tok = get_token(u)
            got = realm_roles(tok)
            return got == expected, f"got {sorted(got)}, want {sorted(expected)}"
        case("identity", f"{user}: token + expected roles", _)


def om_authorization() -> None:
    section("3. OpenMetadata tag-policy authorization")
    for user, spec in USERS.items():
        def _(u=user, tag=spec["tag"], expected=spec["expected_views"]):
            tok = get_token(u)
            got = om_search_for_tag(tok, tag)
            return got == expected, f"got {sorted(got)}, want {sorted(expected)}"
        case("om_authz", f"{user}: OM tag search returns expected views", _)


def nlq_flow(skip: bool) -> None:
    section("4. Middleware NLQ flow (SSE)")
    if skip:
        case("nlq", "skipped", lambda: (True, "--skip-nlq"))
        return

    # Each user gets a role-appropriate query.
    user_queries = {
        "finance.alice":   "what is our daily revenue last week",
        "auditor.bob":     "show me the payment history",
        "marketing.carol": "show me customer lifetime value",
        "agency.dave":     "regional sales performance",
        "om.admin":        "what tables can I query",
    }
    for user, q in user_queries.items():
        spec = USERS[user]
        expected = spec["expected_views"]

        def _(u=user, query=q, expected_count=len(expected)):
            tok = get_token(u)
            code, events = post_nlq_collect_stream(MIDDLEWARE_URL, tok, query)
            if code != 200:
                return False, f"HTTP {code}"
            # Look for the "Found N Allowed Views" status — proves OM authz fired
            statuses = [e.get("status", "") for e in events if "status" in e]
            found_line = next((s for s in statuses if s.startswith("Found ")), None)
            if not found_line:
                return False, f"no 'Found N Allowed Views' status; events={statuses[:3]}"
            # Parse the number out
            try:
                n = int(found_line.split()[1])
            except (IndexError, ValueError):
                return False, f"unparsable status: {found_line!r}"
            return n == expected_count, (
                f"middleware found {n} views, expected {expected_count}"
            )
        case("nlq", f"{user}: NLQ → 'Found {len(expected)} Allowed Views'", _)


def adversarial() -> None:
    section("5. Adversarial — bad / missing / tampered tokens")

    def no_token():
        code, _ = post_nlq_collect_stream(MIDDLEWARE_URL, None, "foo")
        return code == 401, f"HTTP {code}"
    case("adversarial", "No bearer header → 401", no_token)

    def gibberish():
        code, _ = post_nlq_collect_stream(MIDDLEWARE_URL, "not-a-token", "foo")
        return code == 401, f"HTTP {code}"
    case("adversarial", "Gibberish bearer → 401", gibberish)

    def tampered():
        # Get a real token then flip 10 chars of the signature
        tok = get_token("finance.alice")
        head, payload, sig = tok.split(".")
        bad = f"{head}.{payload}.{'X' * 10}{sig[10:]}"
        code, _ = post_nlq_collect_stream(MIDDLEWARE_URL, bad, "foo")
        return code == 401, f"HTTP {code}"
    case("adversarial", "Tampered signature → 401", tampered)

    def wrong_realm():
        # Mint a JWT for a non-eunomia realm (impossible to do meaningfully
        # without a key; substitute by altering the iss claim — signature breaks
        # too which gives the same 401, but the test is intentionally redundant
        # with `tampered` and serves as a documented spec).
        tok = get_token("finance.alice")
        head_b64, payload_b64, sig = tok.split(".")
        payload = json.loads(base64.urlsafe_b64decode(
            payload_b64 + "=" * (-len(payload_b64) % 4)
        ))
        payload["iss"] = "http://attacker.example/realms/eunomia"
        bad_payload = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b"=").decode()
        bad = f"{head_b64}.{bad_payload}.{sig}"
        code, _ = post_nlq_collect_stream(MIDDLEWARE_URL, bad, "foo")
        return code == 401, f"HTTP {code}"
    case("adversarial", "Wrong issuer in claims → 401", wrong_realm)


def pii_matrix() -> None:
    """Section 6: PII masking semantics (independent of LLM success).

    We rely on the AUDIT JSONL log to read the trust trail without needing
    a successful Gemini call. The audit record's `unmask_pii` flag and
    `pii_columns_masked` array are authoritative.
    """
    section("6. PII masking matrix (via audit log inspection)")

    # Each user makes a query that triggers discovery + audit emission,
    # regardless of whether the LLM/MySQL succeeds.
    from pathlib import Path
    middleware_audit = Path(__file__).resolve().parent.parent / "eunomia-middleware" / "logs" / "audit.jsonl"
    if not middleware_audit.exists():
        case("pii", "audit.jsonl exists", lambda: (False, str(middleware_audit)))
        return

    # Per-user expected unmask flag.
    for user, spec in USERS.items():
        def _(u=user, want_unmask=spec["unmask_pii"]):
            tok = get_token(u)
            post_nlq_collect_stream(MIDDLEWARE_URL, tok, f"verify pii probe for {u}")
            # Scan the LAST line in audit.jsonl that matches this user.
            with middleware_audit.open() as f:
                lines = [ln for ln in f.read().splitlines() if ln.strip()]
            entry = None
            for ln in reversed(lines):
                rec = json.loads(ln)
                if rec.get("preferred_username") == u:
                    entry = rec
                    break
            if entry is None:
                return False, f"no audit entry for {u}"
            got = bool(entry.get("unmask_pii"))
            return got == want_unmask, f"unmask_pii={got}, expected {want_unmask}"
        case("pii", f"{user}: audit.unmask_pii matches role", _)


# --------------------------------------------------------------------------- #
# Summary                                                                     #
# --------------------------------------------------------------------------- #


def _summary() -> int:
    print("\n" + "=" * 70)
    print("PHASE D VERIFICATION SUMMARY")
    print("=" * 70)
    by_section: Dict[str, List[CaseResult]] = {}
    for r in RESULTS:
        by_section.setdefault(r.section, []).append(r)
    overall_ok = True
    for sec_name, results in by_section.items():
        passed = sum(1 for r in results if r.passed)
        total  = len(results)
        mark   = "\033[32m✓\033[0m" if passed == total else "\033[31m✗\033[0m"
        print(f"  {mark} {sec_name:18s}  {passed}/{total}")
        for r in results:
            if not r.passed:
                overall_ok = False
                print(f"      \033[31m✗\033[0m {r.name}: {r.detail}")
    total_pass = sum(1 for r in RESULTS if r.passed)
    total      = len(RESULTS)
    print("-" * 70)
    print(f"  TOTAL: {total_pass}/{total}  "
          + ("\033[32mPASS\033[0m" if overall_ok else "\033[31mFAIL\033[0m"))
    return 0 if overall_ok else 1


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--skip-nlq", action="store_true",
                    help="Skip the LLM-dependent NLQ section.")
    p.add_argument("--quiet", action="store_true",
                    help="Suppress per-case output; print only the summary.")
    args = p.parse_args()

    global QUIET
    QUIET = bool(args.quiet)

    preflight()
    identity()
    om_authorization()
    nlq_flow(skip=args.skip_nlq)
    adversarial()
    pii_matrix()

    return _summary()


if __name__ == "__main__":
    sys.exit(main())
