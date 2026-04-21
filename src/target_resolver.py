"""
target_resolver.py
─────────────────────────────────────────────────────────────────────────────
Converts a GitHub URL (or short name) into a validated search scope qualifier
that can be appended to a GitHub code-search query.

Responsible scanning principles applied here
─────────────────────────────────────────────
  HEAD-first validation  — We confirm a target exists by sending a HEAD
    request before committing to a full scan.  HEAD asks the server for
    its "ID badge" (status code + headers) without downloading any content,
    so it is faster and produces zero load on the target.

  Transparent User-Agent — Every outbound request carries the researcher
    User-Agent so the origin of the probe is clear and auditable.

  Single validation request — We probe the canonical GitHub URL exactly
    once to confirm existence; we do not enumerate, brute-force, or
    spider any paths.

Supported input formats
───────────────────────
  https://github.com/dynatrace                  → org or user scope
  https://github.com/dynatrace/dynatrace-otel   → single repo scope
  github.com/dynatrace                          → same (no scheme required)
  dynatrace                                     → bare name — org/user probe
  dynatrace/dynatrace-otel                      → bare owner/repo
  (empty / Enter)                               → global scan, no scoping
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

# ── Researcher User-Agent — same string used throughout the project ──────────
# Identifying ourselves prevents us from looking like an anonymous script and
# signals to GitHub's abuse-detection systems that this is legitimate research.
_USER_AGENT = (
    "CTI-Researcher-SSH-Hunter/1.0 "
    "(responsible-disclosure-research; github-key-exposure-scan)"
)

# Standard headers for every outbound HTTP request from this module
_HEADERS = {
    "User-Agent": _USER_AGENT,
    # Accept header signals a browser-like client; avoids some WAF fingerprints
    "Accept": "text/html,application/xhtml+xml",
}

# How long to wait for GitHub to respond to our HEAD validation probe
_PROBE_TIMEOUT: int = 10

# Polite pause after any outbound request from this module — keeps us well
# under GitHub's unauthenticated rate limit of 60 requests/hour for the API
# and avoids triggering abuse detection on the web tier.
_PROBE_DELAY: float = 1.0


# ── Scope types ───────────────────────────────────────────────────────────────

class ScopeType(str, Enum):
    ORG    = "org"     # GitHub organisation   → org:name qualifier
    USER   = "user"    # Individual user        → user:name qualifier
    REPO   = "repo"    # Single repository      → repo:owner/name qualifier
    GLOBAL = "global"  # No scoping — scan all of GitHub


@dataclass
class TargetScope:
    """
    Resolved scan target.  The search_qualifier is appended directly to
    every GitHub code-search query string, e.g.:
        '"BEGIN RSA PRIVATE KEY" org:dynatrace'
    """
    raw_input:        str            # exactly what the user typed
    scope_type:       ScopeType      # ORG | USER | REPO | GLOBAL
    name:             str            # org name, username, or owner/repo
    search_qualifier: str            # ready-to-append GitHub search qualifier
    display_label:    str            # human-readable label for console output
    verified:         bool = False   # True if HEAD probe confirmed existence


# ── URL / string parser ───────────────────────────────────────────────────────

# Matches an owner/repo pair — letters, digits, hyphens, underscores, dots
_OWNER_REPO_RE = re.compile(
    r"^(?P<owner>[A-Za-z0-9_.\-]+)/(?P<repo>[A-Za-z0-9_.\-]+)$"
)

# Matches a bare org/user name (no slash)
_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")


def parse_github_url(raw: str) -> Optional[TargetScope]:
    """
    Parse any GitHub URL or short-form identifier into a :class:`TargetScope`.

    Returns None if the input is empty (caller should treat as GLOBAL).
    Raises ValueError for inputs that look like GitHub URLs but are malformed.

    Examples
    --------
    >>> parse_github_url("https://github.com/dynatrace")
    TargetScope(scope_type=ORG, name="dynatrace", ...)

    >>> parse_github_url("https://github.com/dynatrace/dynatrace-operator")
    TargetScope(scope_type=REPO, name="dynatrace/dynatrace-operator", ...)

    >>> parse_github_url("dynatrace")
    TargetScope(scope_type=ORG, name="dynatrace", ...)

    >>> parse_github_url("")
    None   →  caller treats as GLOBAL
    """
    # ── Strip whitespace ──────────────────────────────────────────────────────
    raw = raw.strip()

    if not raw:
        # Empty input → global scan (no scoping qualifier)
        return TargetScope(
            raw_input        = raw,
            scope_type       = ScopeType.GLOBAL,
            name             = "",
            search_qualifier = "",
            display_label    = "Global scan (all of GitHub)",
        )

    # ── Detect bare-name inputs BEFORE URL parsing ───────────────────────────
    # urlparse cannot handle bare names like "dynatrace" or "owner/repo"
    # because it interprets the name as a hostname, not a path.
    # We catch these patterns first and return early.

    # Case 1: bare owner/repo  e.g.  "dynatrace/dynatrace-operator"
    m = _OWNER_REPO_RE.match(raw)
    if m and "github.com" not in raw.lower():
        owner, repo = m.group("owner"), m.group("repo")
        full_name = f"{owner}/{repo}"
        return TargetScope(
            raw_input        = raw,
            scope_type       = ScopeType.REPO,
            name             = full_name,
            search_qualifier = f"repo:{full_name}",
            display_label    = f"Single repository: {full_name}",
        )

    # Case 2: bare org/user name  e.g.  "dynatrace"
    # Must not contain a dot that would indicate a domain (github.com),
    # a colon (http://...), or a slash already caught above.
    if (_NAME_RE.match(raw)
            and "." not in raw         # dots → likely a domain, not a bare name
            and ":" not in raw         # colons → likely a scheme
            and "/" not in raw):       # slashes → already caught above
        return TargetScope(
            raw_input        = raw,
            scope_type       = ScopeType.ORG,   # tentative; confirmed by validate_target
            name             = raw,
            search_qualifier = f"org:{raw}",
            display_label    = f"Organisation / user: {raw}",
        )

    # ── URL path — add scheme if missing so urlparse works correctly ──────────
    # Handles "github.com/dynatrace" without https://
    normalised = raw
    if not normalised.startswith(("http://", "https://")):
        normalised = "https://" + normalised

    parsed = urlparse(normalised)
    path   = parsed.path.strip("/")   # remove leading/trailing slashes

    # ── Validate host — must be github.com ────────────────────────────────────
    host = parsed.netloc.lower()
    if host and host not in ("github.com", "www.github.com"):
        raise ValueError(
            f"Unsupported host '{parsed.netloc}'. "
            f"Only github.com URLs are supported."
        )

    # ── Route based on path depth ─────────────────────────────────────────────
    parts = [p for p in path.split("/") if p]   # remove empty segments

    if len(parts) == 0:
        # e.g. https://github.com/  — treat as global
        return TargetScope(
            raw_input        = raw,
            scope_type       = ScopeType.GLOBAL,
            name             = "",
            search_qualifier = "",
            display_label    = "Global scan (all of GitHub)",
        )

    elif len(parts) == 1:
        # e.g. https://github.com/dynatrace
        name = parts[0]
        if not _NAME_RE.match(name):
            raise ValueError(f"Invalid GitHub org/user name: '{name}'")
        # Default to ORG scope; validate_target() promotes to USER if needed
        return TargetScope(
            raw_input        = raw,
            scope_type       = ScopeType.ORG,   # tentative — confirmed by validate_target
            name             = name,
            search_qualifier = f"org:{name}",
            display_label    = f"Organisation / user: {name}",
        )

    elif len(parts) == 2:
        # e.g. https://github.com/dynatrace/dynatrace-operator
        owner, repo = parts[0], parts[1]
        if not _NAME_RE.match(owner) or not _NAME_RE.match(repo):
            raise ValueError(f"Invalid GitHub repo path: '{owner}/{repo}'")
        full_name = f"{owner}/{repo}"
        return TargetScope(
            raw_input        = raw,
            scope_type       = ScopeType.REPO,
            name             = full_name,
            search_qualifier = f"repo:{full_name}",
            display_label    = f"Single repository: {full_name}",
        )

    else:
        # 3+ path segments — strip deep paths (/tree/main, /blob/main/…)
        # and resolve as a repo scope using the first two segments.
        owner, repo = parts[0], parts[1]
        full_name   = f"{owner}/{repo}"
        logger.debug(
            "URL has %d path segments; treating as repo scope '%s'",
            len(parts), full_name,
        )
        return TargetScope(
            raw_input        = raw,
            scope_type       = ScopeType.REPO,
            name             = full_name,
            search_qualifier = f"repo:{full_name}",
            display_label    = f"Single repository: {full_name} (truncated from longer URL)",
        )


# ── HEAD-based existence validation ──────────────────────────────────────────

def validate_target(scope: TargetScope) -> TargetScope:
    """
    Confirm the target exists by sending a single HEAD request to GitHub.

    HEAD-first rationale
    ────────────────────
    We ask for only the "ID badge" (HTTP status code) rather than the full
    page.  This is courteous (no bandwidth cost to GitHub), fast (~100ms),
    and sufficient — a 200/301 tells us the org/user/repo is real.

    For ORG scope, we first probe https://github.com/{name}.  If the target
    turns out to be an individual user rather than an org, GitHub still
    returns 200 at that URL — so no extra probe is needed.  We upgrade the
    qualifier from org: to user: only when the GitHub API explicitly returns
    404 for the org endpoint, confirming it is a user account.

    Returns a (potentially updated) TargetScope with verified=True.
    Raises ValueError if the target cannot be confirmed.
    """
    if scope.scope_type == ScopeType.GLOBAL:
        # Global scope requires no validation — always valid
        return TargetScope(
            raw_input        = scope.raw_input,
            scope_type       = ScopeType.GLOBAL,
            name             = "",
            search_qualifier = "",
            display_label    = "Global scan (all of GitHub)",
            verified         = True,
        )

    # Build the canonical GitHub web URL for this target
    if scope.scope_type == ScopeType.REPO:
        probe_url = f"https://github.com/{scope.name}"
    else:
        probe_url = f"https://github.com/{scope.name}"

    logger.info(
        "Validating target via HEAD probe: %s (User-Agent: %s)",
        probe_url, _USER_AGENT,
    )

    try:
        # ── HEAD request — polite, fast, read-only ────────────────────────────
        # We use HEAD (not GET) so we receive only headers with no response body.
        # This is the minimum possible footprint for confirming a URL exists.
        resp = requests.head(
            probe_url,
            headers   = _HEADERS,
            timeout   = _PROBE_TIMEOUT,
            # Follow redirects — GitHub redirects http→https and www→non-www
            allow_redirects = True,
        )

        # Polite delay after every outbound request
        time.sleep(_PROBE_DELAY)

        logger.debug(
            "HEAD %s → HTTP %d (final URL: %s)",
            probe_url, resp.status_code, resp.url,
        )

        if resp.status_code == 200:
            # Target confirmed.  Now determine if it's an org or user so we
            # emit the correct search qualifier (org: vs user:).
            # We do this with a lightweight API call rather than another web probe.
            resolved_scope = _resolve_org_or_user(scope)
            resolved_scope.verified = True
            return resolved_scope

        elif resp.status_code in (301, 302):
            # GitHub sometimes redirects org URLs — follow and accept as valid
            logger.info("Target redirected to %s — treating as valid.", resp.url)
            resolved_scope = _resolve_org_or_user(scope)
            resolved_scope.verified = True
            return resolved_scope

        elif resp.status_code == 404:
            raise ValueError(
                f"Target not found (HTTP 404): '{scope.name}'.  "
                f"Check the URL and ensure the org/user/repo is public."
            )

        elif resp.status_code == 429:
            # GitHub rate-limited even the HEAD probe — rare but possible
            raise ValueError(
                "GitHub rate-limited the validation probe (HTTP 429).  "
                "Wait a minute and try again."
            )

        else:
            raise ValueError(
                f"Unexpected HTTP {resp.status_code} validating '{probe_url}'.  "
                f"The target may be private or GitHub may be experiencing issues."
            )

    except requests.exceptions.ConnectionError:
        raise ValueError(
            f"Could not connect to github.com.  "
            f"Check your network connection and try again."
        )
    except requests.exceptions.Timeout:
        raise ValueError(
            f"Connection timed out while probing '{probe_url}'.  "
            f"GitHub may be slow; try again shortly."
        )
    except requests.exceptions.RequestException as exc:
        raise ValueError(f"Network error during target validation: {exc}") from exc


def _resolve_org_or_user(scope: TargetScope) -> TargetScope:
    """
    Determine whether a single-name scope is an organisation or a user account.

    Strategy — single lightweight API call:
      GET https://api.github.com/orgs/{name}
        → 200: it's an org    → qualifier = org:{name}
        → 404: it's a user   → qualifier = user:{name}

    This is a GET (not HEAD) because the GitHub API returns a 404 body that
    confirms user existence, whereas a HEAD would give us less information.
    We only call this once per scan, so the cost is negligible.

    For REPO scope, no disambiguation is needed — the qualifier is always
    repo:owner/name regardless.
    """
    if scope.scope_type != ScopeType.ORG:
        # REPO scope: no disambiguation needed
        return scope

    # ── Probe the orgs API endpoint ───────────────────────────────────────────
    api_url = f"https://api.github.com/orgs/{scope.name}"
    logger.debug("Disambiguating org vs user: GET %s", api_url)

    try:
        resp = requests.get(
            api_url,
            headers = {
                **_HEADERS,
                # Ask for the v3 API explicitly
                "Accept": "application/vnd.github.v3+json",
            },
            timeout         = _PROBE_TIMEOUT,
            allow_redirects = True,
        )
        time.sleep(_PROBE_DELAY)   # polite pause after API call

        if resp.status_code == 200:
            # Confirmed organisation
            data         = resp.json()
            display_name = data.get("name") or scope.name
            logger.info(
                "Target confirmed as GitHub Organisation: %s (%s)",
                scope.name, display_name,
            )
            return TargetScope(
                raw_input        = scope.raw_input,
                scope_type       = ScopeType.ORG,
                name             = scope.name,
                search_qualifier = f"org:{scope.name}",
                display_label    = (
                    f"Organisation: {display_name} "
                    f"({data.get('public_repos', '?')} public repos)"
                ),
            )

        elif resp.status_code == 404:
            # Not an org — check if it's a user account
            user_url  = f"https://api.github.com/users/{scope.name}"
            user_resp = requests.get(
                user_url,
                headers         = {**_HEADERS, "Accept": "application/vnd.github.v3+json"},
                timeout         = _PROBE_TIMEOUT,
                allow_redirects = True,
            )
            time.sleep(_PROBE_DELAY)

            if user_resp.status_code == 200:
                data         = user_resp.json()
                display_name = data.get("name") or scope.name
                logger.info(
                    "Target confirmed as GitHub User: %s (%s)",
                    scope.name, display_name,
                )
                return TargetScope(
                    raw_input        = scope.raw_input,
                    scope_type       = ScopeType.USER,
                    name             = scope.name,
                    search_qualifier = f"user:{scope.name}",
                    display_label    = (
                        f"User: {display_name} "
                        f"({data.get('public_repos', '?')} public repos)"
                    ),
                )
            else:
                # Neither org nor user — shouldn't happen after the HEAD probe
                # passed, but handle defensively
                raise ValueError(
                    f"'{scope.name}' is neither a GitHub org nor a user account."
                )

        else:
            # Unexpected status — fall back to org: qualifier and log a warning
            logger.warning(
                "Could not disambiguate org/user for '%s' (HTTP %d); "
                "defaulting to org: qualifier.",
                scope.name, resp.status_code,
            )
            return scope

    except requests.exceptions.RequestException as exc:
        # Network error during disambiguation — fall back to original scope
        logger.warning(
            "Network error during org/user disambiguation (%s); "
            "using default qualifier '%s'.",
            exc, scope.search_qualifier,
        )
        return scope


# ── Interactive prompt ────────────────────────────────────────────────────────

def prompt_for_target() -> TargetScope:
    """
    Interactively prompt the operator for a target GitHub URL.

    Validates the parsed scope before returning so the scan never starts
    against a target that doesn't exist.  The operator can press Enter
    (empty input) to run a global scan of all of GitHub.

    This function loops until it receives valid, confirmed input or the
    operator interrupts with Ctrl+C.
    """
    print()
    print("┌─────────────────────────────────────────────────────────────┐")
    print("│          CTI SSH Key Hunter — Target Selection              │")
    print("├─────────────────────────────────────────────────────────────┤")
    print("│  Enter a GitHub URL, org name, or repo to scope the scan.  │")
    print("│  Press Enter with no input to scan all of GitHub (global).  │")
    print("│                                                             │")
    print("│  Examples:                                                  │")
    print("│    https://github.com/dynatrace                             │")
    print("│    https://github.com/dynatrace/dynatrace-operator          │")
    print("│    dynatrace                                                │")
    print("│    dynatrace/dynatrace-operator                             │")
    print("│    (Enter)  →  global scan                                  │")
    print("└─────────────────────────────────────────────────────────────┘")
    print()

    while True:
        try:
            raw = input("  GitHub target URL › ").strip()
        except (EOFError, KeyboardInterrupt):
            # Ctrl+C / Ctrl+D during prompt — exit cleanly
            print("\n  Cancelled.")
            raise SystemExit(0)

        # ── Parse the input ───────────────────────────────────────────────────
        try:
            scope = parse_github_url(raw)
        except ValueError as exc:
            # Malformed input — show error and re-prompt
            print(f"\n  ⚠️   Invalid input: {exc}")
            print("  Please try again.\n")
            continue

        # ── Confirm scope with the operator before validating ─────────────────
        if scope.scope_type == ScopeType.GLOBAL:
            print()
            print("  ℹ️   No target specified — will scan all of GitHub.")
            print("  ⚠️   Global scans may take a long time and return many results.")
            print()
        else:
            print(f"\n  Parsed scope  : {scope.display_label}")
            print(f"  Search filter : {scope.search_qualifier}")
            print()

        # ── Confirm ───────────────────────────────────────────────────────────
        try:
            confirm = input("  Proceed with this target? [Y/n] › ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n  Cancelled.")
            raise SystemExit(0)

        # Default to Yes on empty confirmation (just pressing Enter)
        if confirm in ("", "y", "yes"):
            pass
        elif confirm in ("n", "no"):
            print()
            continue   # re-prompt for a different target
        else:
            print("  Please enter y or n.\n")
            continue

        # ── Validate target exists via HEAD probe (skip for global) ───────────
        if scope.scope_type != ScopeType.GLOBAL:
            print(f"\n  Validating target via HEAD probe…")
            try:
                scope = validate_target(scope)
            except ValueError as exc:
                print(f"\n  ❌  Target validation failed: {exc}")
                print("  Please check the URL and try again.\n")
                continue

            # Print the confirmed scope (may have been updated by org/user probe)
            print(f"  ✅  Target confirmed: {scope.display_label}")
            print(f"  Search qualifier  : {scope.search_qualifier}")
        else:
            # Global scope — mark as verified without a probe
            scope = TargetScope(
                raw_input        = scope.raw_input,
                scope_type       = ScopeType.GLOBAL,
                name             = "",
                search_qualifier = "",
                display_label    = "Global scan (all of GitHub)",
                verified         = True,
            )
            print("  ✅  Global scan confirmed.")

        print()
        return scope
