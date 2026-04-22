"""
main.py
─────────────────────────────────────────────────────────────────────────────
CLI entry point and orchestration layer.

Usage
─────
  # Prompted target entry (interactive — recommended)
  python -m src.main

  # Pass a GitHub URL directly on the command line
  python -m src.main --target https://github.com/dynatrace
  python -m src.main --target https://github.com/dynatrace/dynatrace-operator
  python -m src.main --target dynatrace

  # Limit key types or result count
  python -m src.main --target dynatrace --key-types OPENSSH RSA --max-results 200

  # Global scan (all of GitHub — use with care)
  python -m src.main --target ""

  # Launch health endpoint only (useful in Docker healthcheck)
  python -m src.main --health-only

Environment variables (or .env file)
─────────────────────────────────────
  GITHUB_TOKEN      Required.  Public-repo read-only PAT.
  LOG_LEVEL         Optional.  DEBUG | INFO | WARNING  (default: INFO)
  OUTPUT_DIR        Optional.  Report output directory  (default: /app/output)
  RATE_LIMIT_PAUSE  Optional.  Seconds between search results (default: 6.5)

Signal handling
───────────────
  SIGTERM / SIGINT  Flush any buffered findings to disk before exiting.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
from pathlib import Path
from typing import Dict, List, Optional

# Load .env before any other imports that might read env vars
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass   # dotenv is optional; env vars may be injected by Docker / CI

from .api_client import GitHubClient, AuthenticationError, GitHubClientError
from .key_detector import KeyDetector
from .classifier import KeyClassifier, ClassifiedFinding
from .trend_analyzer import TrendAnalyzer
from .reporter import Reporter
from .target_resolver import (
    TargetScope,
    ScopeType,
    parse_github_url,
    prompt_for_target,
    validate_target,
)

# ── Logging setup ─────────────────────────────────────────────────────────────

def _configure_logging(level: str = "INFO") -> None:
    numeric = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric,
        format="%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
        stream=sys.stderr,
    )
    # Quieten noisy third-party loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("github").setLevel(logging.WARNING)


logger = logging.getLogger(__name__)


# ── Search query builder ──────────────────────────────────────────────────────
#
# The catalogue is sourced from KeyDetector so adding a new secret type to
# key_detector.py automatically makes it searchable — no changes needed here.

def _build_queries(
    secret_ids: List[str],
    scope: Optional[TargetScope] = None,
) -> List[str]:
    """
    Return deduplicated GitHub code-search query strings for the requested
    secret IDs, optionally scoped to a specific org / user / repo.

    Pass ["ALL"] to build queries for every known secret type.
    Duplicate queries (when multiple secret IDs share a search string) are
    merged automatically to avoid redundant API calls.
    """
    catalogue: Dict[str, str] = KeyDetector.all_search_queries()
    qualifier = (scope.search_qualifier if scope else "").strip()

    # Expand sentinel "ALL" to the full catalogue
    if len(secret_ids) == 1 and secret_ids[0].upper() == "ALL":
        secret_ids = list(catalogue.keys())

    seen_queries: set = set()   # deduplicate identical search strings
    queries: List[str] = []

    for sid in secret_ids:
        base_query = catalogue.get(sid.upper())
        if not base_query:
            logger.warning("Unknown secret ID '%s' — skipping.", sid)
            continue
        # Append org/user/repo scope qualifier when one is provided
        full_query = f"{base_query} {qualifier}".strip() if qualifier else base_query
        if full_query in seen_queries:
            logger.debug("Skipping duplicate query: %s", full_query)
            continue
        seen_queries.add(full_query)
        queries.append(full_query)
        logger.debug("Query [%s]: %s", sid, full_query)

    logger.info(
        "Built %d search queries | scope=%s",
        len(queries),
        scope.search_qualifier if scope else "global",
    )
    return queries


# ── Graceful shutdown helpers ─────────────────────────────────────────────────

class _ScanState:
    """Shared mutable state so signal handlers can flush in-progress findings."""
    def __init__(self) -> None:
        self.findings: List[ClassifiedFinding] = []
        self.shutdown_requested = threading.Event()


_STATE = _ScanState()


def _handle_signal(signum, _frame) -> None:
    sig_name = signal.Signals(signum).name
    logger.warning(
        "Received %s — flushing %d findings and exiting gracefully.",
        sig_name, len(_STATE.findings),
    )
    _STATE.shutdown_requested.set()


# ── Health endpoint (lightweight Flask route) ─────────────────────────────────

def _start_health_server(client: GitHubClient, port: int = 8080) -> None:
    """
    Spin up a minimal HTTP server returning the GitHub auth health status.
    Used by Docker HEALTHCHECK and Kubernetes liveness probes.
    Runs in a daemon thread so it doesn't block the main scan.
    """
    import json
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path == "/health":
                data = client.health_check()
                body = json.dumps(data).encode()
                status = 200 if data.get("status") == "ok" else 503
            else:
                body = b'{"error": "not found"}'
                status = 404
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args) -> None:  # silence default access log
            pass

    server = HTTPServer(("0.0.0.0", port), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    logger.info("Health endpoint listening on http://0.0.0.0:%d/health", port)


# ── Main orchestration ────────────────────────────────────────────────────────

def run_scan(args: argparse.Namespace) -> int:
    """
    Execute the full scan pipeline.
    Returns an OS exit code: 0 = success, 1 = error.
    """
    # Register signal handlers so Ctrl+C / SIGTERM flushes findings to disk
    # rather than losing in-progress work mid-scan.
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT,  _handle_signal)

    # ── Initialise components ──────────────────────────────────────────────
    try:
        client = GitHubClient()
    except AuthenticationError as exc:
        logger.error("Authentication failed: %s", exc)
        return 1

    # Optionally start the /health HTTP endpoint (always on in Docker mode)
    if args.enable_health or os.getenv("ENABLE_HEALTH_ENDPOINT", "").lower() == "true":
        _start_health_server(client, port=int(os.getenv("HEALTH_PORT", "8080")))

    if args.health_only:
        logger.info("--health-only flag set; skipping scan.")
        import time; time.sleep(9999)   # keep health server alive indefinitely
        return 0

    # ── List available secret types and exit ───────────────────────────────
    if getattr(args, "list_secrets", False):
        catalogue = KeyDetector.all_search_queries()
        from .key_detector import _SECRET_DEFS, Category
        cats: Dict[str, list] = {}
        for d in _SECRET_DEFS:
            cats.setdefault(d["category"], []).append(d)
        print("\n  Available Secret Type IDs")
        print("  " + "─" * 52)
        cat_labels = {
            Category.PRIVATE_KEY: "Private Keys",
            Category.CLOUD:       "Cloud Credentials",
            Category.API_KEY:     "API Keys / SaaS",
            Category.VCS_TOKEN:   "VCS / Registry Tokens",
            Category.OAUTH_TOKEN: "OAuth / JWT",
            Category.DATABASE:    "Database Credentials",
        }
        for cat, label in cat_labels.items():
            defs = cats.get(cat, [])
            if not defs:
                continue
            print(f"\n  [{label}]")
            for d in defs:
                conf_icon = "🟢" if d["confidence"]=="high" else ("🟡" if d["confidence"]=="medium" else "🔴")
                print(f"    {conf_icon} {d['id']:<35} {d['label']}")
        print()
        print("  Confidence: 🟢 high  🟡 medium  🔴 low")
        print("  Usage: python -m src.main --secrets AWS_ACCESS_KEY_ID GITHUB_PAT")
        print()
        return 0

    # ── Resolve scan target ────────────────────────────────────────────────
    # Determine WHAT we are scanning — a specific org/user/repo or all of GitHub.
    # --target on the CLI skips the interactive prompt; omitting it triggers
    # the prompt so the operator can paste a URL directly.
    scope: Optional[TargetScope] = None

    if args.target is not None:
        # Target supplied on command line — parse and validate without prompting
        try:
            scope = parse_github_url(args.target)
            if scope.scope_type != ScopeType.GLOBAL:
                # HEAD-validate before spending API quota on a bad target
                scope = validate_target(scope)
                logger.info("Target confirmed: %s", scope.display_label)
            else:
                scope.verified = True
        except ValueError as exc:
            logger.error("Invalid target: %s", exc)
            return 1
    else:
        # No --target flag — show the interactive URL prompt
        # This is the primary UX path when running the tool manually
        try:
            scope = prompt_for_target()
        except SystemExit:
            return 0   # operator cancelled at the prompt — clean exit

    # ── Print scan banner ──────────────────────────────────────────────────
    # Show a clear summary of what is about to be scanned before the first
    # API call so the operator can abort if the scope is wrong.
    print()
    print("┌─────────────────────────────────────────────────────────────┐")
    print("│               CTI SSH Key Hunter — Scan Starting            │")
    print("├─────────────────────────────────────────────────────────────┤")
    print(f"│  Target   : {scope.display_label:<49}│")
    print(f"│  Qualifier: {(scope.search_qualifier or 'none (global)'):<49}│")
    ids_display = ", ".join(args.secret_ids[:4])
    if len(args.secret_ids) > 4: ids_display += f" +{len(args.secret_ids)-4} more"
    print(f"│  Secrets  : {ids_display:<49}│")
    print(f"│  Max/query: {args.max_results:<49}│")
    print("└─────────────────────────────────────────────────────────────┘")
    print()

    detector    = KeyDetector()
    classifier  = KeyClassifier()
    analyzer    = TrendAnalyzer()
    reporter    = Reporter()

    # Build search queries, injecting the scope qualifier into each one
    queries = _build_queries(args.secret_ids, scope=scope)
    if not queries:
        logger.error("No valid key types specified.  Use --key-types OPENSSH RSA EC DSA")
        return 1

    logger.info(
        "Starting scan | target=%s | secrets=%s | max_results=%d",
        scope.search_qualifier or "global",
        args.secret_ids,
        args.max_results,
    )

    # ── Search → detect → classify pipeline ───────────────────────────────
    # Global set of SHA-256 fingerprints seen so far — prevents the same
    # physical key from being counted twice across different files/repos.
    seen_hashes: set = set()

    for query in queries:
        if _STATE.shutdown_requested.is_set():
            break

        logger.info("Query: %s", query)

        try:
            for hit in client.search_code(query, max_results=args.max_results):
                if _STATE.shutdown_requested.is_set():
                    logger.info("Shutdown requested — stopping search iteration.")
                    break

                # Fetch raw file content; content is discarded after key detection
                content = client.fetch_file_content(hit)
                if content is None:
                    logger.debug("No content for %s — skipping.", hit.file_url)
                    continue

                # Detect keys — plaintext is hashed immediately and discarded
                detected = detector.scan(content)
                key_count_raw = detector.estimate_key_count_in_file(content)

                if not detected:
                    logger.debug("No keys detected in %s — skipping.", hit.file_path)
                    continue

                # Deduplicate by SHA-256 fingerprint across all files in this run
                new_keys = [
                    k for k in detected
                    if k.sha256_fingerprint not in seen_hashes
                ]
                if not new_keys and args.skip_duplicates:
                    logger.debug("All keys in %s already seen — skipping.", hit.file_path)
                    continue
                for k in new_keys:
                    seen_hashes.add(k.sha256_fingerprint)

                # Classify the finding: LEAKED | ACCIDENTAL | UNCERTAIN
                finding = classifier.classify(hit, new_keys or detected, key_count_raw)

                _STATE.findings.append(finding)
                logger.info(
                    "[%s %.2f] %s | %d key(s) | %s",
                    finding.classification.value,
                    finding.confidence_score,
                    hit.repo_name,
                    finding.key_count,
                    hit.file_path,
                )

        except GitHubClientError as exc:
            logger.error("Search failed for query '%s': %s", query, exc)
            # Continue to the next query rather than aborting the entire run
            continue

    logger.info(
        "Scan complete.  %d findings collected (%d unique key hashes).",
        len(_STATE.findings), len(seen_hashes),
    )

    if not _STATE.findings:
        logger.warning("No findings to report.")
        return 0

    # ── Trend analysis ─────────────────────────────────────────────────────
    trend_report = analyzer.analyse(_STATE.findings)

    # ── Write reports ──────────────────────────────────────────────────────
    report_paths = reporter.write_all(_STATE.findings, trend_report)

    # Human-readable summary to stdout — useful in CI/CD pipelines too
    print("\n─────────────────────────────────────────────")
    print("  CTI SSH Hunter — Scan Complete")
    print(f"  Target: {scope.display_label}")
    print("─────────────────────────────────────────────")
    for label, path in report_paths.items():
        print(f"  {label:<22} → {path}")
    print(f"\n  Total findings       : {len(_STATE.findings)}")
    from .classifier import Classification
    print(f"  LEAKED               : "
          f"{sum(1 for f in _STATE.findings if f.classification == Classification.LEAKED)}")
    print(f"  ACCIDENTAL           : "
          f"{sum(1 for f in _STATE.findings if f.classification == Classification.ACCIDENTAL)}")
    print(f"  UNCERTAIN            : "
          f"{sum(1 for f in _STATE.findings if f.classification == Classification.UNCERTAIN)}")
    print(f"  Unique key hashes    : {len(seen_hashes)}")
    print("─────────────────────────────────────────────\n")

    return 0


# ── CLI argument parsing ──────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cti-ssh-hunter",
        description=(
            "CTI SSH Key Hunter — ethical GitHub intelligence tool for locating "
            "exposed SSH private keys and generating responsible-disclosure targets."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Interactive URL prompt (recommended for manual use)
  python -m src.main

  # Scope to a specific GitHub organisation
  python -m src.main --target https://github.com/dynatrace

  # Scope to a single repository
  python -m src.main --target https://github.com/dynatrace/dynatrace-operator

  # Bare name works too (no URL needed)
  python -m src.main --target dynatrace

  # Specific key types only
  python -m src.main --target dynatrace --key-types OPENSSH RSA --max-results 200

  # Global scan (no scoping — use with care)
  python -m src.main --target ""

  # Debug mode
  python -m src.main --target dynatrace --log-level DEBUG
        """,
    )
    # ── Target scope ──────────────────────────────────────────────────────────
    parser.add_argument(
        "--target",
        default=None,    # None = show interactive prompt; "" = global scan
        metavar="URL",
        help=(
            "GitHub URL, org name, or repo to scope the scan.  "
            "Accepts full URLs (https://github.com/dynatrace), bare org/user names "
            "(dynatrace), or owner/repo pairs (dynatrace/dynatrace-operator).  "
            "Omit to be prompted interactively.  Pass an empty string for a global scan."
        ),
    )
    # ── Scan behaviour ────────────────────────────────────────────────────────
    parser.add_argument(
        "--secrets",
        dest="secret_ids",
        nargs="+",
        default=["ALL"],
        metavar="ID",
        help=(
            "Secret type IDs to search for. Default: ALL (every known type). "
            "Use 'ALL' or specify IDs like: AWS_ACCESS_KEY_ID GITHUB_PAT "
            "STRIPE_SECRET_KEY OPENSSH_PRIVATE_KEY RSA_PRIVATE_KEY "
            "GCP_API_KEY SLACK_TOKEN JWT_TOKEN DATABASE_URL "
            "(run --list-secrets to see all available IDs)"
        ),
    )
    parser.add_argument(
        "--list-secrets",
        action="store_true",
        default=False,
        help="Print all available secret type IDs and exit",
    )
    parser.add_argument(
        "--max-results",
        type=int,
        default=int(os.getenv("MAX_RESULTS", "1000")),
        metavar="N",
        help="Max results per query (GitHub ceiling: 1000)",
    )
    parser.add_argument(
        "--log-level",
        default=os.getenv("LOG_LEVEL", "INFO"),
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )
    parser.add_argument(
        "--no-dedup",
        dest="skip_duplicates",
        action="store_false",
        default=True,
        help="Disable cross-file deduplication by SHA256 fingerprint",
    )
    # ── Infrastructure ────────────────────────────────────────────────────────
    parser.add_argument(
        "--enable-health",
        action="store_true",
        default=False,
        help="Start HTTP /health endpoint on port 8080",
    )
    parser.add_argument(
        "--health-only",
        action="store_true",
        default=False,
        help="Start health endpoint only, do not run scan",
    )
    return parser


def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()
    _configure_logging(args.log_level)
    sys.exit(run_scan(args))


if __name__ == "__main__":
    main()
