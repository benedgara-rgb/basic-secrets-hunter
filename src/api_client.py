"""
src/api_client.py
═════════════════════════════════════════════════════════════════════════════
GitHub API client for the CTI Secrets Hunter.

This module is the ONLY file in the project that talks to GitHub directly.
Every other module receives already-hydrated SearchHit objects and cannot
make network calls on its own. This design provides four benefits:

  1. Rate-limit enforcement is centralised — a single RateLimitGuard
     instance governs all outbound API traffic, so we cannot accidentally
     exceed GitHub's code-search ceiling of 10 requests/minute even if new
     code paths are added downstream.

  2. Ethical guardrails are centralised — the GitHub User-Agent header, the
     read-only token scope assumption, and the no-content-caching policy
     are all expressed here and nowhere else.

  3. Failure modes are uniform — every API call flows through
     _call_with_backoff(), which handles primary rate limits, secondary
     (abuse-detection) rate limits, and pagination-embedded 404/422
     responses identically. Callers never need to know how GitHub
     communicates rate limits.

  4. Observability is uniform — every API call is timed and logged, so any
     performance problem can be pinpointed by reading a single log stream.

Design principles
─────────────────
  • Read-only: the token is expected to have public_repo scope only.
  • Polite: every API call waits for the rate-limit guard before firing.
  • Defensible: all access is via GitHub's official API, all requests carry
    an identifying User-Agent, and no content is cached to disk.
  • Observable: every call is timed, every wait is logged, every skip
    includes the reason.

For junior security engineers reading this file: the comments on key lines
explain not just *what* the code does but *why* it does it that way, with
attention to the specific GitHub rate-limit semantics that govern
responsible CTI research at scale.
"""

from __future__ import annotations

import logging
import os
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Deque, Generator, List, Optional

import requests
from github import Github, GithubException, RateLimitExceededException
from github.ContentFile import ContentFile
from github.Repository import Repository

logger = logging.getLogger(__name__)


# ═════════════════════════════════════════════════════════════════════════════
# TYPED EXCEPTION HIERARCHY
# ═════════════════════════════════════════════════════════════════════════════
# We expose a typed exception tree so callers can handle different failure
# modes without inspecting error messages. This is defensive programming:
# an upstream change to PyGithub's exception wording won't break our
# downstream error handling.

class GitHubClientError(Exception):
    """Base for all client errors. Callers that want to 'catch everything'
    from this module should catch this class."""


class AuthenticationError(GitHubClientError):
    """The supplied token is invalid, expired, or lacks required scopes.
    This is typically fatal — the scan cannot proceed without auth."""


class RateLimitError(GitHubClientError):
    """We exhausted our retry budget while waiting for rate limits to clear.
    Callers should skip the current query and continue with the next."""


class SearchError(GitHubClientError):
    """A search query failed for reasons unrelated to rate limits —
    usually a bad query string or an upstream GitHub API error."""


# ═════════════════════════════════════════════════════════════════════════════
# DATA CONTAINER
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class SearchHit:
    """
    One fully-hydrated code-search match.

    We capture every piece of metadata downstream modules need so callers
    never need to reach back into PyGithub objects (which would trigger
    additional unguarded API calls).

    Fields marked "Populated lazily" are filled in by fetch_file_content()
    when the caller actually wants the raw bytes. We never cache content.
    """
    # Identification
    repo_url: str
    repo_name: str                         # owner/repo format
    repo_description: Optional[str]
    file_path: str
    file_url: str
    raw_content_url: str
    default_branch: str

    # Repository metadata
    repo_created_at: Optional[datetime]
    repo_pushed_at: Optional[datetime]
    repo_language: Optional[str]
    repo_languages: dict                   # {language_name: byte_count}
    repo_topics: List[str]
    repo_stargazers: int
    repo_size_kb: int

    # Owner metadata (feeds classifier's threat-actor signals)
    owner_login: str
    owner_type: str                        # "User" | "Organization"
    owner_created_at: Optional[datetime]
    owner_public_repos: int
    owner_followers: int
    owner_following: int
    owner_bio: Optional[str]
    owner_location: Optional[str]

    # Populated by _fetch_latest_commit(); best-effort so failures are
    # logged but do not skip the finding entirely.
    latest_commit_sha: Optional[str] = None
    latest_commit_author_name: Optional[str] = None
    latest_commit_author_email: Optional[str] = None
    latest_commit_date: Optional[datetime] = None

    # Intentionally excluded from repr so raw secret content never gets
    # logged by accident when a SearchHit is printed for debugging.
    raw_content: Optional[str] = field(default=None, repr=False)


# ═════════════════════════════════════════════════════════════════════════════
# RATE-LIMIT GUARD
# ═════════════════════════════════════════════════════════════════════════════

class RateLimitGuard:
    """
    A proactive rolling-window rate limiter.

    GitHub enforces separate rate limits for different API buckets:
      • core API      — 5000 requests/hour   (metadata, file content)
      • search API    — 30 requests/minute   (some /search/* endpoints)
      • code_search   — 10 requests/minute   (*this is what we hit*)

    The code_search limit is the tightest and the one that crashes most
    CTI tooling. GitHub imposed this separate bucket because code search
    is enormously expensive on their side (they maintain a full-text
    index over ~billions of files).

    This class guarantees we never exceed a configured (max_requests,
    window_seconds) by tracking the timestamp of every request in a
    rolling window. When we would exceed the limit, we sleep until the
    oldest timestamp falls off the edge of the window.

    Why proactive beats reactive: GitHub's 403-based rate-limit signaling
    is delayed and sometimes escalates to IP-level throttling or account
    suspension. A well-behaved client never relies on the server's error
    response to know it is going too fast.
    """

    def __init__(
        self,
        max_requests: int,
        window_seconds: float,
        name: str = "api",
    ) -> None:
        """
        Args:
            max_requests: Maximum requests allowed within window_seconds.
            window_seconds: Width of the rolling window.
            name: Human-readable identifier for log messages.
        """
        if max_requests < 1:
            raise ValueError("max_requests must be >= 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")

        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.name = name

        # Bounded deque — oldest entries naturally evicted when we're at
        # capacity. Using a deque (not a list) gives O(1) popleft().
        self._timestamps: Deque[float] = deque(maxlen=max_requests * 2)

    def wait_if_needed(self) -> None:
        """
        Block until firing a new API call would NOT exceed the configured
        rate limit. Records the outgoing call's timestamp on return.

        Callers must invoke this immediately before every GitHub API call.
        If they forget, the rate limit can be breached and the entire scan
        may be terminated by GitHub.
        """
        now = time.monotonic()

        # Drop timestamps older than the window — they no longer count
        # against our budget. We use monotonic time (not wall-clock)
        # because system clock changes should not affect rate limiting.
        cutoff = now - self.window_seconds
        while self._timestamps and self._timestamps[0] <= cutoff:
            self._timestamps.popleft()

        # If at capacity, sleep just long enough for the oldest timestamp
        # to fall off the edge of the window.
        if len(self._timestamps) >= self.max_requests:
            oldest = self._timestamps[0]
            # +0.25s buffer to ensure we wake AFTER the window, not right at
            # the boundary where a race with the server clock could lose.
            sleep_for = (oldest + self.window_seconds) - now + 0.25
            if sleep_for > 0:
                logger.info(
                    "[%s guard] throttling: %d req in last %.0fs, "
                    "sleeping %.1fs to stay under %d/%ds cap",
                    self.name, len(self._timestamps), self.window_seconds,
                    sleep_for, self.max_requests, int(self.window_seconds),
                )
                # Sleep in 5-second chunks with heartbeats. A naive
                # time.sleep(30) looks identical to "program hung" to an
                # operator. Heartbeats make it obvious we are still alive.
                slept = 0.0
                while slept < sleep_for:
                    chunk = min(5.0, sleep_for - slept)
                    time.sleep(chunk)
                    slept += chunk
                    if slept < sleep_for:
                        logger.debug(
                            "[%s guard] still sleeping… %.1fs remaining",
                            self.name, sleep_for - slept,
                        )
                # Re-evict expired timestamps post-sleep
                now = time.monotonic()
                cutoff = now - self.window_seconds
                while self._timestamps and self._timestamps[0] <= cutoff:
                    self._timestamps.popleft()

        # Record this outgoing request
        self._timestamps.append(now)
        logger.debug(
            "[%s guard] usage: %d/%d in last %.0fs",
            self.name, len(self._timestamps), self.max_requests,
            self.window_seconds,
        )


# ═════════════════════════════════════════════════════════════════════════════
# GITHUB CLIENT
# ═════════════════════════════════════════════════════════════════════════════

class GitHubClient:
    """
    Read-only wrapper around PyGithub.

    Responsibilities:
      - Validate the token immediately (fail fast on bad credentials)
      - Enforce rate limits proactively via RateLimitGuard
      - Retry transient failures with exponential backoff
      - Yield fully-hydrated SearchHit objects via a generator
      - Expose a health_check() for Docker/Kubernetes liveness probes

    This class is thread-compatible but not thread-safe. Do not share a
    single instance across concurrent threads.
    """

    # ── Retry / backoff tunables ─────────────────────────────────────────────
    MAX_RETRIES: int = 5
    BASE_BACKOFF: float = 1.0          # initial backoff in seconds
    MAX_BACKOFF: float = 120.0         # ceiling on exponential growth

    # ── Polite between-result pause ──────────────────────────────────────────
    # Kept as a belt-and-braces delay on top of the rate-limit guard.
    # Setting this to 0 is unwise — GitHub's abuse detection considers
    # request cadence in addition to absolute rate.
    SEARCH_DELAY: float = float(os.getenv("RATE_LIMIT_PAUSE", "6.5"))

    # ── User-Agent ───────────────────────────────────────────────────────────
    # GitHub's API requires a User-Agent header. Ours identifies the tool,
    # its version, and its research purpose. Transparency in identification
    # is the single strongest operational-security practice for responsible
    # research — it signals good faith to GitHub's abuse team and creates
    # an audit trail if questions arise later.
    USER_AGENT: str = (
        "CTI-Secrets-Hunter/3.0 "
        "(+https://github.com/benedgara-rgb/cti-ssh-hunter; "
        "responsible-disclosure-research)"
    )

    # ── Slow-call warning thresholds ─────────────────────────────────────────
    SLOW_API_CALL_SECONDS: float = 5.0
    SLOW_FETCH_SECONDS: float = 10.0

    def __init__(self, token: Optional[str] = None) -> None:
        """
        Args:
            token: GitHub Personal Access Token with public_repo scope.
                   If None, falls back to the GITHUB_TOKEN env var.

        Raises:
            AuthenticationError: Token missing, invalid, or unauthorized.
        """
        resolved_token = token or os.getenv("GITHUB_TOKEN", "")
        if not resolved_token:
            raise AuthenticationError(
                "GITHUB_TOKEN is not set. "
                "Export it as an env var or add it to your .env file. "
                "Create a token at https://github.com/settings/tokens/new "
                "with the 'public_repo' scope (read-only)."
            )

        # per_page=100 maximises results per API call, minimising the
        # total number of paginated calls needed.
        # retry=3 is PyGithub's built-in retry on network errors (distinct
        # from our rate-limit retries in _call_with_backoff).
        # timeout=30s avoids hanging indefinitely on slow responses.
        self._gh = Github(resolved_token, per_page=100, retry=3, timeout=30)

        # ── Rate-limit guards ────────────────────────────────────────────────
        # Code search bucket: GitHub enforces 10 requests per minute for
        # /search/code specifically (distinct from the general 30/min search
        # bucket). We cap at 8 to leave a 2-call safety margin for PyGithub
        # internal retries and any concurrency we did not anticipate.
        self._search_guard = RateLimitGuard(
            max_requests=8, window_seconds=60, name="code_search"
        )
        # Core API bucket: 5000 requests per hour. We cap at 4500 so a
        # full-day scan cannot exhaust the hourly budget.
        self._core_guard = RateLimitGuard(
            max_requests=4500, window_seconds=3600, name="core"
        )

        # Validate the token immediately. Fail-fast: if auth is broken, we
        # want the operator to see a clean error now, not 20 minutes into
        # a scan that was silently failing.
        self._validate_token()

    # ═════════════════════════════════════════════════════════════════════════
    # TOKEN VALIDATION
    # ═════════════════════════════════════════════════════════════════════════

    def _validate_token(self) -> None:
        """
        Confirm the token authenticates and log the remaining rate budget.

        We hit two endpoints: GET /user (to verify auth) and GET /rate_limit
        (to establish a baseline budget for the upcoming scan). Both are
        core-API calls but small and fast.
        """
        try:
            self._core_guard.wait_if_needed()
            user = self._gh.get_user()
            _ = user.login  # attribute access triggers the actual API call

            self._core_guard.wait_if_needed()
            rate = self._gh.get_rate_limit().core
            logger.info(
                "Authenticated as '%s' | core rate limit: %d/%d remaining",
                user.login, rate.remaining, rate.limit,
            )
        except GithubException as exc:
            if exc.status == 401:
                raise AuthenticationError(
                    "GitHub token rejected (HTTP 401). "
                    "Ensure the token has public_repo read scope and has "
                    "not expired."
                ) from exc
            # Anything else during auth is unexpected — fail loudly.
            raise GitHubClientError(f"Auth probe failed: {exc}") from exc

    # ═════════════════════════════════════════════════════════════════════════
    # RATE-LIMIT WAIT (used when the server tells us to wait, not our guard)
    # ═════════════════════════════════════════════════════════════════════════

    def _wait_for_rate_limit_reset(self, limit_type: str = "search") -> None:
        """
        Block until the server-side rate-limit window resets.

        Called when PyGithub raises RateLimitExceededException. We ask
        GitHub when the limit resets and sleep until then.
        """
        try:
            limits = self._gh.get_rate_limit()
            resource = getattr(limits, limit_type, limits.search)
            reset_utc = resource.reset  # naive datetime in UTC
            now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
            # +2s buffer so we do not wake just before the reset boundary.
            wait = max(0.0, (reset_utc - now_utc).total_seconds()) + 2.0
            logger.warning(
                "Rate limit hit on '%s'. Sleeping %.0fs until reset at %s UTC.",
                limit_type, wait, reset_utc.isoformat(),
            )
            time.sleep(wait)
        except Exception as exc:
            # Fallback — if we cannot read the reset time for any reason,
            # a flat 60-second sleep is a safe default since code_search
            # uses a 60s rolling window.
            logger.warning(
                "Could not read rate-limit reset time (%s); sleeping 60s.", exc,
            )
            time.sleep(60)

    # ═════════════════════════════════════════════════════════════════════════
    # EXPONENTIAL-BACKOFF CALL WRAPPER
    # ═════════════════════════════════════════════════════════════════════════

    def _call_with_backoff(self, fn: Callable, *args, **kwargs):
        """
        Execute fn(*args, **kwargs) with exponential backoff on rate-limit
        responses. Times every call and warns on slow ones.

        This is the single choke point for observability — every API call
        that flows through here is logged, timed, and retry-protected.

        Args:
            fn: The PyGithub method to invoke.
            *args/**kwargs: Forwarded to fn.

        Returns:
            Whatever fn returns on success.

        Raises:
            RateLimitError: We exhausted MAX_RETRIES without success.
            SearchError: Non-rate-limit GitHub API error.
        """
        fn_name = getattr(fn, "__name__", repr(fn))
        delay = self.BASE_BACKOFF

        for attempt in range(1, self.MAX_RETRIES + 1):
            # CRITICAL: define attempt_start_time INSIDE the loop so each
            # retry gets a fresh timestamp. If we defined it before the
            # loop, retry-elapsed-time logging would be cumulative (wrong)
            # and any variable-scoping bugs would surface as NameError on
            # retry paths (which is exactly what broke in an earlier
            # iteration of this codebase).
            attempt_start_time = time.monotonic()
            logger.debug(
                "→ API call: %s (attempt %d/%d)",
                fn_name, attempt, self.MAX_RETRIES,
            )

            try:
                result = fn(*args, **kwargs)
                elapsed = time.monotonic() - attempt_start_time
                # Emit a clearly-visible warning for slow calls so operators
                # can spot "the scan is slow because X takes 8 seconds".
                if elapsed > self.SLOW_API_CALL_SECONDS:
                    logger.warning(
                        "⚠  slow API call: %s took %.2fs", fn_name, elapsed,
                    )
                else:
                    logger.debug(
                        "← API call: %s returned in %.2fs", fn_name, elapsed,
                    )
                return result

            except RateLimitExceededException:
                # Primary rate limit — GitHub explicitly says "you're out
                # of quota." Wait until the window actually resets, which
                # may be up to an hour on the core API.
                logger.warning(
                    "Primary rate limit exceeded on '%s' (attempt %d/%d). "
                    "Waiting for reset…",
                    fn_name, attempt, self.MAX_RETRIES,
                )
                self._wait_for_rate_limit_reset("search")

            except GithubException as exc:
                if exc.status == 403:
                    # Secondary rate limit / abuse detection. The message
                    # is usually "You have triggered an abuse detection
                    # mechanism." Back off exponentially and try again.
                    logger.warning(
                        "Secondary rate limit (403) on '%s' attempt %d. "
                        "Backing off %.0fs.",
                        fn_name, attempt, delay,
                    )
                    time.sleep(min(delay, self.MAX_BACKOFF))
                    delay = min(delay * 2, self.MAX_BACKOFF)
                else:
                    # Any other GitHub error (404, 422, 500, etc.) is not
                    # rate-limit related. Translate to our typed exception
                    # and let the caller decide how to handle it.
                    raise SearchError(
                        f"GitHub API error {exc.status}: {exc.data}"
                    ) from exc

        # Exhausted all retries without success.
        raise RateLimitError(
            f"Exhausted {self.MAX_RETRIES} retries on '{fn_name}' due to "
            f"rate limiting. The scan should pause and retry later."
        )

    # ═════════════════════════════════════════════════════════════════════════
    # CODE SEARCH (public entry point for scanning)
    # ═════════════════════════════════════════════════════════════════════════

    def search_code(
        self,
        query: str,
        max_results: int = 1000,
    ) -> Generator[SearchHit, None, None]:
        """
        Stream SearchHit objects for every match of *query*.

        Uses a Python generator so callers can process results incrementally
        without loading all of them into memory (and so early termination
        via max_results stops the API work immediately).

        All rate limiting is handled internally. Callers can treat this
        like any normal iterator.

        Args:
            query: Raw GitHub code-search query string.
                   Example: '"BEGIN RSA PRIVATE KEY" org:dynatrace'
            max_results: Hard cap on results yielded (GitHub's own
                         ceiling is 1000 regardless).

        Yields:
            SearchHit, one per match, in the order GitHub returned them.
        """
        logger.info("Starting code search: %r (max_results=%d)", query, max_results)
        query_start_time = time.monotonic()

        # Guard the initial code-search call itself.
        self._search_guard.wait_if_needed()
        results = self._call_with_backoff(
            self._gh.search_code, query, highlight=False,
        )

        count = 0
        # ── Manual iteration instead of 'for item in results' ────────────────
        # PyGithub's PaginatedList lazily fetches subsequent pages by calling
        # the code-search API again under the hood. If those page-fetches
        # raise (404 when a scope has no more results, 403 on rate limits,
        # 422 on query validation), we want to translate them to clean
        # terminations instead of letting PyGithub's own exceptions bubble
        # up and kill the scan. This is why we cannot use a simple for-loop.
        iterator = iter(results)
        while True:
            # Rate-limit guard before EVERY next() call. PyGithub may fetch
            # a new page under the hood whenever its internal buffer is
            # drained, and those fetches count against code_search quota.
            self._search_guard.wait_if_needed()

            try:
                item = next(iterator)
            except StopIteration:
                # Normal end of results.
                break
            except RateLimitExceededException:
                # Hit primary rate limit during pagination. Wait for the
                # window to reset, then retry the same iterator — PyGithub
                # will re-issue the page fetch transparently.
                logger.warning(
                    "Rate limit hit during pagination — waiting for reset…"
                )
                self._wait_for_rate_limit_reset("search")
                continue
            except GithubException as exc:
                if exc.status == 404:
                    # "No more results" is signaled this way on empty
                    # scopes. Not an error; just end of data.
                    logger.debug(
                        "Search returned no (more) results for query: %s",
                        query,
                    )
                    break
                if exc.status == 422:
                    # Validation error — usually the query hit a scope
                    # with no searchable files, or query syntax got
                    # rejected. Not fatal; skip this query.
                    logger.debug(
                        "Search query invalid or scope too narrow (422): %s",
                        query,
                    )
                    break
                if exc.status == 403:
                    # Secondary rate limit during pagination. Short back-off
                    # then end this query — we will move to the next one
                    # rather than hammer the same scope.
                    logger.warning(
                        "Secondary rate limit (403) during pagination. "
                        "Backing off 60s and ending query.",
                    )
                    time.sleep(60)
                    break
                # Any other GitHub error: log and end this query.
                logger.error(
                    "Unexpected GitHub error during pagination (%d): %s",
                    exc.status, exc.data,
                )
                break

            # Respect max_results cap AFTER we know we have another item
            if count >= max_results:
                logger.info(
                    "Reached max_results cap (%d); ending iteration.",
                    max_results,
                )
                break

            # Belt-and-braces: a small per-result pause on top of the
            # rate-limit guard. Helps with abuse-detection heuristics
            # that look at request cadence, not just absolute rate.
            time.sleep(self.SEARCH_DELAY)

            # Hydrate the full SearchHit. This makes several core-API
            # calls (owner, languages, topics, commits) — each guarded
            # and logged individually.
            hit_start_time = time.monotonic()
            try:
                hit = self._build_search_hit(item)
                hit_elapsed = time.monotonic() - hit_start_time
                logger.info(
                    "  [%d] hydrated %s/%s in %.2fs (file: %s)",
                    count + 1,
                    getattr(item.repository.owner, "login", "?"),
                    getattr(item.repository, "name", "?"),
                    hit_elapsed,
                    getattr(item, "path", "?"),
                )
                if hit_elapsed > self.SLOW_FETCH_SECONDS:
                    logger.warning(
                        "⚠  slow hydration: %.2fs for %s",
                        hit_elapsed, getattr(item, "html_url", "?"),
                    )
            except Exception as exc:
                # Any hydration error (network glitch, PyGithub bug,
                # malformed upstream data) should not kill the scan.
                # Log the specific URL that failed and skip to the next.
                logger.warning(
                    "Skipping result '%s': %s (%s)",
                    getattr(item, "html_url", "?"), exc, type(exc).__name__,
                )
                continue

            yield hit
            count += 1

        total_elapsed = time.monotonic() - query_start_time
        logger.info(
            "Code search complete. %d result(s) processed in %.1fs.",
            count, total_elapsed,
        )

    # ═════════════════════════════════════════════════════════════════════════
    # SEARCHHIT HYDRATION
    # ═════════════════════════════════════════════════════════════════════════

    def _build_search_hit(self, item: ContentFile) -> SearchHit:
        """
        Build a fully-populated SearchHit from a PyGithub ContentFile.

        Each field is fetched through _call_with_backoff() for uniform
        retry/rate-limit handling, and each fetch is guarded against
        the core-API rate limit.

        Best-effort semantics: languages, topics, and commit metadata
        fetches are wrapped in try/except so one missing field does not
        blackhole an entire finding.
        """
        repo: Repository = item.repository

        # ── Owner ────────────────────────────────────────────────────────
        # repo.owner is returned as a pre-populated NamedUser from the
        # search response. PyGithub lazy-loads extended fields (like
        # created_at and followers) on first access, so we read them
        # directly rather than forcing an explicit .get() call — that
        # call does not exist on the NamedUser API surface.
        owner = repo.owner
        owner_created = getattr(owner, "created_at", None)

        # ── Language breakdown (best-effort, non-fatal on failure) ───────
        self._core_guard.wait_if_needed()
        try:
            languages: dict = self._call_with_backoff(repo.get_languages)
        except Exception as exc:
            logger.debug("get_languages failed for %s: %s", repo.full_name, exc)
            languages = {}

        # ── Topics (best-effort) ─────────────────────────────────────────
        self._core_guard.wait_if_needed()
        try:
            topics: List[str] = self._call_with_backoff(repo.get_topics)
        except Exception as exc:
            logger.debug("get_topics failed for %s: %s", repo.full_name, exc)
            topics = []

        # ── Latest commit on default branch (best-effort) ────────────────
        commit_sha = commit_author_name = commit_author_email = None
        commit_date: Optional[datetime] = None
        try:
            self._core_guard.wait_if_needed()
            commits = self._call_with_backoff(
                repo.get_commits,
                path=item.path,
                sha=repo.default_branch,
            )
            # commits is a PaginatedList — accessing [0] triggers another
            # core-API call, which is why we guard again before the index.
            self._core_guard.wait_if_needed()
            latest = commits[0]
            commit_sha = latest.sha
            if latest.commit.author:
                commit_author_name = latest.commit.author.name
                commit_author_email = latest.commit.author.email
                commit_date = latest.commit.author.date
        except Exception as exc:
            logger.debug(
                "Could not fetch commit metadata for '%s': %s",
                item.path, exc,
            )

        return SearchHit(
            # Identification
            repo_url            = repo.html_url,
            repo_name           = repo.full_name,
            repo_description    = repo.description,
            file_path           = item.path,
            file_url            = item.html_url,
            raw_content_url     = item.download_url or "",
            default_branch      = repo.default_branch or "main",
            # Repository metadata
            repo_created_at     = repo.created_at,
            repo_pushed_at      = repo.pushed_at,
            repo_language       = repo.language,
            repo_languages      = languages,
            repo_topics         = topics,
            repo_stargazers     = repo.stargazers_count,
            repo_size_kb        = repo.size,
            # Owner metadata
            owner_login         = owner.login,
            owner_type          = owner.type,
            owner_created_at    = owner_created,
            owner_public_repos  = owner.public_repos,
            owner_followers     = owner.followers,
            owner_following     = owner.following,
            owner_bio           = owner.bio,
            owner_location      = owner.location,
            # Commit metadata
            latest_commit_sha   = commit_sha,
            latest_commit_author_name  = commit_author_name,
            latest_commit_author_email = commit_author_email,
            latest_commit_date  = commit_date,
        )

    # ═════════════════════════════════════════════════════════════════════════
    # RAW FILE CONTENT FETCHER
    # ═════════════════════════════════════════════════════════════════════════

    def fetch_file_content(self, hit: SearchHit) -> Optional[str]:
        """
        Download raw file content from raw.githubusercontent.com.

        Intentionally does NOT go through PyGithub or the authenticated
        API — raw.githubusercontent.com serves public content anonymously,
        and using it keeps our API rate-limit budget for real search work.

        This function returns the raw file bytes (decoded as text). The
        caller (key_detector) hashes any secret material it finds and
        discards the plaintext immediately — we do not cache, log, or
        persist the content.

        Returns:
            File contents as a string, or None on any failure.
        """
        if not hit.raw_content_url:
            return None

        try:
            fetch_start_time = time.monotonic()
            resp = requests.get(
                hit.raw_content_url,
                headers={"User-Agent": self.USER_AGENT},
                timeout=15,  # short timeout — most files fetch in <1s
            )
            resp.raise_for_status()
            elapsed = time.monotonic() - fetch_start_time
            if elapsed > self.SLOW_FETCH_SECONDS:
                logger.warning(
                    "⚠  slow file fetch: %.2fs for %s",
                    elapsed, hit.raw_content_url,
                )
            return resp.text
        except requests.RequestException as exc:
            # Non-fatal: the scan continues without this file's content.
            logger.debug(
                "Failed to fetch content from '%s': %s",
                hit.raw_content_url, exc,
            )
            return None

    # ═════════════════════════════════════════════════════════════════════════
    # HEALTH CHECK (for Docker HEALTHCHECK and Kubernetes probes)
    # ═════════════════════════════════════════════════════════════════════════

    def health_check(self) -> dict:
        """
        Return a JSON-serialisable dict describing auth health and
        remaining rate-limit budget.

        Used by the /health HTTP endpoint. Must not raise — always
        returns a dict, even on failure.
        """
        try:
            rate = self._gh.get_rate_limit()
            return {
                "status": "ok",
                "core_remaining": rate.core.remaining,
                "core_limit": rate.core.limit,
                "search_remaining": rate.search.remaining,
                "search_limit": rate.search.limit,
            }
        except Exception as exc:
            # Even an unhealthy response must be valid JSON.
            return {"status": "error", "detail": str(exc)}
