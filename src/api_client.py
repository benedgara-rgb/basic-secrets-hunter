"""
api_client.py
─────────────────────────────────────────────────────────────────────────────
GitHub API client with exponential backoff, rate-limit awareness, and
read-only scoping.  All interaction with GitHub flows through this module.

Design principles
  • Never writes to GitHub (read-only token assumed)
  • Respects primary and secondary rate limits
  • Surfaces rich metadata needed by trend_analyzer
  • Raises typed exceptions so callers can react appropriately
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Generator, List, Optional

import requests
from github import Github, GithubException, RateLimitExceededException
from github.ContentFile import ContentFile
from github.Repository import Repository

logger = logging.getLogger(__name__)


# ── Typed exception hierarchy ────────────────────────────────────────────────

class GitHubClientError(Exception):
    """Base exception for all API-client errors."""


class AuthenticationError(GitHubClientError):
    """Raised when the supplied token is invalid or lacks required scope."""


class RateLimitError(GitHubClientError):
    """Raised when we are rate-limited and cannot recover in time."""


class SearchError(GitHubClientError):
    """Raised when a search query fails for non-rate-limit reasons."""


# ── Rate-limit guard ─────────────────────────────────────────────────────────

class RateLimitGuard:
    """
    Rolling-window rate limiter.  Guarantees no more than `max_requests`
    fire in any `window_seconds` interval, regardless of where the calls
    originate (direct search, PyGithub pagination, metadata fetches, etc.).

    Usage:
        guard = RateLimitGuard(max_requests=28, window_seconds=60)
        guard.wait_if_needed()   # blocks until a request would be safe
        # ... make API call ...

    We set the default cap to 28/minute (not the GitHub limit of 30) to
    leave a small safety margin for PyGithub's internal retries.
    """

    def __init__(self, max_requests: int, window_seconds: float,
                 name: str = "api") -> None:
        self.max_requests   = max_requests
        self.window_seconds = window_seconds
        self.name           = name
        self._timestamps: list = []     # ring buffer of recent request times

    def wait_if_needed(self) -> None:
        """
        Block until firing a new request would not exceed the rate limit.
        Logs current usage at DEBUG level for every call, and at INFO
        level when it actually has to sleep.
        """
        now = time.monotonic()

        # Drop timestamps older than the window — they no longer count
        cutoff = now - self.window_seconds
        self._timestamps = [t for t in self._timestamps if t > cutoff]

        # Always log current state at DEBUG so operators can see
        # the guard is being consulted even when no throttle fires
        logger.debug(
            "[%s guard] usage: %d/%d in last %.0fs",
            self.name, len(self._timestamps), self.max_requests,
            self.window_seconds,
        )

        # If we are at capacity, sleep until the oldest entry falls off
        if len(self._timestamps) >= self.max_requests:
            oldest = self._timestamps[0]
            sleep_for = (oldest + self.window_seconds) - now + 0.25   # buffer
            if sleep_for > 0:
                logger.info(
                    "[%s guard] THROTTLING: %d requests in last %.0fs, "
                    "sleeping %.1fs (then resuming)",
                    self.name, len(self._timestamps), self.window_seconds,
                    sleep_for,
                )
                # Heartbeat every 5s during long sleeps so the operator
                # can distinguish "guard sleeping" from "process hung"
                slept = 0.0
                while slept < sleep_for:
                    chunk = min(5.0, sleep_for - slept)
                    time.sleep(chunk)
                    slept += chunk
                    if slept < sleep_for:
                        logger.info(
                            "[%s guard] still sleeping… %.1fs of %.1fs remaining",
                            self.name, sleep_for - slept, sleep_for,
                        )
                logger.info("[%s guard] wake — resuming request", self.name)
                # Re-drop expired entries after sleeping
                now = time.monotonic()
                cutoff = now - self.window_seconds
                self._timestamps = [t for t in self._timestamps if t > cutoff]

        # Record this request
        self._timestamps.append(now)


# ── Data containers ──────────────────────────────────────────────────────────

@dataclass
class SearchHit:
    """
    One raw match returned by the GitHub code-search API.
    All fields needed by downstream modules are captured here so callers
    never need to reach back into the PyGithub objects.
    """
    repo_url: str
    repo_name: str                         # owner/repo
    repo_description: Optional[str]
    file_path: str
    file_url: str
    raw_content_url: str
    default_branch: str
    repo_created_at: Optional[datetime]
    repo_pushed_at: Optional[datetime]
    repo_language: Optional[str]
    repo_languages: dict                   # full language breakdown
    repo_topics: List[str]
    repo_stargazers: int
    repo_size_kb: int
    owner_login: str
    owner_type: str                        # "User" | "Organization"
    owner_created_at: Optional[datetime]
    owner_public_repos: int
    owner_followers: int
    owner_following: int
    owner_bio: Optional[str]
    owner_location: Optional[str]
    # Populated lazily by fetch_file_content()
    raw_content: Optional[str] = field(default=None, repr=False)
    latest_commit_sha: Optional[str] = None
    latest_commit_author_name: Optional[str] = None
    latest_commit_author_email: Optional[str] = None
    latest_commit_date: Optional[datetime] = None


# ── Main client ──────────────────────────────────────────────────────────────

class GitHubClient:
    """
    Thin wrapper around PyGithub that adds:
      - Token validation on construction
      - Exponential backoff on rate limits  (up to MAX_RETRIES attempts)
      - Structured logging at every decision point
      - A generator-based search interface to avoid loading all results at once
    """

    MAX_RETRIES: int = 5           # maximum back-off attempts before giving up
    BASE_BACKOFF: float = 1.0      # seconds; doubles on each retry
    MAX_BACKOFF: float = 120.0     # ceiling on sleep duration

    # GitHub's secondary rate limit kicks in for code search; stay under 10/min
    SEARCH_DELAY: float = float(os.getenv("RATE_LIMIT_PAUSE", "6.5"))

    def __init__(self, token: Optional[str] = None) -> None:
        resolved_token = token or os.getenv("GITHUB_TOKEN", "")
        if not resolved_token:
            raise AuthenticationError(
                "GITHUB_TOKEN is not set.  "
                "Export it or add it to your .env file."
            )
        # Instantiate PyGithub; verify auth immediately
        self._gh = Github(resolved_token, per_page=100, retry=3, timeout=30)
        # Code Search API: GitHub enforces a separate, stricter limit on the
        # /search/code endpoint specifically — 10 requests per minute for
        # authenticated users.  This is distinct from the general /search
        # bucket (30/min) because code search is expensive on GitHub's side.
        # We cap at 8 to leave a 2-call safety margin for PyGithub's internal
        # retries and any concurrency we didn't anticipate.
        self._search_guard = RateLimitGuard(
            max_requests=8, window_seconds=60, name="code_search"
        )
        # Core API: 5000/hour authenticated — we cap at 4500/hour for safety
        self._core_guard = RateLimitGuard(
            max_requests=4500, window_seconds=3600, name="core"
        )
        self._validate_token()

    # ── Token validation ─────────────────────────────────────────────────────

    def _validate_token(self) -> None:
        """Confirm the token authenticates and log remaining rate-limit budget."""
        try:
            user = self._gh.get_user()
            _ = user.login          # triggers the actual API call
            rate = self._gh.get_rate_limit().core
            logger.info(
                "Authenticated as '%s' | core rate limit: %d/%d remaining",
                user.login, rate.remaining, rate.limit,
            )
        except GithubException as exc:
            if exc.status == 401:
                raise AuthenticationError(
                    "GitHub token rejected (HTTP 401).  "
                    "Ensure the token has public_repo read scope."
                ) from exc
            raise GitHubClientError(f"Auth probe failed: {exc}") from exc

    # ── Rate-limit helpers ────────────────────────────────────────────────────

    def _wait_for_rate_limit_reset(self, limit_type: str = "search") -> None:
        """
        Block until the specified rate-limit window resets.
        Adds a small buffer so we don't wake up a fraction of a second early.
        """
        try:
            limits = self._gh.get_rate_limit()
            resource = getattr(limits, limit_type, limits.search)
            reset_utc = resource.reset       # naive datetime in UTC
            now_utc   = datetime.now(timezone.utc).replace(tzinfo=None)
            wait      = max(0.0, (reset_utc - now_utc).total_seconds()) + 2.0
            logger.warning(
                "Rate limit hit on '%s'.  Sleeping %.0fs until reset at %s.",
                limit_type, wait, reset_utc.isoformat(),
            )
            time.sleep(wait)
        except Exception as exc:            # fallback: just sleep 60 s
            logger.warning("Could not read reset time (%s); sleeping 60s.", exc)
            time.sleep(60)

    def _call_with_backoff(self, fn, *args, **kwargs):
        """
        Execute *fn* with exponential back-off on rate-limit responses.
        On non-rate-limit errors the exception propagates immediately.
        """
        delay = self.BASE_BACKOFF
        for attempt in range(1, self.MAX_RETRIES + 1):
            try:
                result = fn(*args, **kwargs)
                elapsed = time.monotonic() - t_start
                # Warn when any single call takes > 5s — likely a slow repo
                # or lazy-loading field fetch
                if elapsed > 5.0:
                    logger.warning(
                        "⚠  SLOW API call: %s took %.2fs", fn_name, elapsed,
                    )
                else:
                    logger.debug(
                        "← API call: %s returned in %.2fs", fn_name, elapsed,
                    )
                return result
            except RateLimitExceededException:
                logger.warning("Rate limit exceeded (attempt %d/%d).", attempt, self.MAX_RETRIES)
                self._wait_for_rate_limit_reset("search")
            except GithubException as exc:
                if exc.status == 403:       # secondary rate limit
                    logger.warning(
                        "Secondary rate limit (403) on attempt %d.  Sleeping %.0fs.",
                        attempt, delay,
                    )
                    time.sleep(min(delay, self.MAX_BACKOFF))
                    delay = min(delay * 2, self.MAX_BACKOFF)
                else:
                    raise SearchError(f"GitHub API error {exc.status}: {exc.data}") from exc
        raise RateLimitError(f"Exhausted {self.MAX_RETRIES} retries due to rate limiting.")

    # ── Core search ──────────────────────────────────────────────────────────

    def search_code(
        self,
        query: str,
        max_results: int = 1000,
    ) -> Generator[SearchHit, None, None]:
        """
        Yield :class:`SearchHit` objects for every code-search result page.

        Applies the per-request delay required to stay under GitHub's
        secondary rate limit (10 code-search requests per minute).

        Parameters
        ----------
        query:
            Raw GitHub code-search query string.
        max_results:
            Hard cap on total results (default 1000 — GitHub's own ceiling).
        """
        logger.info("Starting code search: %r (max_results=%d)", query, max_results)
        # Guard the initial search request itself
        self._search_guard.wait_if_needed()
        results = self._call_with_backoff(
            self._gh.search_code, query, highlight=False
        )

        count = 0
        # Wrap the PaginatedList iterator manually so we can catch
        # GithubException(404) from pagination — which GitHub returns
        # when a code-search scope yields zero results on the next page.
        # PyGithub's PaginatedList bubbles this up as a hard error instead
        # of "end of results", so we translate it here.
        iterator = iter(results)
        while True:
            # Guard BEFORE calling next() — PyGithub fetches a new page
            # whenever its internal buffer is drained, and those page
            # fetches count against the search rate limit.
            self._search_guard.wait_if_needed()
            try:
                item = next(iterator)
            except StopIteration:
                # Normal end of results
                break
            except RateLimitExceededException:
                # Hit GitHub's code-search rate limit mid-pagination.
                # Wait for the window to reset and retry the same iterator.
                logger.warning(
                    "Rate limit hit during pagination — waiting for reset…"
                )
                self._wait_for_rate_limit_reset("search")
                continue   # retry next() on the same iterator
            except GithubException as exc:
                if exc.status == 404:
                    # Empty result set or no more pages — not an error
                    logger.debug(
                        "Search returned no (more) results for query: %s", query
                    )
                    break
                if exc.status == 422:
                    # Validation error — usually means the search scope
                    # is too narrow (e.g. repo with no code-searchable files)
                    logger.debug(
                        "Search query invalid or too narrow (422): %s", query
                    )
                    break
                if exc.status == 403:
                    # Secondary rate limit or abuse detection.  Back off
                    # for a minute and stop iterating this query; move on.
                    logger.warning(
                        "Secondary rate limit (403) during pagination — "
                        "backing off 60s and skipping remainder of query."
                    )
                    time.sleep(60)
                    break
                raise  # re-raise anything else

            if count >= max_results:
                logger.info("Reached max_results cap (%d); stopping.", max_results)
                break

            # Polite delay between every result to respect secondary rate limits
            # Log this so operators can see WHY the scan is pausing
            if self.SEARCH_DELAY >= 2.0:
                logger.debug(
                    "  sleeping %.1fs (SEARCH_DELAY — polite between-result pause)",
                    self.SEARCH_DELAY,
                )
            time.sleep(self.SEARCH_DELAY)

            try:
                t_hit_start = time.monotonic()
                hit = self._build_search_hit(item)
                t_hit = time.monotonic() - t_hit_start
                # Per-result hydration time — expected < 2s, warn if slower
                logger.info(
                    "  [%d] hydrated %s/%s in %.2fs (file: %s)",
                    count + 1,
                    getattr(item.repository.owner, "login", "?"),
                    getattr(item.repository, "name", "?"),
                    t_hit,
                    getattr(item, "path", "?"),
                )
                if t_hit > 10.0:
                    logger.warning(
                        "⚠  slow hydration: %.2fs for %s — investigate",
                        t_hit, getattr(item, "html_url", "?"),
                    )
            except Exception as exc:
                logger.warning("Skipping result '%s': %s",
                               getattr(item, "html_url", "?"), exc)
                continue

            yield hit
            count += 1

        logger.info("Code search complete.  %d results processed.", count)

    # ── SearchHit construction ────────────────────────────────────────────────

    def _build_search_hit(self, item) -> SearchHit:
        """
        Hydrate a SearchHit from a PyGithub ContentFile + its parent repo
        and owner.  Owner metadata is fetched here so trend_analyzer has
        everything it needs without additional API calls.
        """
        repo: Repository = item.repository

        # ── Owner metadata ──────────────────────────────────────────────────
        # repo.owner is already a populated NamedUser object from the search
        # response — no additional fetch needed.  PyGithub lazy-loads the
        # extended fields (created_at, followers, etc.) on first access, so
        # we just read the attributes directly.
        owner = repo.owner
        owner_created: Optional[datetime] = getattr(owner, "created_at", None)

        # ── Language breakdown (core API — rate-limited) ────────────────────
        self._core_guard.wait_if_needed()
        try:
            languages: dict = self._call_with_backoff(repo.get_languages)
        except Exception:
            languages = {}

        # ── Topics (core API — rate-limited) ────────────────────────────────
        self._core_guard.wait_if_needed()
        try:
            topics: List[str] = self._call_with_backoff(repo.get_topics)
        except Exception:
            topics = []

        # ── Latest commit on default branch for this file ────────────────────
        commit_sha = commit_author_name = commit_author_email = None
        commit_date: Optional[datetime] = None
        try:
            self._core_guard.wait_if_needed()
            commits = self._call_with_backoff(
                repo.get_commits, path=item.path, sha=repo.default_branch
            )
            # get_commits returns a PaginatedList — accessing [0] fires a fetch
            self._core_guard.wait_if_needed()
            latest = commits[0]
            commit_sha = latest.sha
            if latest.commit.author:
                commit_author_name  = latest.commit.author.name
                commit_author_email = latest.commit.author.email
                commit_date         = latest.commit.author.date
        except Exception as exc:
            logger.debug("Could not fetch commit for '%s': %s", item.path, exc)

        return SearchHit(
            repo_url            = repo.html_url,
            repo_name           = repo.full_name,
            repo_description    = repo.description,
            file_path           = item.path,
            file_url            = item.html_url,
            raw_content_url     = item.download_url or "",
            default_branch      = repo.default_branch or "main",
            repo_created_at     = repo.created_at,
            repo_pushed_at      = repo.pushed_at,
            repo_language       = repo.language,
            repo_languages      = languages,
            repo_topics         = topics,
            repo_stargazers     = repo.stargazers_count,
            repo_size_kb        = repo.size,
            owner_login         = owner.login,
            owner_type          = owner.type,
            owner_created_at    = owner_created,
            owner_public_repos  = owner.public_repos,
            owner_followers     = owner.followers,
            owner_following     = owner.following,
            owner_bio           = owner.bio,
            owner_location      = owner.location,
            latest_commit_sha   = commit_sha,
            latest_commit_author_name  = commit_author_name,
            latest_commit_author_email = commit_author_email,
            latest_commit_date  = commit_date,
        )

    # ── File content fetcher ─────────────────────────────────────────────────

    def fetch_file_content(self, hit: SearchHit) -> Optional[str]:
        """
        Download raw file content for *hit* via the download_url.
        Returns the plaintext string or None on failure.

        NOTE: The content returned here is passed directly to key_detector,
        which hashes any key material and discards the plaintext.
        This function intentionally does NOT cache or log content.
        """
        if not hit.raw_content_url:
            return None
        try:
            resp = requests.get(
                hit.raw_content_url,
                headers={
                    "User-Agent": "CTI-SSH-Hunter/1.0 (responsible-disclosure-research)"
                },
                timeout=15,
            )
            resp.raise_for_status()
            return resp.text
        except requests.RequestException as exc:
            logger.debug("Failed to fetch content from '%s': %s", hit.raw_content_url, exc)
            return None

    # ── Convenience: verify auth health (used by health endpoint) ────────────

    def health_check(self) -> dict:
        """Return a dict suitable for a JSON health response."""
        try:
            rate = self._gh.get_rate_limit()
            return {
                "status": "ok",
                "core_remaining": rate.core.remaining,
                "search_remaining": rate.search.remaining,
            }
        except Exception as exc:
            return {"status": "error", "detail": str(exc)}
