"""
tests/test_api_client.py
─────────────────────────────────────────────────────────────────────────────
Tests for GitHubClient — rate limiting, backoff, token validation, and
SearchHit construction.

IMPORTANT: Every test in this file uses unittest.mock.patch to intercept
PyGithub calls.  No live network requests are made.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from src.api_client import (
    GitHubClient,
    AuthenticationError,
    RateLimitError,
    SearchError,
)


# ── Helpers: mock factories ───────────────────────────────────────────────────

def _mock_user(login: str = "testuser") -> MagicMock:
    user = MagicMock()
    user.login = login
    user.type  = "User"
    user.created_at    = datetime(2020, 1, 1, tzinfo=timezone.utc)
    user.public_repos  = 10
    user.followers     = 5
    user.following     = 3
    user.bio           = "A test user"
    user.location      = "Seattle, WA"
    return user


def _mock_rate_limit(core_remaining: int = 4999, search_remaining: int = 29) -> MagicMock:
    rl = MagicMock()
    rl.core.remaining   = core_remaining
    rl.core.limit       = 5000
    rl.search.remaining = search_remaining
    rl.search.limit     = 30
    rl.search.reset     = datetime(2099, 1, 1)
    rl.core.reset       = datetime(2099, 1, 1)
    return rl


def _mock_repo(full_name: str = "owner/repo") -> MagicMock:
    repo = MagicMock()
    repo.html_url        = f"https://github.com/{full_name}"
    repo.full_name       = full_name
    repo.description     = "A test repo"
    repo.default_branch  = "main"
    repo.created_at      = datetime(2022, 1, 1, tzinfo=timezone.utc)
    repo.pushed_at       = datetime(2024, 1, 1, tzinfo=timezone.utc)
    repo.language        = "Python"
    repo.stargazers_count= 0
    repo.size            = 100
    repo.owner           = _mock_user("owner")
    repo.get_languages   = MagicMock(return_value={"Python": 5000})
    repo.get_topics      = MagicMock(return_value=[])
    return repo


def _mock_code_item(file_path: str = "id_rsa", repo=None) -> MagicMock:
    item = MagicMock()
    item.path         = file_path
    item.html_url     = f"https://github.com/owner/repo/blob/main/{file_path}"
    item.download_url = f"https://raw.githubusercontent.com/owner/repo/main/{file_path}"
    item.repository   = repo or _mock_repo()
    return item


def _mock_commit(sha: str = "abc123") -> MagicMock:
    commit = MagicMock()
    commit.sha              = sha
    commit.commit.author.name  = "Test Author"
    commit.commit.author.email = "author@example.com"
    commit.commit.author.date  = datetime(2024, 6, 1, tzinfo=timezone.utc)
    return commit


# ── Token validation ──────────────────────────────────────────────────────────

class TestTokenValidation:
    @patch("src.api_client.Github")
    def test_successful_auth(self, MockGithub):
        gh = MockGithub.return_value
        gh.get_user.return_value = _mock_user()
        gh.get_rate_limit.return_value = _mock_rate_limit()
        # Should not raise
        client = GitHubClient(token="ghp_faketoken")
        assert client is not None

    @patch("src.api_client.Github")
    def test_missing_token_raises(self, MockGithub, monkeypatch):
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        with pytest.raises(AuthenticationError, match="GITHUB_TOKEN is not set"):
            GitHubClient(token="")

    @patch("src.api_client.Github")
    def test_invalid_token_raises_auth_error(self, MockGithub):
        from github import GithubException
        gh = MockGithub.return_value
        gh.get_user.return_value = _mock_user()
        # get_user().login raises 401
        user = _mock_user()
        type(user).login = PropertyMock(
            side_effect=GithubException(401, {"message": "Bad credentials"}, None)
        )
        gh.get_user.return_value = user
        with pytest.raises(AuthenticationError):
            GitHubClient(token="ghp_bad")

    @patch("src.api_client.Github")
    def test_health_check_returns_ok(self, MockGithub):
        gh = MockGithub.return_value
        gh.get_user.return_value = _mock_user()
        gh.get_rate_limit.return_value = _mock_rate_limit(
            core_remaining=4500, search_remaining=25
        )
        client = GitHubClient(token="ghp_test")
        result = client.health_check()
        assert result["status"] == "ok"
        assert "core_remaining" in result

    @patch("src.api_client.Github")
    def test_health_check_returns_error_on_exception(self, MockGithub):
        gh = MockGithub.return_value
        gh.get_user.return_value = _mock_user()
        gh.get_rate_limit.side_effect = Exception("Network down")
        client = GitHubClient.__new__(GitHubClient)
        client._gh = gh
        result = client.health_check()
        assert result["status"] == "error"


# ── Rate limiting and backoff ─────────────────────────────────────────────────

class TestRateLimiting:
    @patch("src.api_client.Github")
    @patch("src.api_client.time.sleep")
    def test_exponential_backoff_on_403(self, mock_sleep, MockGithub):
        from github import GithubException
        gh = MockGithub.return_value
        gh.get_user.return_value = _mock_user()
        gh.get_rate_limit.return_value = _mock_rate_limit()

        client = GitHubClient(token="ghp_test")
        # fn always raises 403
        fn = MagicMock(
            side_effect=GithubException(403, {"message": "secondary rate limit"}, None)
        )
        with pytest.raises(RateLimitError):
            client._call_with_backoff(fn)
        # sleep was called at least once (backoff kicked in)
        assert mock_sleep.call_count >= 1

    @patch("src.api_client.Github")
    @patch("src.api_client.time.sleep")
    def test_succeeds_after_one_403(self, mock_sleep, MockGithub):
        from github import GithubException
        gh = MockGithub.return_value
        gh.get_user.return_value = _mock_user()
        gh.get_rate_limit.return_value = _mock_rate_limit()

        client = GitHubClient(token="ghp_test")
        call_count = {"n": 0}

        def flaky_fn():
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise GithubException(403, {}, None)
            return "success"

        result = client._call_with_backoff(flaky_fn)
        assert result == "success"
        assert call_count["n"] == 2

    @patch("src.api_client.Github")
    @patch("src.api_client.time.sleep")
    def test_non_rate_limit_exception_propagates(self, mock_sleep, MockGithub):
        from github import GithubException
        gh = MockGithub.return_value
        gh.get_user.return_value = _mock_user()
        gh.get_rate_limit.return_value = _mock_rate_limit()

        client = GitHubClient(token="ghp_test")
        fn = MagicMock(
            side_effect=GithubException(404, {"message": "not found"}, None)
        )
        with pytest.raises(SearchError):
            client._call_with_backoff(fn)


# ── Code search ───────────────────────────────────────────────────────────────

class TestCodeSearch:
    @patch("src.api_client.Github")
    @patch("src.api_client.time.sleep")
    @patch("src.api_client.requests.get")
    def test_search_yields_search_hits(self, mock_requests, mock_sleep, MockGithub):
        gh = MockGithub.return_value
        gh.get_user.return_value = _mock_user()
        gh.get_rate_limit.return_value = _mock_rate_limit()

        repo = _mock_repo()
        # Simulate owner.get() returning the mock user
        repo.owner.get = MagicMock(return_value=_mock_user("owner"))
        repo.get_commits = MagicMock(return_value=[_mock_commit()])

        item = _mock_code_item(repo=repo)
        gh.search_code = MagicMock(return_value=[item])

        client = GitHubClient(token="ghp_test")
        hits = list(client.search_code('"BEGIN RSA PRIVATE KEY"', max_results=5))
        assert len(hits) == 1
        assert hits[0].repo_name == "owner/repo"
        assert hits[0].file_path == "id_rsa"

    @patch("src.api_client.Github")
    @patch("src.api_client.time.sleep")
    def test_search_respects_max_results(self, mock_sleep, MockGithub):
        gh = MockGithub.return_value
        gh.get_user.return_value = _mock_user()
        gh.get_rate_limit.return_value = _mock_rate_limit()

        repo = _mock_repo()
        repo.owner.get = MagicMock(return_value=_mock_user("owner"))
        repo.get_commits = MagicMock(return_value=[_mock_commit()])

        items = [_mock_code_item(file_path=f"key_{i}.pem", repo=repo) for i in range(20)]
        gh.search_code = MagicMock(return_value=items)

        client = GitHubClient(token="ghp_test")
        hits = list(client.search_code('"BEGIN OPENSSH"', max_results=3))
        assert len(hits) == 3

    @patch("src.api_client.Github")
    @patch("src.api_client.time.sleep")
    def test_bad_item_skipped_gracefully(self, mock_sleep, MockGithub):
        """An item that raises during hydration should be skipped, not crash.

        Note: the new api_client reads repo.owner directly (no .get() call),
        so we trigger hydration failure via a different path — making
        access to repo.full_name raise. This simulates a malformed search
        response where the basic repo metadata is broken.
        """
        gh = MockGithub.return_value
        gh.get_user.return_value = _mock_user()
        gh.get_rate_limit.return_value = _mock_rate_limit()

        # Bad item: accessing .full_name raises during hydration.
        # The new SearchHit constructor reads repo.full_name during __init__,
        # so an exception here propagates and the item gets skipped.
        bad_item = MagicMock()
        bad_repo = MagicMock()
        type(bad_repo).full_name = PropertyMock(side_effect=Exception("API error"))
        bad_item.repository = bad_repo
        bad_item.html_url = "https://github.com/x/y/blob/main/k"

        # Good item: hydrates cleanly
        good_repo = _mock_repo()
        good_repo.get_commits = MagicMock(return_value=[_mock_commit()])
        good_item = _mock_code_item(repo=good_repo)

        gh.search_code = MagicMock(return_value=[bad_item, good_item])

        client = GitHubClient(token="ghp_test")
        hits = list(client.search_code('"BEGIN RSA"', max_results=10))
        # bad item was skipped; good item was returned
        assert len(hits) == 1, f"Expected 1 hit, got {len(hits)}"


# ── File content fetching ─────────────────────────────────────────────────────

class TestFetchFileContent:
    @patch("src.api_client.Github")
    @patch("src.api_client.time.sleep")
    @patch("src.api_client.requests.get")
    def test_returns_text_on_success(self, mock_get, mock_sleep, MockGithub):
        gh = MockGithub.return_value
        gh.get_user.return_value = _mock_user()
        gh.get_rate_limit.return_value = _mock_rate_limit()

        mock_resp = MagicMock()
        mock_resp.text = "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----"
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        client = GitHubClient(token="ghp_test")
        from src.api_client import SearchHit
        hit = MagicMock(spec=SearchHit)
        hit.raw_content_url = "https://raw.githubusercontent.com/o/r/main/id_rsa"

        content = client.fetch_file_content(hit)
        assert "BEGIN RSA PRIVATE KEY" in content

    @patch("src.api_client.Github")
    @patch("src.api_client.time.sleep")
    @patch("src.api_client.requests.get")
    def test_returns_none_on_network_error(self, mock_get, mock_sleep, MockGithub):
        import requests as req_lib
        gh = MockGithub.return_value
        gh.get_user.return_value = _mock_user()
        gh.get_rate_limit.return_value = _mock_rate_limit()

        mock_get.side_effect = req_lib.RequestException("timeout")

        client = GitHubClient(token="ghp_test")
        hit = MagicMock()
        hit.raw_content_url = "https://raw.githubusercontent.com/o/r/main/id_rsa"

        result = client.fetch_file_content(hit)
        assert result is None

    @patch("src.api_client.Github")
    @patch("src.api_client.time.sleep")
    def test_returns_none_when_no_download_url(self, mock_sleep, MockGithub):
        gh = MockGithub.return_value
        gh.get_user.return_value = _mock_user()
        gh.get_rate_limit.return_value = _mock_rate_limit()

        client = GitHubClient(token="ghp_test")
        hit = MagicMock()
        hit.raw_content_url = ""

        result = client.fetch_file_content(hit)
        assert result is None
