"""
tests/test_target_resolver.py
─────────────────────────────────────────────────────────────────────────────
Tests for target_resolver — URL parsing, HEAD validation, org/user
disambiguation, and the interactive prompt.

All network calls are mocked via unittest.mock.patch.
No live requests are made to GitHub.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch, call
import pytest

from src.target_resolver import (
    parse_github_url,
    validate_target,
    ScopeType,
    TargetScope,
)


# ════════════════════════════════════════════════════════════════════════════
# parse_github_url — offline, no network calls needed
# ════════════════════════════════════════════════════════════════════════════

class TestParseGitHubUrl:
    """URL parsing is pure logic — no mocks required."""

    # ── Full HTTPS URLs ───────────────────────────────────────────────────────

    def test_full_url_org(self):
        scope = parse_github_url("https://github.com/dynatrace")
        assert scope.scope_type == ScopeType.ORG
        assert scope.name == "dynatrace"
        assert scope.search_qualifier == "org:dynatrace"

    def test_full_url_org_with_trailing_slash(self):
        scope = parse_github_url("https://github.com/dynatrace/")
        assert scope.scope_type == ScopeType.ORG
        assert scope.name == "dynatrace"

    def test_full_url_repo(self):
        scope = parse_github_url("https://github.com/dynatrace/dynatrace-operator")
        assert scope.scope_type == ScopeType.REPO
        assert scope.name == "dynatrace/dynatrace-operator"
        assert scope.search_qualifier == "repo:dynatrace/dynatrace-operator"

    def test_full_url_repo_with_extra_path_segments(self):
        """URLs with /tree/main or /blob/... should resolve to repo scope."""
        scope = parse_github_url(
            "https://github.com/dynatrace/dynatrace-operator/tree/main/src"
        )
        assert scope.scope_type == ScopeType.REPO
        assert scope.name == "dynatrace/dynatrace-operator"

    def test_full_url_repo_blob_path(self):
        scope = parse_github_url(
            "https://github.com/microsoft/vscode/blob/main/README.md"
        )
        assert scope.scope_type == ScopeType.REPO
        assert scope.name == "microsoft/vscode"

    # ── No-scheme inputs ─────────────────────────────────────────────────────

    def test_no_scheme_org(self):
        """github.com/dynatrace without https:// should still parse."""
        scope = parse_github_url("github.com/dynatrace")
        assert scope.scope_type == ScopeType.ORG
        assert scope.name == "dynatrace"

    def test_no_scheme_repo(self):
        scope = parse_github_url("github.com/dynatrace/dynatrace-operator")
        assert scope.scope_type == ScopeType.REPO
        assert scope.name == "dynatrace/dynatrace-operator"

    # ── Bare names (no domain) ────────────────────────────────────────────────

    def test_bare_org_name(self):
        """Plain 'dynatrace' should resolve to ORG scope (tentative)."""
        scope = parse_github_url("dynatrace")
        assert scope.scope_type == ScopeType.ORG
        assert scope.name == "dynatrace"
        assert scope.search_qualifier == "org:dynatrace"

    def test_bare_owner_repo(self):
        """Plain 'dynatrace/dynatrace-operator' should resolve to REPO scope."""
        scope = parse_github_url("dynatrace/dynatrace-operator")
        assert scope.scope_type == ScopeType.REPO
        assert scope.name == "dynatrace/dynatrace-operator"
        assert scope.search_qualifier == "repo:dynatrace/dynatrace-operator"

    def test_bare_name_with_hyphens(self):
        scope = parse_github_url("some-company-name")
        assert scope.scope_type == ScopeType.ORG
        assert scope.name == "some-company-name"

    def test_bare_name_with_dots_rejected(self):
        """
        A bare string with dots (e.g. 'some.org.name') is ambiguous — it
        could be a hostname.  parse_github_url routes dotted strings
        through URL parsing, which rejects non-github.com hostnames.
        Users with dotted org names should pass the full URL:
          https://github.com/some.org.name
        """
        with pytest.raises(ValueError, match="Unsupported host"):
            parse_github_url("some.org.name")

    def test_org_with_dots_via_full_url(self):
        """Org names with dots work when the full github.com URL is given."""
        scope = parse_github_url("https://github.com/some.org.name")
        assert scope.scope_type == ScopeType.ORG
        assert scope.name == "some.org.name"

    # ── Empty / global ────────────────────────────────────────────────────────

    def test_empty_string_global(self):
        scope = parse_github_url("")
        assert scope.scope_type == ScopeType.GLOBAL
        assert scope.search_qualifier == ""

    def test_whitespace_only_global(self):
        scope = parse_github_url("   ")
        assert scope.scope_type == ScopeType.GLOBAL

    def test_github_root_url_global(self):
        scope = parse_github_url("https://github.com/")
        assert scope.scope_type == ScopeType.GLOBAL

    def test_github_root_no_path_global(self):
        scope = parse_github_url("https://github.com")
        assert scope.scope_type == ScopeType.GLOBAL

    # ── Search qualifier correctness ──────────────────────────────────────────

    def test_org_qualifier_format(self):
        scope = parse_github_url("microsoft")
        assert scope.search_qualifier == "org:microsoft"

    def test_repo_qualifier_format(self):
        scope = parse_github_url("microsoft/vscode")
        assert scope.search_qualifier == "repo:microsoft/vscode"

    def test_display_label_org(self):
        scope = parse_github_url("dynatrace")
        assert "dynatrace" in scope.display_label

    def test_display_label_repo(self):
        scope = parse_github_url("dynatrace/dynatrace-operator")
        assert "dynatrace/dynatrace-operator" in scope.display_label

    def test_raw_input_preserved(self):
        raw = "https://github.com/dynatrace"
        scope = parse_github_url(raw)
        assert scope.raw_input == raw

    # ── Error cases ───────────────────────────────────────────────────────────

    def test_non_github_host_raises(self):
        with pytest.raises(ValueError, match="Unsupported host"):
            parse_github_url("https://gitlab.com/someorg")

    def test_non_github_host_bitbucket_raises(self):
        with pytest.raises(ValueError, match="Unsupported host"):
            parse_github_url("https://bitbucket.org/someorg")

    # ── Case sensitivity ──────────────────────────────────────────────────────

    def test_uppercase_github_host_accepted(self):
        """Host matching should be case-insensitive — full URL with uppercase host."""
        scope = parse_github_url("https://GITHUB.COM/dynatrace")
        assert scope.scope_type == ScopeType.ORG

    def test_org_name_case_preserved(self):
        """Org/repo names are case-preserved (GitHub is case-insensitive
        but we preserve the user's input for the qualifier string)."""
        scope = parse_github_url("https://github.com/Dynatrace")
        assert scope.name == "Dynatrace"


# ════════════════════════════════════════════════════════════════════════════
# _build_queries integration — verify qualifier is appended correctly
# ════════════════════════════════════════════════════════════════════════════

class TestBuildQueries:
    """Test that _build_queries in main.py correctly appends the qualifier."""

    def _get_build_queries(self):
        """
        Import _build_queries with the GitHub stub on the path so the
        src.api_client import inside main.py resolves without a live install.
        """
        import sys, os
        stub_path = os.path.join(os.path.dirname(__file__), "..", "stubs")
        stub_path = os.path.normpath(stub_path)
        if stub_path not in sys.path:
            sys.path.insert(0, stub_path)
        from src.main import _build_queries
        return _build_queries

    def test_org_scope_appended_to_queries(self):
        _build_queries = self._get_build_queries()
        scope = parse_github_url("dynatrace")
        queries = _build_queries(["RSA", "OPENSSH"], scope=scope)
        assert all("org:dynatrace" in q for q in queries)

    def test_repo_scope_appended_to_queries(self):
        _build_queries = self._get_build_queries()
        scope = parse_github_url("dynatrace/dynatrace-operator")
        queries = _build_queries(["RSA"], scope=scope)
        assert queries[0] == '"BEGIN RSA PRIVATE KEY" repo:dynatrace/dynatrace-operator'

    def test_global_scope_no_qualifier(self):
        _build_queries = self._get_build_queries()
        scope = parse_github_url("")
        queries = _build_queries(["RSA"], scope=scope)
        assert queries[0] == '"BEGIN RSA PRIVATE KEY"'
        assert "org:" not in queries[0]
        assert "user:" not in queries[0]
        assert "repo:" not in queries[0]

    def test_none_scope_no_qualifier(self):
        """No scope (None) behaves identically to global."""
        _build_queries = self._get_build_queries()
        queries = _build_queries(["EC"], scope=None)
        assert queries[0] == '"BEGIN EC PRIVATE KEY"'

    def test_all_key_types_get_qualifier(self):
        _build_queries = self._get_build_queries()
        scope = parse_github_url("microsoft")
        queries = _build_queries(["OPENSSH", "RSA", "EC", "DSA", "PKCS8"], scope=scope)
        assert len(queries) == 5
        assert all("org:microsoft" in q for q in queries)

    def test_unknown_key_type_skipped(self):
        _build_queries = self._get_build_queries()
        queries = _build_queries(["RSA", "INVALID_TYPE"], scope=None)
        assert len(queries) == 1
        assert '"BEGIN RSA PRIVATE KEY"' in queries[0]


# ════════════════════════════════════════════════════════════════════════════
# validate_target — all network calls mocked
# ════════════════════════════════════════════════════════════════════════════

class TestValidateTarget:

    def _mock_200_response(self, final_url: str = "https://github.com/dynatrace") -> MagicMock:
        """Build a mock requests.Response for a successful HEAD probe."""
        resp = MagicMock()
        resp.status_code = 200
        resp.url = final_url
        return resp

    def _mock_404_response(self) -> MagicMock:
        resp = MagicMock()
        resp.status_code = 404
        resp.url = ""
        return resp

    def _mock_org_api_200(self, name: str = "dynatrace") -> MagicMock:
        """Mock a successful GET /orgs/{name} response."""
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "login": name,
            "name": name.capitalize(),
            "public_repos": 42,
        }
        return resp

    def _mock_user_api_200(self, name: str = "octocat") -> MagicMock:
        """Mock a successful GET /users/{name} response."""
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "login": name,
            "name": "The Octocat",
            "public_repos": 8,
        }
        return resp

    # ── Global scope — no network call ───────────────────────────────────────

    def test_global_scope_verified_without_probe(self):
        scope = parse_github_url("")
        result = validate_target(scope)
        assert result.verified is True
        assert result.scope_type == ScopeType.GLOBAL

    # ── Org confirmed ─────────────────────────────────────────────────────────

    @patch("src.target_resolver.requests.get")
    @patch("src.target_resolver.requests.head")
    @patch("src.target_resolver.time.sleep")
    def test_org_scope_confirmed(self, mock_sleep, mock_head, mock_get):
        """HEAD returns 200, org API returns 200 → LEAKED as ORG scope."""
        mock_head.return_value = self._mock_200_response()
        mock_get.return_value  = self._mock_org_api_200("dynatrace")

        scope  = parse_github_url("dynatrace")
        result = validate_target(scope)

        assert result.verified is True
        assert result.scope_type == ScopeType.ORG
        assert result.search_qualifier == "org:dynatrace"

    @patch("src.target_resolver.requests.get")
    @patch("src.target_resolver.requests.head")
    @patch("src.target_resolver.time.sleep")
    def test_org_display_label_contains_repo_count(self, mock_sleep, mock_head, mock_get):
        mock_head.return_value = self._mock_200_response()
        mock_get.return_value  = self._mock_org_api_200("dynatrace")

        scope  = parse_github_url("dynatrace")
        result = validate_target(scope)
        assert "42" in result.display_label    # public_repos count

    # ── User confirmed ────────────────────────────────────────────────────────

    @patch("src.target_resolver.requests.get")
    @patch("src.target_resolver.requests.head")
    @patch("src.target_resolver.time.sleep")
    def test_user_scope_confirmed(self, mock_sleep, mock_head, mock_get):
        """Org API returns 404, user API returns 200 → resolved as USER scope."""
        mock_head.return_value = self._mock_200_response(
            "https://github.com/octocat"
        )
        # First GET → org API → 404
        # Second GET → user API → 200
        org_404  = MagicMock(status_code=404)
        user_200 = self._mock_user_api_200("octocat")
        mock_get.side_effect = [org_404, user_200]

        scope  = parse_github_url("octocat")
        result = validate_target(scope)

        assert result.verified is True
        assert result.scope_type == ScopeType.USER
        assert result.search_qualifier == "user:octocat"

    @patch("src.target_resolver.requests.get")
    @patch("src.target_resolver.requests.head")
    @patch("src.target_resolver.time.sleep")
    def test_user_qualifier_format(self, mock_sleep, mock_head, mock_get):
        mock_head.return_value = self._mock_200_response()
        org_404  = MagicMock(status_code=404)
        user_200 = self._mock_user_api_200("johndoe")
        mock_get.side_effect = [org_404, user_200]

        scope  = parse_github_url("johndoe")
        result = validate_target(scope)
        assert result.search_qualifier == "user:johndoe"

    # ── Repo confirmed ────────────────────────────────────────────────────────

    @patch("src.target_resolver.requests.get")
    @patch("src.target_resolver.requests.head")
    @patch("src.target_resolver.time.sleep")
    def test_repo_scope_confirmed(self, mock_sleep, mock_head, mock_get):
        """REPO scope — HEAD returns 200, no org/user disambiguation needed."""
        mock_head.return_value = self._mock_200_response(
            "https://github.com/dynatrace/dynatrace-operator"
        )

        scope  = parse_github_url("dynatrace/dynatrace-operator")
        result = validate_target(scope)

        assert result.verified is True
        assert result.scope_type == ScopeType.REPO
        assert result.search_qualifier == "repo:dynatrace/dynatrace-operator"

    # ── Error cases ───────────────────────────────────────────────────────────

    @patch("src.target_resolver.requests.head")
    @patch("src.target_resolver.time.sleep")
    def test_404_raises_value_error(self, mock_sleep, mock_head):
        mock_head.return_value = self._mock_404_response()
        scope = parse_github_url("this-org-does-not-exist-xyz987")
        with pytest.raises(ValueError, match="not found"):
            validate_target(scope)

    @patch("src.target_resolver.requests.head")
    @patch("src.target_resolver.time.sleep")
    def test_429_raises_value_error(self, mock_sleep, mock_head):
        resp = MagicMock(status_code=429)
        mock_head.return_value = resp
        scope = parse_github_url("dynatrace")
        with pytest.raises(ValueError, match="rate-limited"):
            validate_target(scope)

    @patch("src.target_resolver.requests.head")
    @patch("src.target_resolver.time.sleep")
    def test_connection_error_raises_value_error(self, mock_sleep, mock_head):
        import requests as req
        mock_head.side_effect = req.exceptions.ConnectionError("no route to host")
        scope = parse_github_url("dynatrace")
        with pytest.raises(ValueError, match="connect"):
            validate_target(scope)

    @patch("src.target_resolver.requests.head")
    @patch("src.target_resolver.time.sleep")
    def test_timeout_raises_value_error(self, mock_sleep, mock_head):
        import requests as req
        mock_head.side_effect = req.exceptions.Timeout("timed out")
        scope = parse_github_url("dynatrace")
        with pytest.raises(ValueError, match="timed out"):
            validate_target(scope)

    # ── HEAD request properties ───────────────────────────────────────────────

    @patch("src.target_resolver.requests.get")
    @patch("src.target_resolver.requests.head")
    @patch("src.target_resolver.time.sleep")
    def test_head_called_before_get(self, mock_sleep, mock_head, mock_get):
        """HEAD probe must fire BEFORE any GET call — cheaper, faster."""
        mock_head.return_value = self._mock_200_response()
        mock_get.return_value  = self._mock_org_api_200()

        scope = parse_github_url("dynatrace")
        validate_target(scope)

        # HEAD should have been called exactly once
        assert mock_head.call_count == 1
        # The HEAD call should target the github.com web URL, not the API
        head_url = mock_head.call_args[0][0]
        assert "github.com/dynatrace" in head_url
        assert "api.github.com" not in head_url

    @patch("src.target_resolver.requests.get")
    @patch("src.target_resolver.requests.head")
    @patch("src.target_resolver.time.sleep")
    def test_user_agent_header_present_on_head(self, mock_sleep, mock_head, mock_get):
        """Every outbound request must carry the researcher User-Agent."""
        mock_head.return_value = self._mock_200_response()
        mock_get.return_value  = self._mock_org_api_200()

        scope = parse_github_url("dynatrace")
        validate_target(scope)

        head_kwargs = mock_head.call_args[1]
        ua = head_kwargs.get("headers", {}).get("User-Agent", "")
        assert "CTI-Researcher" in ua

    @patch("src.target_resolver.requests.get")
    @patch("src.target_resolver.requests.head")
    @patch("src.target_resolver.time.sleep")
    def test_polite_delay_called_after_head(self, mock_sleep, mock_head, mock_get):
        """time.sleep() must be called after every network request."""
        mock_head.return_value = self._mock_200_response()
        mock_get.return_value  = self._mock_org_api_200()

        scope = parse_github_url("dynatrace")
        validate_target(scope)

        # At minimum one sleep call after the HEAD probe
        assert mock_sleep.call_count >= 1

    @patch("src.target_resolver.requests.get")
    @patch("src.target_resolver.requests.head")
    @patch("src.target_resolver.time.sleep")
    def test_redirects_followed_on_head(self, mock_sleep, mock_head, mock_get):
        """allow_redirects=True must be set — GitHub redirects http→https."""
        mock_head.return_value = self._mock_200_response()
        mock_get.return_value  = self._mock_org_api_200()

        scope = parse_github_url("dynatrace")
        validate_target(scope)

        head_kwargs = mock_head.call_args[1]
        assert head_kwargs.get("allow_redirects") is True

    @patch("src.target_resolver.requests.get")
    @patch("src.target_resolver.requests.head")
    @patch("src.target_resolver.time.sleep")
    def test_301_redirect_treated_as_valid(self, mock_sleep, mock_head, mock_get):
        """HTTP 301 from HEAD is a valid response — target exists."""
        resp_301 = MagicMock(status_code=301, url="https://github.com/dynatrace")
        mock_head.return_value = resp_301
        mock_get.return_value  = self._mock_org_api_200()

        scope  = parse_github_url("dynatrace")
        result = validate_target(scope)
        assert result.verified is True
