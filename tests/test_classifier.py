"""
tests/test_classifier.py
─────────────────────────────────────────────────────────────────────────────
Tests for the LEAKED / ACCIDENTAL / UNCERTAIN classification heuristics.
All tests are offline — no GitHub API calls are made.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from src.api_client import SearchHit
from src.classifier import Classification, KeyClassifier
from src.key_detector import DetectedKey


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fake_key(key_type: str = "RSA") -> DetectedKey:
    """
    Factory for synthetic DetectedSecret instances used throughout
    classifier tests.  Maps the legacy 'key_type' parameter (test ergonomics)
    onto the new secret_id/category/label fields.
    """
    from src.key_detector import Category
    return DetectedKey(
        secret_id=f"{key_type}_PRIVATE_KEY",
        category=Category.PRIVATE_KEY,
        label=f"{key_type} Private Key",
        sha256_fingerprint="a" * 64,
        confidence="high",
        redacted_sample="---",
        is_pem_block=True,
    )


def _make_hit(
    repo_name: str = "alice/my-project",
    file_path: str = "collected/keys.txt",
    owner_login: str = "alice",
    owner_type: str = "User",
    owner_created_at: datetime | None = None,
    owner_public_repos: int = 10,
    owner_followers: int = 5,
    owner_following: int = 5,
    owner_bio: str | None = None,
    owner_location: str | None = None,
    commit_author_name: str = "Alice Smith",
    commit_author_email: str = "alice@example.com",
    repo_topics: list | None = None,
    repo_description: str | None = None,
    repo_language: str = "Python",
) -> SearchHit:
    return SearchHit(
        repo_url=f"https://github.com/{repo_name}",
        repo_name=repo_name,
        repo_description=repo_description,
        file_path=file_path,
        file_url=f"https://github.com/{repo_name}/blob/main/{file_path}",
        raw_content_url=f"https://raw.githubusercontent.com/{repo_name}/main/{file_path}",
        default_branch="main",
        repo_created_at=datetime(2022, 1, 1, tzinfo=timezone.utc),
        repo_pushed_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        repo_language=repo_language,
        repo_languages={"Python": 1000},
        repo_topics=repo_topics or [],
        repo_stargazers=0,
        repo_size_kb=50,
        owner_login=owner_login,
        owner_type=owner_type,
        owner_created_at=owner_created_at,
        owner_public_repos=owner_public_repos,
        owner_followers=owner_followers,
        owner_following=owner_following,
        owner_bio=owner_bio,
        owner_location=owner_location,
        latest_commit_sha="abc123",
        latest_commit_author_name=commit_author_name,
        latest_commit_author_email=commit_author_email,
        latest_commit_date=datetime(2024, 6, 1, tzinfo=timezone.utc),
    )


@pytest.fixture
def clf() -> KeyClassifier:
    return KeyClassifier()


# ── LEAKED signals ────────────────────────────────────────────────────────────

class TestLeakedClassification:
    def test_dump_keyword_in_repo_name(self, clf):
        hit = _make_hit(repo_name="threatactor/ssh-dump-2024")
        result = clf.classify(hit, [_fake_key()])
        assert result.classification == Classification.LEAKED
        assert any("dump" in s for s in result.signals)

    def test_leak_keyword_in_repo_name(self, clf):
        hit = _make_hit(repo_name="badactor/leak-collection")
        result = clf.classify(hit, [_fake_key()])
        assert result.classification == Classification.LEAKED

    def test_stealer_keyword_in_repo_name(self, clf):
        hit = _make_hit(repo_name="xxxxxxxxxxx/stealer-logs")
        result = clf.classify(hit, [_fake_key()])
        assert result.classification == Classification.LEAKED

    def test_bulk_key_count_scored_leaked(self, clf):
        hit = _make_hit()
        keys = [
            DetectedKey(
                secret_id="RSA_PRIVATE_KEY",
                category="private_key",
                label="RSA Private Key",
                sha256_fingerprint="a" * 63 + str(i % 10),
                confidence="high",
                redacted_sample="---",
                is_pem_block=True,
            )
            for i in range(15)
        ]
        result = clf.classify(hit, keys, key_count_in_file=15)
        assert result.classification in (Classification.LEAKED, Classification.UNCERTAIN)

    def test_mass_dump_100_plus(self, clf):
        hit = _make_hit()
        keys = [_fake_key()]
        result = clf.classify(hit, keys, key_count_in_file=150)
        assert result.classification == Classification.LEAKED
        assert any("mass key dump" in s for s in result.signals)

    def test_very_new_account_triggers_signal(self, clf):
        new_account_date = datetime.now(timezone.utc) - timedelta(days=5)
        hit = _make_hit(owner_created_at=new_account_date)
        result = clf.classify(hit, [_fake_key()])
        assert any("days old" in s for s in result.signals)

    def test_non_owner_commit_signals_leaked(self, clf):
        hit = _make_hit(
            repo_name="repoowner/myproject",
            owner_login="repoowner",
            commit_author_name="Someone Else",
            commit_author_email="stranger@dark.io",
        )
        result = clf.classify(hit, [_fake_key()])
        assert any("≠ repo owner" in s for s in result.signals)


# ── ACCIDENTAL signals ────────────────────────────────────────────────────────

class TestAccidentalClassification:
    def test_ssh_directory_single_key(self, clf):
        hit = _make_hit(file_path=".ssh/id_rsa")
        result = clf.classify(hit, [_fake_key()], key_count_in_file=1)
        assert result.classification == Classification.ACCIDENTAL
        assert any(".ssh" in s for s in result.signals)

    def test_test_fixture_key(self, clf):
        hit = _make_hit(file_path="tests/fixtures/id_rsa")
        result = clf.classify(hit, [_fake_key()], key_count_in_file=1)
        assert result.classification in (Classification.ACCIDENTAL, Classification.UNCERTAIN)

    def test_example_directory(self, clf):
        hit = _make_hit(file_path="examples/ssh_key.pem")
        result = clf.classify(hit, [_fake_key()])
        assert result.classification in (Classification.ACCIDENTAL, Classification.UNCERTAIN)

    def test_research_topic_reduces_score(self, clf):
        hit = _make_hit(
            file_path=".ssh/id_ed25519",
            repo_topics=["ctf", "capture-the-flag"],
        )
        result_with_topic = clf.classify(hit, [_fake_key()], key_count_in_file=1)
        hit_no_topic = _make_hit(file_path=".ssh/id_ed25519")
        result_no_topic = clf.classify(hit_no_topic, [_fake_key()], key_count_in_file=1)
        # With research topic, score should be lower (more toward ACCIDENTAL)
        assert result_with_topic.confidence_score <= result_no_topic.confidence_score


# ── Score boundaries ──────────────────────────────────────────────────────────

class TestScoreBoundaries:
    def test_score_between_zero_and_one(self, clf):
        for file_path, repo_name in [
            (".ssh/id_rsa", "alice/personal"),
            ("ssh-dump-logs/keys.txt", "hacker/ssh-dump"),
            ("config/app.pem", "company/service"),
        ]:
            hit = _make_hit(file_path=file_path, repo_name=repo_name)
            result = clf.classify(hit, [_fake_key()])
            assert 0.0 <= result.confidence_score <= 1.0, (
                f"Score {result.confidence_score} out of range for {file_path}"
            )

    def test_signals_list_is_always_list(self, clf):
        hit = _make_hit()
        result = clf.classify(hit, [_fake_key()])
        assert isinstance(result.signals, list)

    def test_classified_finding_fields_populated(self, clf):
        hit = _make_hit()
        result = clf.classify(hit, [_fake_key()])
        assert result.repo_url == hit.repo_url
        assert result.file_path == hit.file_path
        assert result.author_email == hit.latest_commit_author_email
        assert result.key_count == 1


# ── Edge cases ────────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_no_keys_still_classifies(self, clf):
        """Even with an empty key list, classify should not raise."""
        hit = _make_hit()
        result = clf.classify(hit, [], key_count_in_file=0)
        assert result.classification is not None

    def test_none_author_fields_handled(self, clf):
        hit = _make_hit(commit_author_name=None, commit_author_email=None)
        hit.latest_commit_author_name = None
        hit.latest_commit_author_email = None
        result = clf.classify(hit, [_fake_key()])
        assert result is not None

    def test_none_owner_created_at_handled(self, clf):
        hit = _make_hit(owner_created_at=None)
        result = clf.classify(hit, [_fake_key()])
        assert result is not None
