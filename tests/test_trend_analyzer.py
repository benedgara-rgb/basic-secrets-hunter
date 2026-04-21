"""
tests/test_trend_analyzer.py
─────────────────────────────────────────────────────────────────────────────
Tests for TrendAnalyzer — account profiling, keyword frequency, language
distribution, temporal heatmaps, and volumetric analysis.

All tests are fully offline.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List

import pytest

from src.api_client import SearchHit
from src.classifier import ClassifiedFinding, Classification
from src.key_detector import DetectedKey
from src.trend_analyzer import TrendAnalyzer


# ── Test-data factories ───────────────────────────────────────────────────────

def _dt(days_ago: int = 0) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days_ago)


def _make_hit(
    repo_name: str = "user/repo",
    file_path: str = "keys.txt",
    owner_login: str = "user",
    owner_created_days_ago: int = 365,
    owner_followers: int = 0,
    owner_public_repos: int = 1,
    repo_language: str = "Python",
    repo_languages: dict | None = None,
    repo_topics: list | None = None,
    repo_pushed_days_ago: int = 10,
    commit_date_days_ago: int = 5,
    commit_author_email: str = "user@example.com",
    repo_description: str | None = None,
    repo_stargazers: int = 0,
    repo_size_kb: int = 10,
    owner_location: str | None = None,
) -> SearchHit:
    return SearchHit(
        repo_url=f"https://github.com/{repo_name}",
        repo_name=repo_name,
        repo_description=repo_description,
        file_path=file_path,
        file_url=f"https://github.com/{repo_name}/blob/main/{file_path}",
        raw_content_url="",
        default_branch="main",
        repo_created_at=_dt(500),
        repo_pushed_at=_dt(repo_pushed_days_ago),
        repo_language=repo_language,
        repo_languages=repo_languages or {repo_language: 1000},
        repo_topics=repo_topics or [],
        repo_stargazers=repo_stargazers,
        repo_size_kb=repo_size_kb,
        owner_login=owner_login,
        owner_type="User",
        owner_created_at=_dt(owner_created_days_ago),
        owner_public_repos=owner_public_repos,
        owner_followers=owner_followers,
        owner_following=0,
        owner_bio=None,
        owner_location=owner_location,
        latest_commit_sha="abc" + repo_name[-3:],
        latest_commit_author_name="Author",
        latest_commit_author_email=commit_author_email,
        latest_commit_date=_dt(commit_date_days_ago),
    )


def _make_finding(
    hit: SearchHit,
    classification: Classification = Classification.LEAKED,
    key_count: int = 1,
) -> ClassifiedFinding:
    keys = [
        DetectedKey(
            secret_id="RSA_PRIVATE_KEY",
            category="private_key",
            label="RSA Private Key",
            sha256_fingerprint="a" * 63 + str(i),
            confidence="high",
            redacted_sample="---",
            is_pem_block=True,
        )
        for i in range(key_count)
    ]
    return ClassifiedFinding(
        hit=hit,
        detected_keys=keys,
        classification=classification,
        confidence_score=0.8 if classification == Classification.LEAKED else 0.1,
        signals=["test signal"],
    )


@pytest.fixture
def analyzer() -> TrendAnalyzer:
    return TrendAnalyzer()


# ── Empty input ───────────────────────────────────────────────────────────────

class TestEmptyInput:
    def test_empty_list_returns_empty_report(self, analyzer):
        report = analyzer.analyse([])
        assert report.total_leaked_findings == 0
        assert report.total_unique_repos == 0
        assert report.top_prolific_accounts == []

    def test_only_accidental_findings_returns_empty_leaked_report(self, analyzer):
        findings = [
            _make_finding(_make_hit(), classification=Classification.ACCIDENTAL)
        ]
        report = analyzer.analyse(findings)
        assert report.total_leaked_findings == 0

    def test_empty_heatmaps_have_all_keys(self, analyzer):
        report = analyzer.analyse([])
        assert set(report.commit_hour_heatmap.keys()) == {
            str(h).zfill(2) for h in range(24)
        }
        assert set(report.commit_dow_heatmap.keys()) == {
            "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"
        }


# ── Account profiling ─────────────────────────────────────────────────────────

class TestAccountProfiling:
    def test_top_accounts_sorted_by_key_count(self, analyzer):
        findings = [
            _make_finding(_make_hit(owner_login="bigdumper", repo_name=f"bigdumper/repo{i}"), key_count=50)
            for i in range(3)
        ] + [
            _make_finding(_make_hit(owner_login="smalldumper", repo_name="smalldumper/r"), key_count=2)
        ]
        report = analyzer.analyse(findings)
        assert report.top_prolific_accounts[0].login == "bigdumper"

    def test_prolific_account_has_correct_repo_count(self, analyzer):
        findings = [
            _make_finding(_make_hit(owner_login="actor", repo_name=f"actor/repo{i}"))
            for i in range(6)
        ]
        report = analyzer.analyse(findings)
        actor_profile = next(p for p in report.top_prolific_accounts if p.login == "actor")
        assert actor_profile.repo_count == 6

    def test_suspected_automation_detected(self, analyzer):
        """Account with many repos, young age, and many keys should be flagged."""
        findings = [
            _make_finding(
                _make_hit(
                    owner_login="botaccount",
                    repo_name=f"botaccount/leak{i}",
                    owner_created_days_ago=15,  # very new account
                ),
                key_count=20,
            )
            for i in range(6)   # 6 repos → triggers AUTO_REPO_MIN
        ]
        report = analyzer.analyse(findings)
        suspected = [p for p in report.suspected_automation_accounts if p.login == "botaccount"]
        assert len(suspected) == 1
        assert suspected[0].is_suspected_automation is True

    def test_old_legitimate_account_not_flagged_automation(self, analyzer):
        findings = [
            _make_finding(
                _make_hit(owner_login="researcher", repo_name="researcher/study", owner_created_days_ago=1000),
                key_count=1,
            )
        ]
        report = analyzer.analyse(findings)
        suspected = [p for p in report.suspected_automation_accounts if p.login == "researcher"]
        assert len(suspected) == 0

    def test_top_accounts_capped_at_10(self, analyzer):
        findings = [
            _make_finding(_make_hit(owner_login=f"user{i}", repo_name=f"user{i}/r"))
            for i in range(20)
        ]
        report = analyzer.analyse(findings)
        assert len(report.top_prolific_accounts) <= 10


# ── Keyword frequency ─────────────────────────────────────────────────────────

class TestKeywordFrequency:
    def test_dump_keyword_counted(self, analyzer):
        findings = [
            _make_finding(_make_hit(repo_name="actor/ssh-dump-logs")),
            _make_finding(_make_hit(repo_name="actor2/dump-collection")),
        ]
        report = analyzer.analyse(findings)
        assert report.repo_keyword_frequency.get("dump", 0) >= 2

    def test_no_keywords_returns_empty(self, analyzer):
        findings = [_make_finding(_make_hit(repo_name="user/normal-project"))]
        report = analyzer.analyse(findings)
        # May be empty or have no taxonomy keywords
        for kw in ["stealer", "dump", "leak", "grabber"]:
            assert report.repo_keyword_frequency.get(kw, 0) == 0

    def test_top_repo_words_returns_list_of_tuples(self, analyzer):
        findings = [_make_finding(_make_hit(repo_name="user/ssh-stealer-tool"))]
        report = analyzer.analyse(findings)
        for item in report.top_repo_name_words:
            assert isinstance(item, tuple)
            assert len(item) == 2


# ── Language distribution ─────────────────────────────────────────────────────

class TestLanguageDistribution:
    def test_percentages_sum_to_100(self, analyzer):
        findings = [
            _make_finding(_make_hit(repo_language="Python")),
            _make_finding(_make_hit(repo_language="Go")),
            _make_finding(_make_hit(repo_language="Python")),
        ]
        report = analyzer.analyse(findings)
        total = sum(report.language_distribution.values())
        assert abs(total - 100.0) < 0.5    # floating-point tolerance

    def test_single_language_is_100_percent(self, analyzer):
        findings = [_make_finding(_make_hit(repo_language="Rust")) for _ in range(5)]
        report = analyzer.analyse(findings)
        assert report.language_distribution.get("Rust", 0) == 100.0


# ── Temporal heatmaps ─────────────────────────────────────────────────────────

class TestTemporalHeatmaps:
    def test_hour_heatmap_has_24_slots(self, analyzer):
        findings = [_make_finding(_make_hit())]
        report = analyzer.analyse(findings)
        assert len(report.commit_hour_heatmap) == 24

    def test_dow_heatmap_has_7_days(self, analyzer):
        findings = [_make_finding(_make_hit())]
        report = analyzer.analyse(findings)
        assert set(report.commit_dow_heatmap.keys()) == {
            "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"
        }

    def test_batch_upload_detected(self, analyzer):
        """Repos committed at the exact same hour should trigger batch detection."""
        same_hour = datetime(2024, 6, 15, 14, 30, 0, tzinfo=timezone.utc)
        findings = []
        for i in range(4):
            hit = _make_hit(repo_name=f"actor/repo{i}")
            hit.latest_commit_date = same_hour
            findings.append(_make_finding(hit))
        report = analyzer.analyse(findings)
        assert report.batch_upload_suspected is True

    def test_no_batch_upload_single_repo(self, analyzer):
        findings = [_make_finding(_make_hit())]
        report = analyzer.analyse(findings)
        assert report.batch_upload_suspected is False


# ── Volumetrics ───────────────────────────────────────────────────────────────

class TestVolumetrics:
    def test_volume_buckets_correct(self, analyzer):
        findings = [
            _make_finding(_make_hit(repo_name="u/r1"), key_count=1),
            _make_finding(_make_hit(repo_name="u/r2"), key_count=5),
            _make_finding(_make_hit(repo_name="u/r3"), key_count=50),
            _make_finding(_make_hit(repo_name="u/r4"), key_count=200),
        ]
        report = analyzer.analyse(findings)
        assert report.key_volume_buckets["1"] == 1
        assert report.key_volume_buckets["2-9"] == 1
        assert report.key_volume_buckets["10-99"] == 1
        assert report.key_volume_buckets["100+"] == 1

    def test_median_keys_single_finding(self, analyzer):
        findings = [_make_finding(_make_hit(), key_count=7)]
        report = analyzer.analyse(findings)
        assert report.median_keys_per_repo == 7.0

    def test_median_keys_multiple(self, analyzer):
        findings = [
            _make_finding(_make_hit(repo_name=f"u/r{i}"), key_count=k)
            for i, k in enumerate([2, 4, 6, 8, 10])
        ]
        report = analyzer.analyse(findings)
        assert report.median_keys_per_repo == 6.0


# ── Freshness ─────────────────────────────────────────────────────────────────

class TestFreshness:
    def test_recent_repo_counted(self, analyzer):
        findings = [_make_finding(_make_hit(repo_pushed_days_ago=5))]
        report = analyzer.analyse(findings)
        assert report.repos_active_last_30_days >= 1

    def test_old_repo_counted_abandoned(self, analyzer):
        findings = [_make_finding(_make_hit(repo_pushed_days_ago=200))]
        report = analyzer.analyse(findings)
        assert report.repos_abandoned >= 1

    def test_recent_not_abandoned(self, analyzer):
        findings = [_make_finding(_make_hit(repo_pushed_days_ago=10))]
        report = analyzer.analyse(findings)
        assert report.repos_abandoned == 0
