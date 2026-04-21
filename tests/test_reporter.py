"""
tests/test_reporter.py
─────────────────────────────────────────────────────────────────────────────
Tests for Reporter — JSON findings, CSV disclosure targets, and Markdown
trend analysis output.  Uses a temporary directory so no real /app/output
path is needed.
"""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.classifier import ClassifiedFinding, Classification
from src.key_detector import DetectedKey
from src.trend_analyzer import TrendAnalyzer, TrendReport
from src.reporter import Reporter


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_hit_mock(
    repo_name: str = "user/repo",
    file_path: str = "id_rsa",
    owner_login: str = "user",
    email: str = "dev@example.com",
    classification: Classification = Classification.ACCIDENTAL,
):
    """Build a minimal ClassifiedFinding for reporter tests."""
    from src.api_client import SearchHit
    hit = SearchHit(
        repo_url=f"https://github.com/{repo_name}",
        repo_name=repo_name,
        repo_description=None,
        file_path=file_path,
        file_url=f"https://github.com/{repo_name}/blob/main/{file_path}",
        raw_content_url="",
        default_branch="main",
        repo_created_at=datetime(2022, 1, 1, tzinfo=timezone.utc),
        repo_pushed_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        repo_language="Python",
        repo_languages={"Python": 1000},
        repo_topics=[],
        repo_stargazers=0,
        repo_size_kb=50,
        owner_login=owner_login,
        owner_type="User",
        owner_created_at=datetime(2021, 6, 1, tzinfo=timezone.utc),
        owner_public_repos=5,
        owner_followers=2,
        owner_following=2,
        owner_bio=None,
        owner_location="Seattle, WA",
        latest_commit_sha="deadbeef",
        latest_commit_author_name="Dev User",
        latest_commit_author_email=email,
        latest_commit_date=datetime(2024, 3, 1, tzinfo=timezone.utc),
    )
    keys = [DetectedKey(
        secret_id="RSA_PRIVATE_KEY",
        category="private_key",
        label="RSA Private Key",
        sha256_fingerprint="a" * 64,
        confidence="high",
        redacted_sample="---",
        is_pem_block=True,
    )]
    return ClassifiedFinding(
        hit=hit,
        detected_keys=keys,
        classification=classification,
        confidence_score=0.2 if classification == Classification.ACCIDENTAL else 0.9,
        signals=["test signal"],
    )


def _empty_trend_report() -> TrendReport:
    return TrendAnalyzer._empty_report()


@pytest.fixture
def reporter(tmp_path, monkeypatch):
    """Provide a Reporter instance whose output goes to a tmp directory."""
    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))
    import src.reporter as rep_mod
    rep_mod.OUTPUT_DIR = tmp_path
    return Reporter()


# ── Findings JSON ─────────────────────────────────────────────────────────────

class TestFindingsJSON:
    def test_json_file_created(self, reporter, tmp_path):
        findings = [_make_hit_mock()]
        paths = reporter.write_all(findings, _empty_trend_report())
        assert Path(paths["findings_json"]).exists()

    def test_json_contains_metadata(self, reporter, tmp_path):
        findings = [
            _make_hit_mock(classification=Classification.ACCIDENTAL),
            _make_hit_mock(repo_name="actor/dump", classification=Classification.LEAKED),
        ]
        paths = reporter.write_all(findings, _empty_trend_report())
        data = json.loads(Path(paths["findings_json"]).read_text())
        assert "metadata" in data
        assert data["metadata"]["total_findings"] == 2
        assert data["metadata"]["leaked_count"] == 1
        assert data["metadata"]["accidental_count"] == 1

    def test_json_no_key_material(self, reporter, tmp_path):
        """The JSON must NEVER contain PEM private key headers."""
        findings = [_make_hit_mock()]
        paths = reporter.write_all(findings, _empty_trend_report())
        raw = Path(paths["findings_json"]).read_text()
        assert "BEGIN RSA PRIVATE KEY" not in raw
        assert "BEGIN OPENSSH PRIVATE KEY" not in raw
        assert "BEGIN EC PRIVATE KEY" not in raw

    def test_json_contains_sha256_fingerprints(self, reporter):
        findings = [_make_hit_mock()]
        paths = reporter.write_all(findings, _empty_trend_report())
        data = json.loads(Path(paths["findings_json"]).read_text())
        record = data["findings"][0]
        # New schema: each secret has its own fingerprint nested under "secrets"
        assert "secrets" in record
        assert len(record["secrets"]) == 1
        assert "sha256_fingerprint" in record["secrets"][0]
        assert len(record["secrets"][0]["sha256_fingerprint"]) == 64

    def test_json_empty_findings(self, reporter):
        paths = reporter.write_all([], _empty_trend_report())
        data = json.loads(Path(paths["findings_json"]).read_text())
        assert data["findings"] == []
        assert data["metadata"]["total_findings"] == 0

    def test_json_required_fields_present(self, reporter):
        findings = [_make_hit_mock()]
        paths = reporter.write_all(findings, _empty_trend_report())
        data = json.loads(Path(paths["findings_json"]).read_text())
        record = data["findings"][0]
        required = [
            "classification", "repo_url", "file_path", "commit_sha",
            "author_name", "author_email", "commit_date",
        ]
        for field in required:
            assert field in record, f"Missing field: {field}"


# ── Disclosure CSV ────────────────────────────────────────────────────────────

class TestDisclosureCSV:
    def test_csv_file_created(self, reporter):
        findings = [_make_hit_mock(classification=Classification.ACCIDENTAL)]
        paths = reporter.write_all(findings, _empty_trend_report())
        assert Path(paths["disclosure_csv"]).exists()

    def test_csv_contains_accidental_findings(self, reporter):
        findings = [
            _make_hit_mock(email="dev@example.com", classification=Classification.ACCIDENTAL),
        ]
        paths = reporter.write_all(findings, _empty_trend_report())
        with open(paths["disclosure_csv"], newline="") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 1
        assert rows[0]["author_email"] == "dev@example.com"

    def test_csv_excludes_leaked_findings(self, reporter):
        """LEAKED repos are threat actors, not developers to alert."""
        findings = [
            _make_hit_mock(classification=Classification.LEAKED),
        ]
        paths = reporter.write_all(findings, _empty_trend_report())
        with open(paths["disclosure_csv"], newline="") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 0

    def test_csv_excludes_findings_without_email(self, reporter):
        findings = [_make_hit_mock(email="", classification=Classification.ACCIDENTAL)]
        findings[0].hit.latest_commit_author_email = None
        paths = reporter.write_all(findings, _empty_trend_report())
        with open(paths["disclosure_csv"], newline="") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 0

    def test_csv_includes_uncertain_findings(self, reporter):
        findings = [
            _make_hit_mock(email="maybe@example.com", classification=Classification.UNCERTAIN),
        ]
        paths = reporter.write_all(findings, _empty_trend_report())
        with open(paths["disclosure_csv"], newline="") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 1

    def test_csv_no_key_material(self, reporter):
        """CSV must never contain PEM key headers."""
        findings = [_make_hit_mock()]
        paths = reporter.write_all(findings, _empty_trend_report())
        raw = Path(paths["disclosure_csv"]).read_text()
        assert "BEGIN RSA PRIVATE KEY" not in raw

    def test_csv_empty_findings(self, reporter):
        paths = reporter.write_all([], _empty_trend_report())
        with open(paths["disclosure_csv"], newline="") as f:
            rows = list(csv.DictReader(f))
        assert rows == []


# ── Trend Markdown ────────────────────────────────────────────────────────────

class TestTrendMarkdown:
    def test_markdown_file_created(self, reporter):
        paths = reporter.write_all([], _empty_trend_report())
        assert Path(paths["trend_markdown"]).exists()

    def test_markdown_has_title(self, reporter):
        paths = reporter.write_all([], _empty_trend_report())
        content = Path(paths["trend_markdown"]).read_text()
        assert "# CTI SSH Key Hunter" in content

    def test_markdown_has_executive_summary(self, reporter):
        paths = reporter.write_all([], _empty_trend_report())
        content = Path(paths["trend_markdown"]).read_text()
        assert "Executive Summary" in content

    def test_markdown_no_key_material(self, reporter):
        paths = reporter.write_all([], _empty_trend_report())
        content = Path(paths["trend_markdown"]).read_text()
        assert "BEGIN RSA PRIVATE KEY" not in content

    def test_markdown_no_email_addresses_in_trend(self, reporter):
        """
        Email addresses belong only in the disclosure CSV.
        They must NOT appear in the aggregated trend report.
        """
        findings = [
            _make_hit_mock(
                email="sensitive@developer.com",
                classification=Classification.LEAKED,
            )
        ]
        tr = TrendAnalyzer().analyse(findings)
        paths = reporter.write_all(findings, tr)
        md_content = Path(paths["trend_markdown"]).read_text()
        assert "sensitive@developer.com" not in md_content

    def test_markdown_hour_heatmap_present(self, reporter):
        findings = [_make_hit_mock(classification=Classification.LEAKED)]
        tr = TrendAnalyzer().analyse(findings)
        paths = reporter.write_all(findings, tr)
        content = Path(paths["trend_markdown"]).read_text()
        assert "Commits by Hour" in content

    def test_markdown_disclaimer_present(self, reporter):
        paths = reporter.write_all([], _empty_trend_report())
        content = Path(paths["trend_markdown"]).read_text()
        assert "No private key material is stored" in content
