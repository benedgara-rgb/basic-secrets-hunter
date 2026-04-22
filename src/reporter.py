"""
reporter.py
─────────────────────────────────────────────────────────────────────────────
Generates three output artefacts from a completed scan:

  1. findings_report.json  — Machine-readable full findings (no key material)
  2. disclosure_targets.csv — Responsible-disclosure mailing list (ACCIDENTAL only)
  3. trend_analysis.md     — Human-readable analytical summary (LEAKED only)

PRIVACY NOTE:
  Author email addresses appear ONLY in disclosure_targets.csv.
  The trend analysis and findings JSON use anonymised/aggregated data.
  Raw key material is NEVER written anywhere.
"""

from __future__ import annotations

import csv
import dataclasses
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .classifier import ClassifiedFinding, Classification
from .trend_analyzer import TrendReport, AccountProfile

logger = logging.getLogger(__name__)

OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "/app/output"))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ensure_output_dir() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def _ts() -> str:
    """UTC timestamp slug for filenames."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


class _EnhancedEncoder(json.JSONEncoder):
    """Serialize dataclasses, datetimes, and enums transparently."""
    def default(self, obj: Any) -> Any:
        if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
            return dataclasses.asdict(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        if hasattr(obj, "value"):        # Enum
            return obj.value
        return super().default(obj)


# ── Report builder ────────────────────────────────────────────────────────────

class Reporter:
    """
    Writes scan results to disk in three formats.
    All file paths are logged so operators know where to look.
    """

    def write_all(
        self,
        findings: List[ClassifiedFinding],
        trend_report: TrendReport,
    ) -> Dict[str, str]:
        """
        Write all three report files.

        Returns a dict mapping report type → absolute file path.
        """
        _ensure_output_dir()
        ts = _ts()
        paths: Dict[str, str] = {}

        paths["findings_json"]    = self._write_findings_json(findings, ts)
        paths["disclosure_csv"]   = self._write_disclosure_csv(findings, ts)
        paths["trend_markdown"]   = self._write_trend_markdown(trend_report, ts)

        logger.info("Reports written to %s", OUTPUT_DIR)
        for label, path in paths.items():
            logger.info("  %-20s → %s", label, path)

        return paths

    # ── 1. Findings JSON ──────────────────────────────────────────────────────

    def _write_findings_json(
        self,
        findings: List[ClassifiedFinding],
        ts: str,
    ) -> str:
        path = OUTPUT_DIR / f"findings_{ts}.json"

        records = []
        for f in findings:
            records.append({
                "classification":        f.classification.value,
                "confidence_score":      f.confidence_score,
                "signals":               f.signals,
                "repo_url":              f.repo_url,
                "file_path":             f.file_path,
                "commit_sha":            f.commit_sha,
                "author_name":           f.author_name,
                # Email appears only in this JSON and the disclosure CSV
                "author_email":          f.author_email,
                "commit_date":           f.commit_date,
                "secret_count":          f.key_count,
                # Each detected secret: type, category, confidence, redacted sample
                # SHA-256 fingerprint for dedup — raw value is NEVER stored
                "secrets": [
                    {
                        "secret_id":         k.secret_id,
                        "category":          k.category,
                        "label":             k.label,
                        "confidence":        k.confidence,
                        "redacted_sample":   k.redacted_sample,
                        "sha256_fingerprint":k.sha256_fingerprint,
                    }
                    for k in f.detected_keys
                ],
                "owner_login":           f.hit.owner_login,
                "owner_type":            f.hit.owner_type,
                "repo_language":         f.hit.repo_language,
                "repo_topics":           f.hit.repo_topics,
                "repo_created_at":       (
                    f.hit.repo_created_at.isoformat()
                    if f.hit.repo_created_at else None
                ),
            })

        # Build category breakdown across all secrets in all findings
        cat_counts: dict = {}
        for f in findings:
            for k in f.detected_keys:
                cat_counts[k.category] = cat_counts.get(k.category, 0) + 1

        output = {
            "metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_findings": len(findings),
                "leaked_count": sum(
                    1 for f in findings if f.classification == Classification.LEAKED
                ),
                "accidental_count": sum(
                    1 for f in findings if f.classification == Classification.ACCIDENTAL
                ),
                "uncertain_count": sum(
                    1 for f in findings if f.classification == Classification.UNCERTAIN
                ),
                # Breakdown by secret category so analysts can triage quickly
                "secrets_by_category": cat_counts,
            },
            "findings": records,
        }

        path.write_text(
            json.dumps(output, indent=2, cls=_EnhancedEncoder),
            encoding="utf-8",
        )
        logger.info("Findings JSON: %s (%d records)", path, len(records))
        return str(path)

    # ── 2. Disclosure CSV ─────────────────────────────────────────────────────

    def _write_disclosure_csv(
        self,
        findings: List[ClassifiedFinding],
        ts: str,
    ) -> str:
        """
        Responsible-disclosure target list.
        Contains ACCIDENTAL + UNCERTAIN findings where we have an email address.
        Excludes LEAKED findings — those are threat-actor infrastructure,
        not developers who need a heads-up.
        """
        path = OUTPUT_DIR / f"disclosure_targets_{ts}.csv"

        targets = [
            f for f in findings
            if f.classification in (Classification.ACCIDENTAL, Classification.UNCERTAIN)
            and f.author_email
        ]

        fieldnames = [
            "author_email", "author_name", "repo_url", "file_path",
            "commit_sha", "commit_date", "classification",
            "secret_types", "secret_categories", "secret_count",
            "secret_sha256_fingerprints",
        ]

        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for f in targets:
                writer.writerow({
                    "author_email":                f.author_email,
                    "author_name":                 f.author_name or "",
                    "repo_url":                    f.repo_url,
                    "file_path":                   f.file_path,
                    "commit_sha":                  f.commit_sha or "",
                    "commit_date":                 f.commit_date,
                    "classification":              f.classification.value,
                    "secret_types":                ";".join(k.secret_id for k in f.detected_keys),
                    "secret_categories":           ";".join(sorted({k.category for k in f.detected_keys})),
                    "secret_count":                f.key_count,
                    "secret_sha256_fingerprints":  ";".join(
                        k.sha256_fingerprint for k in f.detected_keys
                    ),
                })

        logger.info(
            "Disclosure CSV: %s (%d actionable targets)", path, len(targets)
        )
        return str(path)

    # ── 3. Trend Analysis Markdown ────────────────────────────────────────────

    def _write_trend_markdown(
        self,
        report: TrendReport,
        ts: str,
    ) -> str:
        path = OUTPUT_DIR / f"trend_analysis_{ts}.md"

        lines: List[str] = []
        a = lines.append   # shorthand

        a("# CTI SSH Key Hunter — Threat Intelligence Trend Report")
        a(f"\n**Generated:** {report.generated_at}")
        a("\n---\n")

        # ── Executive summary ────────────────────────────────────────────
        a("## Executive Summary\n")
        a(f"| Metric | Value |")
        a(f"|--------|-------|")
        a(f"| Total LEAKED findings | {report.total_leaked_findings} |")
        a(f"| Unique repositories   | {report.total_unique_repos} |")
        a(f"| Unique accounts       | {report.total_unique_accounts} |")
        a(f"| Total keys observed   | {report.total_keys_observed} |")
        a(f"| Median keys per repo  | {report.median_keys_per_repo} |")
        a(f"| Mean sophistication   | {report.mean_sophistication_score}/10 |")
        a(f"| Batch upload suspected| {'Yes ⚠️' if report.batch_upload_suspected else 'No'} |")
        a(f"| Repos w/ stealer artifacts | {report.repos_with_stealer_artifacts} |")
        a("")

        # ── Temporal freshness ────────────────────────────────────────────
        a("## Infrastructure Freshness\n")
        a(f"| Period | Active Repos |")
        a(f"|--------|-------------|")
        a(f"| Last 30 days  | {report.repos_active_last_30_days} |")
        a(f"| Last 90 days  | {report.repos_active_last_90_days} |")
        a(f"| Abandoned (>180d) | {report.repos_abandoned} |")
        a("")

        # ── Top prolific accounts ─────────────────────────────────────────
        a("## Top 10 Most Prolific Accounts\n")
        if report.top_prolific_accounts:
            a("| Account | Repos | Keys | Age | Suspected Automation |")
            a("|---------|-------|------|-----|---------------------|")
            for p in report.top_prolific_accounts:
                auto = "🤖 Yes" if p.is_suspected_automation else "No"
                a(f"| `{p.login}` | {p.repo_count} | {p.total_keys} "
                  f"| {p.age_label} | {auto} |")
        else:
            a("_No data._")
        a("")

        # ── Suspected automation ──────────────────────────────────────────
        if report.suspected_automation_accounts:
            a("## Suspected Automated Stealer Infrastructure\n")
            a("> Accounts meeting ≥2 of: ≥5 leak repos, account age ≤90d, "
              "≥50 total keys\n")
            for p in report.suspected_automation_accounts:
                a(f"### `{p.login}`")
                for sig in p.automation_signals:
                    a(f"- {sig}")
                a("")

        # ── Repo naming patterns ──────────────────────────────────────────
        a("## Repository Naming Patterns\n")
        a("### Taxonomy Keyword Frequency\n")
        if report.repo_keyword_frequency:
            a("| Keyword | Count |")
            a("|---------|-------|")
            for kw, cnt in sorted(
                report.repo_keyword_frequency.items(), key=lambda x: -x[1]
            ):
                a(f"| `{kw}` | {cnt} |")
        else:
            a("_No taxonomy keywords detected._")
        a("")

        a("### Top 20 Repo Name Tokens\n")
        if report.top_repo_name_words:
            a("| Token | Count |")
            a("|-------|-------|")
            for token, cnt in report.top_repo_name_words:
                a(f"| `{token}` | {cnt} |")
        a("")

        # ── Language distribution ─────────────────────────────────────────
        a("## Language Distribution\n")
        a("_Higher-sophistication languages (Go, C/C++, Rust) indicate "
          "more capable threat actors._\n")
        if report.language_distribution:
            a("| Language | Share |")
            a("|----------|-------|")
            for lang, pct in report.language_distribution.items():
                a(f"| {lang} | {pct}% |")
        a("")

        a("## Sophistication Score Distribution\n")
        a("| Tier | Repo Count |")
        a("|------|-----------|")
        for tier, cnt in report.sophistication_distribution.items():
            a(f"| {tier} | {cnt} |")
        a("")

        # ── Temporal heatmap ──────────────────────────────────────────────
        a("## Temporal Commit Patterns\n")
        if report.batch_upload_suspected:
            a("⚠️ **Batch upload activity detected** — multiple repos committed "
              "within the same hour, consistent with automated stealer infrastructure.\n")
            for ev in report.batch_upload_evidence:
                a(f"- {ev}")
            a("")

        a("### Commits by Hour of Day (UTC)\n")
        a("```")
        for h, cnt in sorted(report.commit_hour_heatmap.items()):
            bar = "█" * min(cnt, 40)
            a(f"  {h}:00  {bar} {cnt}")
        a("```\n")

        a("### Commits by Day of Week\n")
        a("```")
        for dow, cnt in report.commit_dow_heatmap.items():
            bar = "█" * min(cnt, 40)
            a(f"  {dow}  {bar} {cnt}")
        a("```\n")

        # ── Key volume ────────────────────────────────────────────────────
        a("## Key Volume per Repository\n")
        a("| Bucket | Repos | Interpretation |")
        a("|--------|-------|----------------|")
        interp = {
            "1":     "Likely accidental single commit",
            "2-9":   "Small batch or multiple accidental",
            "10-99": "Probable stealer log fragment",
            "100+":  "Stealer infrastructure / mass dump",
        }
        for bucket, cnt in report.key_volume_buckets.items():
            a(f"| {bucket} keys | {cnt} | {interp.get(bucket, '')} |")
        a("")

        # ── Stealer artifacts ─────────────────────────────────────────────
        if report.stealer_artifact_frequency:
            a("## Co-located Stealer Artifacts\n")
            a("> Files commonly found alongside stolen SSH keys in credential "
              "stealer log dumps.\n")
            a("| Artifact | Occurrences |")
            a("|----------|-------------|")
            for art, cnt in report.stealer_artifact_frequency.items():
                a(f"| `{art}` | {cnt} |")
            a("")

        a("---")
        a("*This report was generated by CTI SSH Key Hunter. "
          "No private key material is stored in this file.*")

        path.write_text("\n".join(lines), encoding="utf-8")
        logger.info("Trend analysis Markdown: %s", path)
        return str(path)
