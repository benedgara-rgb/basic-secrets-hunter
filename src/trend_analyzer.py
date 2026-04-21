"""
trend_analyzer.py
─────────────────────────────────────────────────────────────────────────────
Threat intelligence enrichment and trend analysis for LEAKED findings.

Answers the following CTI questions:
  1. Account patterns  — Are uploaders throwaway bots or persistent actors?
  2. Naming patterns   — What keywords dominate repo names?  (stealer taxonomy)
  3. Language mix      — How sophisticated is the surrounding code?
  4. Temporal patterns — Are keys dumped in batches? (automation fingerprint)
  5. Volumetrics       — Key counts per repo vs. account age (stealer vs one-off)
  6. Sophistication    — Project structure, README presence, code indicators
  7. Malware artifacts — co-located credential files suggesting stealer logs

All analysis is performed entirely in-memory on the ClassifiedFindings list;
no additional API calls are made here.
"""

from __future__ import annotations

import logging
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .classifier import ClassifiedFinding, Classification

logger = logging.getLogger(__name__)


# ── Constants / word lists ────────────────────────────────────────────────────

# Keywords whose presence in a repo name gives us taxonomy signal
_REPO_TAXONOMY_KEYWORDS: List[str] = [
    "stealer", "grabber", "logs", "dump", "leak", "combo", "collection",
    "credentials", "creds", "hacked", "breach", "database", "loot",
    "harvest", "exfil", "stolen", "keylogger", "rat", "botnet",
    "infostealer", "malware", "panel", "bot", "c2",
]

# Files co-located with SSH keys in stealer logs
_STEALER_ARTIFACT_NAMES: List[str] = [
    "passwords.txt", "passwords.csv", "logins.txt",
    "cookies.txt", "cookies.json", "autofill.txt",
    "credit_cards.txt", "cc.txt",
    "metamask", "exodus", "electrum",       # crypto wallet artifacts
    "discord_tokens", "telegram_session",
    "system_info.txt", "userinfo.txt",
    "screenshot.png", "screen.jpg",
]

# Languages scored by relative attacker sophistication
_LANGUAGE_SOPHISTICATION: Dict[str, int] = {
    "C":          5, "C++": 5, "Rust": 5,
    "Go":         4,
    "Python":     3, "Ruby": 3, "PowerShell": 3,
    "JavaScript": 2, "PHP": 2, "Perl": 2,
    "Batch":      1, "Shell": 1,
    "HTML":       0, "Text": 0,
}

# Account age bands (days) mapped to suspicion labels
_ACCOUNT_AGE_BANDS: List[Tuple[int, str]] = [
    (7,   "< 1 week  (almost certainly throwaway)"),
    (30,  "< 1 month (very suspicious)"),
    (90,  "< 3 months (suspicious)"),
    (365, "< 1 year  (moderate)"),
    (9999,"≥ 1 year  (established)"),
]


# ── Result containers ─────────────────────────────────────────────────────────

@dataclass
class AccountProfile:
    login: str
    repo_count: int
    total_keys: int
    account_age_days: Optional[int]
    age_label: str
    followers: int
    public_repos: int
    locations: List[str]
    is_suspected_automation: bool
    automation_signals: List[str]


@dataclass
class TrendReport:
    """
    Complete analytical summary report produced by TrendAnalyzer.
    This is serialised to JSON/Markdown by reporter.py.
    """
    generated_at: str
    total_leaked_findings: int
    total_unique_repos: int
    total_unique_accounts: int
    total_keys_observed: int

    # Tier-1: account patterns
    top_prolific_accounts: List[AccountProfile]         # top 10 by key count
    suspected_automation_accounts: List[AccountProfile] # auto-stealer infra

    # Tier-2: repo naming
    repo_keyword_frequency: Dict[str, int]              # word → count
    top_repo_name_words: List[Tuple[str, int]]          # top 20 words

    # Tier-3: language distribution
    language_distribution: Dict[str, float]             # lang → % of repos
    sophistication_distribution: Dict[str, int]         # low/med/high counts
    mean_sophistication_score: float

    # Tier-4: temporal patterns
    commit_hour_heatmap: Dict[str, int]                 # "00"–"23" → count
    commit_dow_heatmap: Dict[str, int]                  # "Mon"–"Sun" → count
    batch_upload_suspected: bool
    batch_upload_evidence: List[str]

    # Tier-5: volumetrics
    key_volume_buckets: Dict[str, int]                  # "1","2-9","10-99","100+"
    median_keys_per_repo: float
    repos_with_stealer_artifacts: int
    stealer_artifact_frequency: Dict[str, int]

    # Tier-6: freshness
    repos_active_last_30_days: int
    repos_active_last_90_days: int
    repos_abandoned: int                                # no push > 180 days


# ── Analyzer ─────────────────────────────────────────────────────────────────

class TrendAnalyzer:
    """
    Consumes a list of :class:`ClassifiedFinding` objects and produces a
    :class:`TrendReport` covering account, code, temporal, and volumetric
    trends within the LEAKED subset.
    """

    # Thresholds for "suspected automated stealer infrastructure"
    AUTO_REPO_MIN: int   = 5     # ≥ N leak repos from one account
    AUTO_AGE_MAX:  int   = 90    # account age ≤ N days
    AUTO_KEYS_MIN: int   = 50    # total keys across all repos

    def analyse(self, findings: List[ClassifiedFinding]) -> TrendReport:
        """
        Main entry point.  Returns a complete :class:`TrendReport`.
        Only LEAKED findings are included in the analysis; ACCIDENTAL findings
        are excluded to keep threat-actor profiling clean.
        """
        leaked = [f for f in findings if f.classification == Classification.LEAKED]
        logger.info(
            "TrendAnalyzer: %d total findings, %d classified LEAKED",
            len(findings), len(leaked),
        )

        if not leaked:
            return self._empty_report()

        return TrendReport(
            generated_at                  = datetime.now(timezone.utc).isoformat(),
            total_leaked_findings         = len(leaked),
            total_unique_repos            = len({f.repo_url for f in leaked}),
            total_unique_accounts         = len({f.hit.owner_login for f in leaked}),
            total_keys_observed           = sum(f.key_count for f in leaked),
            top_prolific_accounts         = self._top_accounts(leaked),
            suspected_automation_accounts = self._automation_suspects(leaked),
            repo_keyword_frequency        = self._repo_keyword_freq(leaked),
            top_repo_name_words           = self._top_repo_words(leaked),
            language_distribution         = self._language_dist(leaked),
            sophistication_distribution   = self._sophistication_dist(leaked),
            mean_sophistication_score     = self._mean_sophist(leaked),
            commit_hour_heatmap           = self._hour_heatmap(leaked),
            commit_dow_heatmap            = self._dow_heatmap(leaked),
            batch_upload_suspected        = self._batch_suspected(leaked),
            batch_upload_evidence         = self._batch_evidence(leaked),
            key_volume_buckets            = self._volume_buckets(leaked),
            median_keys_per_repo          = self._median_keys(leaked),
            repos_with_stealer_artifacts  = self._stealer_artifact_count(leaked),
            stealer_artifact_frequency    = self._stealer_artifact_freq(leaked),
            repos_active_last_30_days     = self._recency_count(leaked, 30),
            repos_active_last_90_days     = self._recency_count(leaked, 90),
            repos_abandoned               = self._abandoned_count(leaked),
        )

    # ── Account analysis ─────────────────────────────────────────────────────

    def _build_account_map(
        self, leaked: List[ClassifiedFinding]
    ) -> Dict[str, AccountProfile]:
        """Group findings by owner and build an AccountProfile per owner."""
        groups: Dict[str, List[ClassifiedFinding]] = defaultdict(list)
        for f in leaked:
            groups[f.hit.owner_login].append(f)

        profiles: Dict[str, AccountProfile] = {}
        for login, group in groups.items():
            hit = group[0].hit
            total_keys = sum(f.key_count for f in group)
            age_days: Optional[int] = None
            age_label = "unknown"
            if hit.owner_created_at:
                age_days = (datetime.now(timezone.utc) - hit.owner_created_at).days
                for threshold, label in _ACCOUNT_AGE_BANDS:
                    if age_days < threshold:
                        age_label = label
                        break

            auto_signals: List[str] = []
            if len(group) >= self.AUTO_REPO_MIN:
                auto_signals.append(f"{len(group)} leak repos from one account")
            if age_days is not None and age_days <= self.AUTO_AGE_MAX:
                auto_signals.append(f"account only {age_days} days old")
            if total_keys >= self.AUTO_KEYS_MIN:
                auto_signals.append(f"{total_keys} keys across repos")

            profiles[login] = AccountProfile(
                login                   = login,
                repo_count              = len(group),
                total_keys              = total_keys,
                account_age_days        = age_days,
                age_label               = age_label,
                followers               = hit.owner_followers,
                public_repos            = hit.owner_public_repos,
                locations               = list({
                    hit.owner_location
                    for f in group
                    if f.hit.owner_location
                }),
                is_suspected_automation = len(auto_signals) >= 2,
                automation_signals      = auto_signals,
            )
        return profiles

    def _top_accounts(self, leaked: List[ClassifiedFinding]) -> List[AccountProfile]:
        profiles = self._build_account_map(leaked)
        return sorted(profiles.values(), key=lambda p: p.total_keys, reverse=True)[:10]

    def _automation_suspects(self, leaked: List[ClassifiedFinding]) -> List[AccountProfile]:
        profiles = self._build_account_map(leaked)
        return [p for p in profiles.values() if p.is_suspected_automation]

    # ── Repo naming ──────────────────────────────────────────────────────────

    def _repo_keyword_freq(self, leaked: List[ClassifiedFinding]) -> Dict[str, int]:
        """Count occurrences of taxonomy keywords in repo names."""
        counter: Counter = Counter()
        for f in leaked:
            name = f.hit.repo_name.lower()
            for kw in _REPO_TAXONOMY_KEYWORDS:
                if kw in name:
                    counter[kw] += 1
        return dict(counter.most_common())

    def _top_repo_words(self, leaked: List[ClassifiedFinding]) -> List[Tuple[str, int]]:
        """
        Tokenise all repo name segments (split on non-alphanumeric) and
        return top-20 tokens by frequency, excluding noise words.
        """
        noise = {"the", "a", "an", "is", "of", "in", "and", "or", "to", "for", ""}
        counter: Counter = Counter()
        for f in leaked:
            # split repo name after the owner/ prefix
            repo_part = f.hit.repo_name.split("/", 1)[-1].lower()
            tokens = re.split(r"[^a-z0-9]+", repo_part)
            for tok in tokens:
                if tok not in noise and len(tok) > 1:
                    counter[tok] += 1
        return counter.most_common(20)

    # ── Language / sophistication ────────────────────────────────────────────

    def _language_dist(self, leaked: List[ClassifiedFinding]) -> Dict[str, float]:
        """
        Compute language share as percentage of repos that use each language.
        Uses the primary repo language field as the key signal.
        """
        total = len(leaked)
        counter: Counter = Counter()
        for f in leaked:
            lang = f.hit.repo_language or "Unknown"
            counter[lang] += 1
        return {
            lang: round(count / total * 100, 1)
            for lang, count in counter.most_common()
        }

    def _sophist_score(self, f: ClassifiedFinding) -> int:
        """
        Assign 0–10 sophistication score to one finding.
        Higher = more skilled / organised threat actor.
        """
        score = 0
        lang = f.hit.repo_language or ""
        score += _LANGUAGE_SOPHISTICATION.get(lang, 1)

        # Multi-language repo → more complex project
        if len(f.hit.repo_languages) >= 3:
            score += 2
        elif len(f.hit.repo_languages) >= 2:
            score += 1

        # Non-trivial repository size
        if f.hit.repo_size_kb > 500:
            score += 2
        elif f.hit.repo_size_kb > 50:
            score += 1

        # Stargazers indicate the code was shared / reviewed
        if f.hit.repo_stargazers >= 10:
            score += 1

        # Description present → some effort to document
        if f.hit.repo_description:
            score += 1

        return min(score, 10)

    def _sophistication_dist(self, leaked: List[ClassifiedFinding]) -> Dict[str, int]:
        buckets = {"low (0-3)": 0, "medium (4-6)": 0, "high (7-10)": 0}
        for f in leaked:
            s = self._sophist_score(f)
            if s <= 3:
                buckets["low (0-3)"] += 1
            elif s <= 6:
                buckets["medium (4-6)"] += 1
            else:
                buckets["high (7-10)"] += 1
        return buckets

    def _mean_sophist(self, leaked: List[ClassifiedFinding]) -> float:
        if not leaked:
            return 0.0
        scores = [self._sophist_score(f) for f in leaked]
        return round(sum(scores) / len(scores), 2)

    # ── Temporal patterns ─────────────────────────────────────────────────────

    def _hour_heatmap(self, leaked: List[ClassifiedFinding]) -> Dict[str, int]:
        """Commit counts by hour-of-day (00–23 UTC)."""
        counter: Counter = Counter()
        for f in leaked:
            if f.hit.latest_commit_date:
                h = f.hit.latest_commit_date.strftime("%H")
                counter[h] += 1
        # Ensure all 24 slots are present even if zero
        return {str(h).zfill(2): counter.get(str(h).zfill(2), 0) for h in range(24)}

    def _dow_heatmap(self, leaked: List[ClassifiedFinding]) -> Dict[str, int]:
        """Commit counts by day-of-week."""
        days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        counter: Counter = Counter()
        for f in leaked:
            if f.hit.latest_commit_date:
                d = days[f.hit.latest_commit_date.weekday()]
                counter[d] += 1
        return {d: counter.get(d, 0) for d in days}

    def _batch_suspected(self, leaked: List[ClassifiedFinding]) -> bool:
        """
        Return True if ≥ 3 different repos were committed within the same
        1-hour window — a strong automation indicator.
        """
        hour_repo: Dict[str, set] = defaultdict(set)
        for f in leaked:
            if f.hit.latest_commit_date:
                key = f.hit.latest_commit_date.strftime("%Y-%m-%dT%H")
                hour_repo[key].add(f.repo_url)
        return any(len(repos) >= 3 for repos in hour_repo.values())

    def _batch_evidence(self, leaked: List[ClassifiedFinding]) -> List[str]:
        if not self._batch_suspected(leaked):
            return []
        hour_repo: Dict[str, set] = defaultdict(set)
        for f in leaked:
            if f.hit.latest_commit_date:
                key = f.hit.latest_commit_date.strftime("%Y-%m-%dT%H")
                hour_repo[key].add(f.repo_url)
        evidence = []
        for hour, repos in hour_repo.items():
            if len(repos) >= 3:
                evidence.append(f"{hour}Z: {len(repos)} repos committed in same hour")
        return sorted(evidence, reverse=True)[:5]

    # ── Volumetrics ──────────────────────────────────────────────────────────

    def _volume_buckets(self, leaked: List[ClassifiedFinding]) -> Dict[str, int]:
        buckets = {"1": 0, "2-9": 0, "10-99": 0, "100+": 0}
        for f in leaked:
            k = f.key_count
            if k == 1:
                buckets["1"] += 1
            elif k < 10:
                buckets["2-9"] += 1
            elif k < 100:
                buckets["10-99"] += 1
            else:
                buckets["100+"] += 1
        return buckets

    def _median_keys(self, leaked: List[ClassifiedFinding]) -> float:
        if not leaked:
            return 0.0
        counts = sorted(f.key_count for f in leaked)
        n = len(counts)
        mid = n // 2
        return counts[mid] if n % 2 else (counts[mid - 1] + counts[mid]) / 2

    def _stealer_artifact_count(self, leaked: List[ClassifiedFinding]) -> int:
        """Count repos whose file path suggests a known stealer artifact."""
        count = 0
        for f in leaked:
            if any(
                art in f.file_path.lower() for art in _STEALER_ARTIFACT_NAMES
            ):
                count += 1
        return count

    def _stealer_artifact_freq(self, leaked: List[ClassifiedFinding]) -> Dict[str, int]:
        counter: Counter = Counter()
        for f in leaked:
            path_lower = f.file_path.lower()
            for art in _STEALER_ARTIFACT_NAMES:
                if art in path_lower:
                    counter[art] += 1
        return dict(counter.most_common(10))

    # ── Freshness ────────────────────────────────────────────────────────────

    def _recency_count(self, leaked: List[ClassifiedFinding], days: int) -> int:
        cutoff = datetime.now(timezone.utc)
        from datetime import timedelta
        window = cutoff - timedelta(days=days)
        count = 0
        for f in leaked:
            pushed = f.hit.repo_pushed_at
            if pushed and pushed.replace(tzinfo=timezone.utc) > window:
                count += 1
        return count

    def _abandoned_count(self, leaked: List[ClassifiedFinding]) -> int:
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(days=180)
        count = 0
        for f in leaked:
            pushed = f.hit.repo_pushed_at
            if not pushed or pushed.replace(tzinfo=timezone.utc) < cutoff:
                count += 1
        return count

    # ── Empty report ─────────────────────────────────────────────────────────

    @staticmethod
    def _empty_report() -> TrendReport:
        return TrendReport(
            generated_at="", total_leaked_findings=0, total_unique_repos=0,
            total_unique_accounts=0, total_keys_observed=0,
            top_prolific_accounts=[], suspected_automation_accounts=[],
            repo_keyword_frequency={}, top_repo_name_words=[],
            language_distribution={}, sophistication_distribution={},
            mean_sophistication_score=0.0,
            commit_hour_heatmap={str(h).zfill(2): 0 for h in range(24)},
            commit_dow_heatmap={d: 0 for d in ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]},
            batch_upload_suspected=False, batch_upload_evidence=[],
            key_volume_buckets={"1": 0, "2-9": 0, "10-99": 0, "100+": 0},
            median_keys_per_repo=0.0, repos_with_stealer_artifacts=0,
            stealer_artifact_frequency={},
            repos_active_last_30_days=0, repos_active_last_90_days=0,
            repos_abandoned=0,
        )
