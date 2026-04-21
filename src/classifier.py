"""
classifier.py
─────────────────────────────────────────────────────────────────────────────
Differentiates between two classes of private-key exposure:

  LEAKED   — keys that were deliberately (or semi-deliberately) dumped by a
             third party; often stealer logs, credential marketplaces, or
             bulk-collection repos.

  ACCIDENTAL — a developer accidentally committed their own private key as
               part of normal project work; they should be notified so they
               can rotate it.

The heuristic is additive: each signal contributes a weighted score toward
LEAKED.  A threshold determines the final classification.  All weights and
thresholds are exposed as class-level constants so they can be tuned without
touching the logic.

Every decision is logged at DEBUG level so analysts can trace the reasoning.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from .api_client import SearchHit
from .key_detector import DetectedKey

logger = logging.getLogger(__name__)


# ── Classification label ─────────────────────────────────────────────────────

class Classification(str, Enum):
    LEAKED     = "LEAKED"
    ACCIDENTAL = "ACCIDENTAL"
    UNCERTAIN  = "UNCERTAIN"   # score near the threshold — needs human review


# ── Signals / word lists ─────────────────────────────────────────────────────

# Repository name keywords that strongly suggest deliberate credential dumping
_DUMP_REPO_KEYWORDS: List[str] = [
    "leak", "dump", "stealer", "logs", "creds", "credentials",
    "grabber", "harvest", "collection", "combolist", "combo",
    "hacked", "pwned", "breach", "database", "db-dump",
    "loot", "exfil", "stolen", "private-key", "ssh-keys",
]

# File paths/names that belong in a normal developer project (accidental signal)
_NORMAL_DEV_PATHS: List[re.Pattern] = [
    re.compile(r"^\.ssh/"),                      # user's .ssh directory
    re.compile(r"id_rsa$"),                      # default RSA key name
    re.compile(r"id_ed25519$"),                  # default Ed25519 key name
    re.compile(r"id_ecdsa$"),                    # default ECDSA key name
    re.compile(r"id_dsa$"),                      # default DSA key name (legacy)
    re.compile(r"ansible.*vault", re.I),         # ansible vault keys (accidental)
    re.compile(r"terraform.*key", re.I),         # terraform provisioning keys
    re.compile(r"vagrant.*key", re.I),           # vagrant insecure_private_key
    # NOTE: .pem alone is intentionally NOT in this list — it is too
    # generic to reliably indicate an accidental commit vs. a dump repo.
    # A dump repo named "ssh-dump-2024" can still have .pem files.
    re.compile(r"config/ssh"),                   # SSH config directory
    re.compile(r"test.*key", re.I),              # test fixture keys
    re.compile(r"fixtures?/"),                   # test fixtures folder
    re.compile(r"examples?/"),                   # example/demo folder
    re.compile(r"sample"),                       # sample data
    re.compile(r"\.github/"),                    # CI key material
]

# Topics that signal the repo is a CTF, research, or pentest project
# (still leaked classification but with reduced confidence)
_RESEARCH_TOPICS: List[str] = [
    "ctf", "pentest", "security-research", "red-team",
    "capture-the-flag", "hackthebox", "tryhackme",
]

# Account username patterns common in automated/threat-actor accounts
_SUSPICIOUS_USERNAME_PATTERNS: List[re.Pattern] = [
    re.compile(r"^[a-z0-9]{8,16}$"),        # all-lowercase alnum, no separator
    re.compile(r"\d{6,}"),                   # long digit run (bot-generated)
    re.compile(r"(hack|crack|steal|leak|dump|ghost|anon)", re.I),
]


# ── Result container ─────────────────────────────────────────────────────────

@dataclass
class ClassifiedFinding:
    """Complete finding record — ready for reporter and trend_analyzer."""
    # Source metadata
    hit: SearchHit
    detected_keys: List[DetectedKey]

    # Classification outcome
    classification: Classification
    confidence_score: float         # 0.0 (very accidental) … 1.0 (very leaked)
    signals: List[str]              # human-readable list of triggered signals

    # Convenience accessors (populated from hit)
    repo_url: str = field(init=False)
    file_path: str = field(init=False)
    commit_sha: Optional[str] = field(init=False)
    author_name: Optional[str] = field(init=False)
    author_email: Optional[str] = field(init=False)
    commit_date: str = field(init=False)
    key_count: int = field(init=False)

    def __post_init__(self) -> None:
        self.repo_url    = self.hit.repo_url
        self.file_path   = self.hit.file_path
        self.commit_sha  = self.hit.latest_commit_sha
        self.author_name = self.hit.latest_commit_author_name
        self.author_email= self.hit.latest_commit_author_email
        self.commit_date = (
            self.hit.latest_commit_date.isoformat()
            if self.hit.latest_commit_date else "unknown"
        )
        self.key_count   = len(self.detected_keys)


# ── Classifier ───────────────────────────────────────────────────────────────

class KeyClassifier:
    """
    Assigns a :class:`Classification` to each (SearchHit, [DetectedKey]) pair.

    Scoring rubric (additive, normalised to 0–1 before thresholding):
    ┌──────────────────────────────────────────────────────────┬───────┐
    │ Signal                                                   │ Score │
    ├──────────────────────────────────────────────────────────┼───────┤
    │ Repo name contains dump/leak keyword                     │ +0.45 │
    │ Key committed by non-owner                               │ +0.25 │
    │ Key count ≥ 10 (bulk dump)                               │ +0.25 │
    │ Key count ≥ 100 (stealer log)                            │ +0.40 │
    │ Repo is a GitHub Gist                                    │ +0.20 │
    │ Suspicious username pattern                              │ +0.15 │
    │ Account age < 30 days                                    │ +0.20 │
    │ Topic in research list                                   │ −0.10 │
    │ File path matches normal dev pattern                     │ −0.30 │
    │ Single key in clearly personal .ssh/ path               │ −0.40 │
    │ File in test/examples/fixtures folder                   │ −0.20 │
    └──────────────────────────────────────────────────────────┴───────┘

    Classification thresholds
      score ≥ 0.40  →  LEAKED
      score ≤ 0.15  →  ACCIDENTAL
      otherwise     →  UNCERTAIN
    """

    LEAKED_THRESHOLD:     float = 0.40
    ACCIDENTAL_THRESHOLD: float = 0.15

    def classify(
        self,
        hit: SearchHit,
        detected_keys: List[DetectedKey],
        key_count_in_file: int = 0,
    ) -> ClassifiedFinding:
        """
        Classify one finding.

        Parameters
        ----------
        hit:
            Hydrated search result from GitHubClient.
        detected_keys:
            Keys found in the file by KeyDetector.
        key_count_in_file:
            Raw count of PEM headers (may differ from len(detected_keys)
            if some blocks were deduplicated).
        """
        score  = 0.0
        signals: List[str] = []

        repo_lower  = hit.repo_name.lower()
        owner_lower = hit.owner_login.lower()
        path_lower  = hit.file_path.lower()
        count       = max(len(detected_keys), key_count_in_file)

        # ── Positive LEAKED signals ──────────────────────────────────────────

        for kw in _DUMP_REPO_KEYWORDS:
            if kw in repo_lower:
                score += 0.45
                signals.append(f"repo name contains dump keyword '{kw}'")
                break   # only score once even if multiple keywords hit

        # Key committed by someone other than the repo owner
        author = (hit.latest_commit_author_email or "").lower()
        if (hit.latest_commit_author_name
                and hit.latest_commit_author_name.lower() not in owner_lower
                and author
                and owner_lower not in author.split("@")[0]):
            score += 0.25
            signals.append(
                f"commit author '{hit.latest_commit_author_name}' ≠ repo owner '{hit.owner_login}'"
            )

        # Bulk key dumps
        if count >= 100:
            score += 0.40
            signals.append(f"mass key dump: {count} keys in file")
        elif count >= 10:
            score += 0.25
            signals.append(f"bulk keys: {count} keys in file")

        # GitHub Gists are anonymous paste-bins — common stealer log medium
        if "/gist.github.com/" in hit.repo_url or hit.repo_name.startswith("gist:"):
            score += 0.20
            signals.append("hosted as a GitHub Gist")

        # Suspicious account username
        for pat in _SUSPICIOUS_USERNAME_PATTERNS:
            if pat.search(hit.owner_login):
                score += 0.15
                signals.append(f"suspicious username pattern: '{hit.owner_login}'")
                break

        # Very new account — common for throwaway/bot accounts
        if hit.owner_created_at:
            from datetime import datetime, timezone
            age_days = (datetime.now(timezone.utc) - hit.owner_created_at).days
            if age_days < 30:
                score += 0.20
                signals.append(f"account only {age_days} days old")

        # ── Negative signals (reduce toward ACCIDENTAL) ──────────────────────

        if any(pat.search(hit.owner_location or "") for pat in []):
            pass    # placeholder for future geo signals

        for pat in _NORMAL_DEV_PATHS:
            if pat.search(path_lower):
                # Extra reduction if it's a single key in an obvious .ssh path
                if count == 1 and ".ssh" in path_lower:
                    score -= 0.40
                    signals.append("single key in personal .ssh/ directory (likely accidental)")
                elif "test" in path_lower or "fixture" in path_lower or "example" in path_lower:
                    score -= 0.20
                    signals.append(f"key in test/fixture/example folder: '{hit.file_path}'")
                else:
                    score -= 0.30
                    signals.append(f"file path matches normal dev pattern: '{hit.file_path}'")
                break   # only apply once

        # .pem extension alone is a very weak accidental signal — only applied
        # when no stronger leaked indicators have already scored (score <= 0.10).
        # A dump repo named "ssh-dump-2024" can still have .pem extension files.
        if hit.file_path.lower().endswith(".pem") and score <= 0.10:
            score -= 0.10
            signals.append("file has .pem extension (weak accidental signal)")

        for topic in _RESEARCH_TOPICS:
            if topic in (hit.repo_topics or []):
                score -= 0.10
                signals.append(f"repo topic '{topic}' suggests research/CTF context")
                break

        # ── Normalise and classify ────────────────────────────────────────────
        score = round(max(0.0, min(1.0, score)), 3)

        if score >= self.LEAKED_THRESHOLD:
            classification = Classification.LEAKED
        elif score <= self.ACCIDENTAL_THRESHOLD:
            classification = Classification.ACCIDENTAL
        else:
            classification = Classification.UNCERTAIN

        logger.debug(
            "[%s] score=%.3f | repo=%s | signals=%s",
            classification.value, score, hit.repo_name, signals,
        )

        return ClassifiedFinding(
            hit             = hit,
            detected_keys   = detected_keys,
            classification  = classification,
            confidence_score= score,
            signals         = signals,
        )
