"""
key_detector.py
Multi-category secrets detection engine covering 30 secret types across 6 categories.

ETHICAL GUARDRAIL: Raw secret values are NEVER stored, returned, or logged.
Only SHA-256 fingerprints are recorded, used solely for deduplication.
"""

from __future__ import annotations
import hashlib, logging, re
from dataclasses import dataclass
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class Category:
    PRIVATE_KEY = "private_key"
    CLOUD       = "cloud_credential"
    API_KEY     = "api_key"
    VCS_TOKEN   = "vcs_token"
    OAUTH_TOKEN = "oauth_token"
    DATABASE    = "database_credential"


# Each entry: id, category, label, pattern, confidence, search_query, min_length, max_length
_SECRET_DEFS: List[Dict] = [
    # ── PRIVATE KEYS (PEM blocks) ────────────────────────────────────────────
    {"id": "OPENSSH_PRIVATE_KEY", "category": Category.PRIVATE_KEY,
     "label": "OpenSSH Private Key",
     "pattern": re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----(.+?)-----END OPENSSH PRIVATE KEY-----", re.DOTALL),
     "confidence": "high", "search_query": '"BEGIN OPENSSH PRIVATE KEY"', "min_length": 50, "max_length": None},
    {"id": "RSA_PRIVATE_KEY", "category": Category.PRIVATE_KEY,
     "label": "RSA Private Key (PKCS#1)",
     "pattern": re.compile(r"-----BEGIN RSA PRIVATE KEY-----(.+?)-----END RSA PRIVATE KEY-----", re.DOTALL),
     "confidence": "high", "search_query": '"BEGIN RSA PRIVATE KEY"', "min_length": 50, "max_length": None},
    {"id": "EC_PRIVATE_KEY", "category": Category.PRIVATE_KEY,
     "label": "EC Private Key",
     "pattern": re.compile(r"-----BEGIN EC PRIVATE KEY-----(.+?)-----END EC PRIVATE KEY-----", re.DOTALL),
     "confidence": "high", "search_query": '"BEGIN EC PRIVATE KEY"', "min_length": 50, "max_length": None},
    {"id": "DSA_PRIVATE_KEY", "category": Category.PRIVATE_KEY,
     "label": "DSA Private Key",
     "pattern": re.compile(r"-----BEGIN DSA PRIVATE KEY-----(.+?)-----END DSA PRIVATE KEY-----", re.DOTALL),
     "confidence": "high", "search_query": '"BEGIN DSA PRIVATE KEY"', "min_length": 50, "max_length": None},
    {"id": "PKCS8_PRIVATE_KEY", "category": Category.PRIVATE_KEY,
     "label": "PKCS#8 Private Key",
     "pattern": re.compile(r"-----BEGIN PRIVATE KEY-----(.+?)-----END PRIVATE KEY-----", re.DOTALL),
     "confidence": "high", "search_query": '"BEGIN PRIVATE KEY"', "min_length": 50, "max_length": None},
    {"id": "PKCS8_ENC_PRIVATE_KEY", "category": Category.PRIVATE_KEY,
     "label": "Encrypted PKCS#8 Private Key",
     "pattern": re.compile(r"-----BEGIN ENCRYPTED PRIVATE KEY-----(.+?)-----END ENCRYPTED PRIVATE KEY-----", re.DOTALL),
     "confidence": "high", "search_query": '"BEGIN ENCRYPTED PRIVATE KEY"', "min_length": 50, "max_length": None},
    {"id": "PGP_PRIVATE_KEY", "category": Category.PRIVATE_KEY,
     "label": "PGP/GPG Private Key Block",
     "pattern": re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----(.+?)-----END PGP PRIVATE KEY BLOCK-----", re.DOTALL),
     "confidence": "high", "search_query": '"BEGIN PGP PRIVATE KEY BLOCK"', "min_length": 50, "max_length": None},
    # ── AWS ──────────────────────────────────────────────────────────────────
    # AWS access key IDs: known 4-char prefix + 16 uppercase alphanumeric = exactly 20 chars
    {"id": "AWS_ACCESS_KEY_ID", "category": Category.CLOUD,
     "label": "AWS Access Key ID",
     "pattern": re.compile(r"(?<![A-Z0-9])(?P<secret>(AKIA|AROA|ABIA|ACCA|ASIA)[A-Z0-9]{16})(?![A-Z0-9])"),
     "confidence": "high", "search_query": '"AKIA"', "min_length": 20, "max_length": 20},
    # AWS secret access keys: 40-char base64url string bound to known variable names
    {"id": "AWS_SECRET_ACCESS_KEY", "category": Category.CLOUD,
     "label": "AWS Secret Access Key",
     "pattern": re.compile(r"(?:aws.?secret.?(?:access.?)?key|AWS_SECRET_ACCESS_KEY)[\s\"'`]*[=:]\s*[\"'`]?(?P<secret>[A-Za-z0-9/+]{40})[\"'`]?", re.IGNORECASE),
     "confidence": "high", "search_query": '"AWS_SECRET_ACCESS_KEY"', "min_length": 40, "max_length": 40},
    # ── GCP ──────────────────────────────────────────────────────────────────
    # GCP service account JSON: type field is definitive signal in all SA files
    {"id": "GCP_SERVICE_ACCOUNT_KEY", "category": Category.CLOUD,
     "label": "GCP Service Account Key (JSON)",
     "pattern": re.compile(r'"type"\s*:\s*"service_account"', re.IGNORECASE),
     "confidence": "high", "search_query": '"type": "service_account"', "min_length": 0, "max_length": None},
    # Google API keys: always start AIza, exactly 39 chars
    {"id": "GCP_API_KEY", "category": Category.CLOUD,
     "label": "Google API Key",
     "pattern": re.compile(r"(?P<secret>AIza[A-Za-z0-9_\-]{35})"),
     "confidence": "high", "search_query": '"AIza"', "min_length": 39, "max_length": 39},
    {"id": "GCP_OAUTH_CLIENT_SECRET", "category": Category.CLOUD,
     "label": "Google OAuth Client Secret",
     "pattern": re.compile(r'"client_secret"\s*:\s*"(?P<secret>GOCSPX-[A-Za-z0-9_\-]{28})"'),
     "confidence": "high", "search_query": '"GOCSPX-"', "min_length": 35, "max_length": None},
    # ── AZURE ─────────────────────────────────────────────────────────────────
    {"id": "AZURE_CLIENT_SECRET", "category": Category.CLOUD,
     "label": "Azure Client Secret / Service Principal",
     "pattern": re.compile(r"(?:client.?secret|AZURE_CLIENT_SECRET|clientSecret)[\s\"'`]*[=:]\s*[\"'`]?(?P<secret>[A-Za-z0-9~._\-]{34,40})[\"'`]?", re.IGNORECASE),
     "confidence": "medium", "search_query": '"AZURE_CLIENT_SECRET"', "min_length": 34, "max_length": 40},
    # Azure storage connection string: AccountKey= with 88-char base64 value is definitive
    {"id": "AZURE_CONNECTION_STRING", "category": Category.CLOUD,
     "label": "Azure Storage Connection String",
     "pattern": re.compile(r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=(?P<secret>[A-Za-z0-9+/=]{88});", re.IGNORECASE),
     "confidence": "high", "search_query": '"DefaultEndpointsProtocol=https;AccountName"', "min_length": 88, "max_length": 88},
    # ── VCS / REGISTRY TOKENS ─────────────────────────────────────────────────
    # GitHub PATs: classic (ghp_/gho_/ghu_/ghs_/ghr_ + 36 chars) or fine-grained (github_pat_ + 59)
    {"id": "GITHUB_PAT", "category": Category.VCS_TOKEN,
     "label": "GitHub Personal Access Token",
     "pattern": re.compile(r"(?P<secret>(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{59})"),
     "confidence": "high", "search_query": '"ghp_"', "min_length": 40, "max_length": None},
    {"id": "GITLAB_TOKEN", "category": Category.VCS_TOKEN,
     "label": "GitLab Personal Access Token",
     "pattern": re.compile(r"(?P<secret>glpat-[A-Za-z0-9_\-]{20,})"),
     "confidence": "high", "search_query": '"glpat-"', "min_length": 26, "max_length": None},
    {"id": "NPM_TOKEN", "category": Category.VCS_TOKEN,
     "label": "NPM Access Token",
     "pattern": re.compile(r"(?P<secret>npm_[A-Za-z0-9]{36})"),
     "confidence": "high", "search_query": '"npm_"', "min_length": 40, "max_length": None},
    {"id": "PYPI_TOKEN", "category": Category.VCS_TOKEN,
     "label": "PyPI API Token",
     "pattern": re.compile(r"(?P<secret>pypi-[A-Za-z0-9_\-]{32,})"),
     "confidence": "high", "search_query": '"pypi-"', "min_length": 37, "max_length": None},
    # ── PAYMENT / SaaS ────────────────────────────────────────────────────────
    # Stripe: sk_live_=production critical, sk_test_=test (still flag for disclosure)
    {"id": "STRIPE_SECRET_KEY", "category": Category.API_KEY,
     "label": "Stripe Secret API Key",
     "pattern": re.compile(r"(?P<secret>sk_(?:live|test)_[A-Za-z0-9]{24,})"),
     "confidence": "high", "search_query": '"sk_live_"', "min_length": 32, "max_length": None},
    {"id": "STRIPE_RESTRICTED_KEY", "category": Category.API_KEY,
     "label": "Stripe Restricted API Key",
     "pattern": re.compile(r"(?P<secret>rk_(?:live|test)_[A-Za-z0-9]{24,})"),
     "confidence": "high", "search_query": '"rk_live_"', "min_length": 32, "max_length": None},
    # Twilio Account SIDs always begin with AC and are exactly 34 chars
    {"id": "TWILIO_ACCOUNT_SID", "category": Category.API_KEY,
     "label": "Twilio Account SID",
     "pattern": re.compile(r"(?P<secret>AC[a-f0-9]{32})"),
     "confidence": "high", "search_query": '"AccountSid"', "min_length": 34, "max_length": 34},
    {"id": "TWILIO_AUTH_TOKEN", "category": Category.API_KEY,
     "label": "Twilio Auth Token",
     "pattern": re.compile(r"(?:twilio.?auth.?token|TWILIO_AUTH_TOKEN|authToken)[\s\"'`]*[=:]\s*[\"'`]?(?P<secret>[a-f0-9]{32})[\"'`]?", re.IGNORECASE),
     "confidence": "medium", "search_query": '"TWILIO_AUTH_TOKEN"', "min_length": 32, "max_length": 32},
    # SendGrid: SG.<22chars>.<43chars> — three-part structure is distinctive
    {"id": "SENDGRID_API_KEY", "category": Category.API_KEY,
     "label": "SendGrid API Key",
     "pattern": re.compile(r"(?P<secret>SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})"),
     "confidence": "high", "search_query": '"SG."', "min_length": 69, "max_length": None},
    # Slack token prefixes: xoxb=bot, xoxp=user, xoxa=app, xoxr=refresh, xoxs=session
    {"id": "SLACK_TOKEN", "category": Category.API_KEY,
     "label": "Slack API Token",
     "pattern": re.compile(r"(?P<secret>xox[bparise]-[A-Za-z0-9\-]{10,})"),
     "confidence": "high", "search_query": '"xoxb-"', "min_length": 30, "max_length": None},
    # Telegram bot tokens: <numeric_id>:<alphanum_secret>
    {"id": "TELEGRAM_BOT_TOKEN", "category": Category.API_KEY,
     "label": "Telegram Bot API Token",
     "pattern": re.compile(r"(?P<secret>\d{8,10}:[A-Za-z0-9_\-]{35})"),
     "confidence": "medium", "search_query": '"api.telegram.org/bot"', "min_length": 44, "max_length": None},
    {"id": "MAILGUN_API_KEY", "category": Category.API_KEY,
     "label": "Mailgun API Key",
     "pattern": re.compile(r"(?P<secret>key-[a-f0-9]{32})"),
     "confidence": "medium", "search_query": '"mailgun" "key-"', "min_length": 36, "max_length": 36},
    # Heroku API keys are UUID v4 format assigned to known variable names
    {"id": "HEROKU_API_KEY", "category": Category.API_KEY,
     "label": "Heroku API Key",
     "pattern": re.compile(r"(?:heroku.?api.?key|HEROKU_API_KEY)[\s\"'`]*[=:]\s*[\"'`]?(?P<secret>[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})[\"'`]?", re.IGNORECASE),
     "confidence": "medium", "search_query": '"HEROKU_API_KEY"', "min_length": 36, "max_length": 36},
    # ── OAUTH / JWT ───────────────────────────────────────────────────────────
    # JWTs: three base64url sections; header always begins with eyJ (base64url of '{')
    {"id": "JWT_TOKEN", "category": Category.OAUTH_TOKEN,
     "label": "JSON Web Token (JWT)",
     "pattern": re.compile(r"(?P<secret>eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)"),
     "confidence": "medium", "search_query": '"eyJ"', "min_length": 50, "max_length": None},
    {"id": "GENERIC_BEARER_TOKEN", "category": Category.OAUTH_TOKEN,
     "label": "OAuth Bearer / Access Token",
     "pattern": re.compile(r"(?:bearer|access.?token|oauth.?token)[\s\"'`]*[=:]\s*[\"'`]?(?P<secret>[A-Za-z0-9\-_.]{32,})[\"'`]?", re.IGNORECASE),
     "confidence": "low", "search_query": '"access_token"', "min_length": 32, "max_length": None},
    # ── DATABASE CONNECTION STRINGS ────────────────────────────────────────────
    # Match DB URLs with user:password@ segment — embedded credentials are the concern
    {"id": "DATABASE_URL", "category": Category.DATABASE,
     "label": "Database Connection String with Credentials",
     "pattern": re.compile(r"(?P<secret>(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis(?:s)?|mssql|oracle)://[A-Za-z0-9_.\-]+:[^@\s\"'`]{8,}@[A-Za-z0-9._:\-/]+)", re.IGNORECASE),
     "confidence": "high", "search_query": '"postgres://"', "min_length": 20, "max_length": None},
]


# Fast pre-screen: literal anchors whose presence means we need full scanning
# Pre-screen anchors: literal strings whose presence means a file MAY contain
# a secret.  Missing an anchor means we skip all 30 regexes for that file —
# huge performance win on large codebases.  When adding a new secret type,
# add a reliable anchor string here, otherwise it will never match.
_ANCHORS = [
    # ── PEM private key block headers ────────────────────────────────
    "-----BEGIN",
    # ── AWS ──────────────────────────────────────────────────────────
    "AKIA", "AROA", "ABIA", "ACCA", "ASIA",   # access key ID prefixes
    "AWS_SECRET",                              # env var for secret access key
    "aws_secret",                              # snake_case variant
    # ── GCP ──────────────────────────────────────────────────────────
    "AIza",                                    # Google API key prefix
    "GOCSPX-",                                 # Google OAuth client secret
    "service_account",                         # GCP service account JSON marker
    # ── Azure ────────────────────────────────────────────────────────
    "DefaultEndpointsProtocol",                # Azure storage connection string
    "AZURE_CLIENT_SECRET", "client_secret",    # Azure SP + OAuth
    "clientSecret",                            # camelCase variant
    # ── VCS / Registry tokens ────────────────────────────────────────
    "ghp_", "gho_", "ghu_", "ghs_", "ghr_",   # GitHub classic PATs
    "github_pat_",                             # GitHub fine-grained PATs
    "glpat-",                                  # GitLab PAT
    "npm_",                                    # NPM access token
    "pypi-",                                   # PyPI API token
    # ── Stripe ───────────────────────────────────────────────────────
    "sk_live_", "sk_test_",                    # Stripe secret keys
    "rk_live_", "rk_test_",                    # Stripe restricted keys
    # ── Twilio ───────────────────────────────────────────────────────
    "AccountSid", "account_sid",               # Twilio SID variable names
    "AC",                                      # Twilio SID prefix itself
    "TWILIO_AUTH_TOKEN", "twilio_auth",        # Twilio auth token env vars
    "authToken",                               # camelCase auth token
    # ── SendGrid ─────────────────────────────────────────────────────
    "SG.",                                     # SendGrid key prefix
    # ── Slack ────────────────────────────────────────────────────────
    "xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-",
    # ── Others ───────────────────────────────────────────────────────
    "api.telegram.org/bot",                    # Telegram bot tokens
    "HEROKU_API_KEY", "heroku_api",            # Heroku API key env vars
    "MAILGUN", "mailgun", "key-",              # Mailgun (broad anchor)
    "eyJ",                                     # JWT header prefix
    "access_token", "oauth_token", "bearer",   # generic OAuth anchors
    # ── Database connection strings ──────────────────────────────────
    "postgres://", "postgresql://",
    "mysql://", "mongodb://", "mongodb+srv://",
    "redis://", "rediss://",
    "mssql://", "oracle://",
]

_PRESCREEN: re.Pattern = re.compile(
    "|".join(re.escape(a) for a in _ANCHORS),
    re.IGNORECASE,
)


@dataclass(frozen=True)
class DetectedSecret:
    """
    Metadata about one detected secret. Raw value is NOT stored.
    sha256_fingerprint — for deduplication across files
    redacted_sample    — first 4 chars + **** for analyst identification only
    """
    secret_id:          str
    category:           str
    label:              str
    sha256_fingerprint: str
    confidence:         str
    redacted_sample:    str
    is_pem_block:       bool = False


# Backward-compatibility alias
DetectedKey = DetectedSecret


class KeyDetector:
    """
    Stateless multi-category secrets scanner.
    Name preserved for backward compatibility with existing callers.
    """

    def scan(self, content: str) -> List[DetectedSecret]:
        """
        Scan content for all 30 known secret types.
        Raw secret values are hashed immediately and NEVER returned.
        """
        if not content:
            return []
        if not _PRESCREEN.search(content):
            return []   # fast exit — no anchor strings present

        found: List[DetectedSecret] = []
        seen_hashes: set = set()

        for defn in _SECRET_DEFS:
            for match in defn["pattern"].finditer(content):
                # Extract raw value from named group, first group, or full match
                groups = match.groupdict()
                if "secret" in groups and groups["secret"]:
                    raw_value = groups["secret"]
                elif match.lastindex and match.lastindex >= 1:
                    raw_value = match.group(1)
                else:
                    raw_value = match.group(0)

                # Length filter
                stripped_len = len(raw_value.strip())
                if stripped_len < defn["min_length"]:
                    continue
                if defn["max_length"] and stripped_len > defn["max_length"]:
                    continue

                # ETHICAL GUARDRAIL: hash immediately, discard plaintext
                sha256 = hashlib.sha256(
                    match.group(0).encode("utf-8", errors="replace")
                ).hexdigest()
                if sha256 in seen_hashes:
                    continue
                seen_hashes.add(sha256)

                stripped = raw_value.strip()
                redacted = (stripped[:4] + "****") if len(stripped) >= 4 else "****"

                found.append(DetectedSecret(
                    secret_id          = defn["id"],
                    category           = defn["category"],
                    label              = defn["label"],
                    sha256_fingerprint = sha256,
                    confidence         = defn["confidence"],
                    redacted_sample    = redacted,
                    is_pem_block       = (defn["category"] == Category.PRIVATE_KEY),
                ))
                logger.debug("Detected %s | sha256=%.12s | sample=%s",
                             defn["label"], sha256, redacted)

        if found:
            logger.info("%d secret(s): %s", len(found),
                        ", ".join(s.secret_id for s in found))
        return found

    def contains_secret(self, content: str) -> bool:
        return bool(content and _PRESCREEN.search(content))

    def contains_key(self, content: str) -> bool:
        """Backward-compat alias for contains_secret()."""
        return self.contains_secret(content)

    def estimate_key_count_in_file(self, content: str) -> int:
        """Count PEM private key headers — preserved for classifier.py compat."""
        if not content:
            return 0
        return len(re.findall(
            r"-----BEGIN (?:OPENSSH |RSA |EC |DSA |ENCRYPTED |PGP )?PRIVATE KEY",
            content, re.IGNORECASE))

    @staticmethod
    def group_by_category(secrets: List[DetectedSecret]) -> Dict[str, List[DetectedSecret]]:
        groups: Dict[str, List[DetectedSecret]] = {}
        for s in secrets:
            groups.setdefault(s.category, []).append(s)
        return groups

    @staticmethod
    def all_search_queries() -> Dict[str, str]:
        """Return {secret_id: search_query} for every definition."""
        return {d["id"]: d["search_query"] for d in _SECRET_DEFS}

    @staticmethod
    def categories() -> List[str]:
        return [Category.PRIVATE_KEY, Category.CLOUD, Category.API_KEY,
                Category.VCS_TOKEN, Category.OAUTH_TOKEN, Category.DATABASE]
