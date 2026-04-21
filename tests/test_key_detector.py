"""
tests/test_key_detector.py
─────────────────────────────────────────────────────────────────────────────
Comprehensive tests for the multi-category secrets detection engine.
Covers all 30 secret types across 6 categories.
All tests are offline — no network calls made.
"""
import hashlib
import pytest
from src.key_detector import KeyDetector, DetectedSecret, Category

# ── Synthetic test fixtures ───────────────────────────────────────────────────
# These are structurally valid but NON-FUNCTIONAL credential strings.
# None of these are real credentials and cannot authenticate with any service.

# Private Keys — structurally valid PEM blocks with placeholder base64 bodies
FAKE_OPENSSH = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAAAAAAAAAAAAAFAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcY\n-----END OPENSSH PRIVATE KEY-----\n"
FAKE_RSA     = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4PAtEsHAAAAAAAAAAAAAAAAAAAAAA\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n-----END RSA PRIVATE KEY-----\n"
FAKE_EC      = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIPlaceholderDataHereAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n-----END EC PRIVATE KEY-----\n"
FAKE_DSA     = "-----BEGIN DSA PRIVATE KEY-----\nMIIBugIBAAKBgQDPlaceholderDataHereAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n-----END DSA PRIVATE KEY-----\n"
FAKE_PKCS8   = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQAAAAAAAAAAAAAAAAA\n-----END PRIVATE KEY-----\n"
FAKE_PGP     = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\nlQHYBGRPlaceholderDataHereAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n-----END PGP PRIVATE KEY BLOCK-----\n"

# AWS credentials — fake key ID uses real AKIA prefix format; 40-char secret
FAKE_AWS_KEY_ID  = "AKIAIOSFODNN7EXAMPLE"           # format-valid, non-functional
FAKE_AWS_SECRET  = "AWS_SECRET_ACCESS_KEY = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# GCP — service_account JSON marker
FAKE_GCP_SA      = '{"type": "service_account", "project_id": "example-project"}'
FAKE_GCP_API_KEY = "AIzaSyDummyKeyForTestingPurposesOnly123"  # AIza + 35 chars

# GitHub PATs
FAKE_GITHUB_PAT_CLASSIC    = "ghp_" + "A" * 36
FAKE_GITHUB_PAT_FINEGRAINED = "github_pat_" + "B" * 59

# GitLab token
FAKE_GITLAB_TOKEN = "glpat-" + "x" * 20

# VCS tokens
FAKE_NPM_TOKEN  = "npm_" + "N" * 36
FAKE_PYPI_TOKEN = "pypi-" + "P" * 32

# Stripe
FAKE_STRIPE_LIVE = "sk_live_" + "S" * 24
FAKE_STRIPE_TEST = "sk_test_" + "T" * 24

# Twilio
FAKE_TWILIO_SID  = "AC" + "a" * 32    # AC + 32 hex chars
FAKE_TWILIO_AUTH = "TWILIO_AUTH_TOKEN = " + "b" * 32

# SendGrid — SG.<22>.<43>
FAKE_SENDGRID = "SG." + "A" * 22 + "." + "B" * 43

# Slack
FAKE_SLACK = "xoxb-123456789012-123456789012-" + "A" * 24

# JWT — header.payload.signature (eyJ prefix is base64url of '{"')
FAKE_JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")

# Database URL with embedded credentials
FAKE_DB_URL = "postgres://dbuser:SuperSecret123@prod-db.example.com:5432/mydb"

# Azure connection string
FAKE_AZURE_CS = ("DefaultEndpointsProtocol=https;AccountName=mystorageaccount;"
                 "AccountKey=" + "A" * 88 + ";EndpointSuffix=core.windows.net")

NOT_A_SECRET = "This is a perfectly normal README file with no credentials."


@pytest.fixture
def detector():
    return KeyDetector()


# ════════════════════════════════════════════════════════════════════════════
# PRIVATE KEY DETECTION
# ════════════════════════════════════════════════════════════════════════════

class TestPrivateKeyDetection:
    def test_openssh_detected(self, detector):
        r = detector.scan(FAKE_OPENSSH)
        assert any(s.secret_id == "OPENSSH_PRIVATE_KEY" for s in r)

    def test_rsa_detected(self, detector):
        r = detector.scan(FAKE_RSA)
        assert any(s.secret_id == "RSA_PRIVATE_KEY" for s in r)

    def test_ec_detected(self, detector):
        r = detector.scan(FAKE_EC)
        assert any(s.secret_id == "EC_PRIVATE_KEY" for s in r)

    def test_dsa_detected(self, detector):
        r = detector.scan(FAKE_DSA)
        assert any(s.secret_id == "DSA_PRIVATE_KEY" for s in r)

    def test_pkcs8_detected(self, detector):
        r = detector.scan(FAKE_PKCS8)
        assert any(s.secret_id == "PKCS8_PRIVATE_KEY" for s in r)

    def test_pgp_detected(self, detector):
        r = detector.scan(FAKE_PGP)
        assert any(s.secret_id == "PGP_PRIVATE_KEY" for s in r)

    def test_all_private_key_types_have_correct_category(self, detector):
        combined = FAKE_OPENSSH + FAKE_RSA + FAKE_EC + FAKE_DSA + FAKE_PKCS8 + FAKE_PGP
        results = detector.scan(combined)
        pem_results = [s for s in results if s.is_pem_block]
        assert len(pem_results) == 6
        assert all(s.category == Category.PRIVATE_KEY for s in pem_results)

    def test_multi_key_in_one_file(self, detector):
        combined = FAKE_OPENSSH + "\n\n" + FAKE_RSA + "\n\n" + FAKE_EC
        results = detector.scan(combined)
        ids = {s.secret_id for s in results}
        assert "OPENSSH_PRIVATE_KEY" in ids
        assert "RSA_PRIVATE_KEY" in ids
        assert "EC_PRIVATE_KEY" in ids


# ════════════════════════════════════════════════════════════════════════════
# CLOUD CREDENTIAL DETECTION
# ════════════════════════════════════════════════════════════════════════════

class TestCloudCredentialDetection:
    def test_aws_access_key_id_detected(self, detector):
        r = detector.scan(f"key = {FAKE_AWS_KEY_ID}")
        assert any(s.secret_id == "AWS_ACCESS_KEY_ID" for s in r)

    def test_aws_secret_access_key_detected(self, detector):
        r = detector.scan(FAKE_AWS_SECRET)
        assert any(s.secret_id == "AWS_SECRET_ACCESS_KEY" for s in r)

    def test_gcp_service_account_detected(self, detector):
        r = detector.scan(FAKE_GCP_SA)
        assert any(s.secret_id == "GCP_SERVICE_ACCOUNT_KEY" for s in r)

    def test_gcp_api_key_detected(self, detector):
        r = detector.scan(f'api_key = "{FAKE_GCP_API_KEY}"')
        assert any(s.secret_id == "GCP_API_KEY" for s in r)

    def test_azure_connection_string_detected(self, detector):
        r = detector.scan(FAKE_AZURE_CS)
        assert any(s.secret_id == "AZURE_CONNECTION_STRING" for s in r)

    def test_cloud_category_label(self, detector):
        r = detector.scan(f"key = {FAKE_AWS_KEY_ID}")
        aws = next(s for s in r if s.secret_id == "AWS_ACCESS_KEY_ID")
        assert aws.category == Category.CLOUD

    def test_aws_key_id_exact_length_required(self, detector):
        # Too short — should not match
        r = detector.scan("AKIASHORT123")
        assert not any(s.secret_id == "AWS_ACCESS_KEY_ID" for s in r)

    def test_aws_key_id_must_have_valid_prefix(self, detector):
        # Wrong prefix — should not match as AWS_ACCESS_KEY_ID
        r = detector.scan("AXYZ" + "A" * 16)
        assert not any(s.secret_id == "AWS_ACCESS_KEY_ID" for s in r)


# ════════════════════════════════════════════════════════════════════════════
# API KEY DETECTION
# ════════════════════════════════════════════════════════════════════════════

class TestApiKeyDetection:
    def test_stripe_live_key_detected(self, detector):
        r = detector.scan(f'stripe_key = "{FAKE_STRIPE_LIVE}"')
        assert any(s.secret_id == "STRIPE_SECRET_KEY" for s in r)

    def test_stripe_test_key_detected(self, detector):
        # sk_test_ keys are also flagged — developers should not commit these
        r = detector.scan(f'api_key = "{FAKE_STRIPE_TEST}"')
        assert any(s.secret_id == "STRIPE_SECRET_KEY" for s in r)

    def test_twilio_sid_detected(self, detector):
        r = detector.scan(f"account_sid = {FAKE_TWILIO_SID}")
        assert any(s.secret_id == "TWILIO_ACCOUNT_SID" for s in r)

    def test_twilio_auth_token_detected(self, detector):
        r = detector.scan(FAKE_TWILIO_AUTH)
        assert any(s.secret_id == "TWILIO_AUTH_TOKEN" for s in r)

    def test_sendgrid_key_detected(self, detector):
        r = detector.scan(f'SG_KEY = "{FAKE_SENDGRID}"')
        assert any(s.secret_id == "SENDGRID_API_KEY" for s in r)

    def test_slack_bot_token_detected(self, detector):
        r = detector.scan(f"token = {FAKE_SLACK}")
        assert any(s.secret_id == "SLACK_TOKEN" for s in r)

    def test_api_key_category_label(self, detector):
        r = detector.scan(f'"{FAKE_SENDGRID}"')
        sg = next(s for s in r if s.secret_id == "SENDGRID_API_KEY")
        assert sg.category == Category.API_KEY


# ════════════════════════════════════════════════════════════════════════════
# VCS / REGISTRY TOKEN DETECTION
# ════════════════════════════════════════════════════════════════════════════

class TestVcsTokenDetection:
    def test_github_pat_classic_detected(self, detector):
        r = detector.scan(f"token = {FAKE_GITHUB_PAT_CLASSIC}")
        assert any(s.secret_id == "GITHUB_PAT" for s in r)

    def test_github_pat_finegrained_detected(self, detector):
        r = detector.scan(f"token = {FAKE_GITHUB_PAT_FINEGRAINED}")
        assert any(s.secret_id == "GITHUB_PAT" for s in r)

    def test_gitlab_token_detected(self, detector):
        r = detector.scan(f"CI_JOB_TOKEN={FAKE_GITLAB_TOKEN}")
        assert any(s.secret_id == "GITLAB_TOKEN" for s in r)

    def test_npm_token_detected(self, detector):
        r = detector.scan(f"//registry.npmjs.org/:_authToken={FAKE_NPM_TOKEN}")
        assert any(s.secret_id == "NPM_TOKEN" for s in r)

    def test_pypi_token_detected(self, detector):
        r = detector.scan(f"password = {FAKE_PYPI_TOKEN}")
        assert any(s.secret_id == "PYPI_TOKEN" for s in r)

    def test_vcs_token_category_label(self, detector):
        r = detector.scan(f"token = {FAKE_GITHUB_PAT_CLASSIC}")
        gh = next(s for s in r if s.secret_id == "GITHUB_PAT")
        assert gh.category == Category.VCS_TOKEN


# ════════════════════════════════════════════════════════════════════════════
# OAUTH / JWT DETECTION
# ════════════════════════════════════════════════════════════════════════════

class TestOauthTokenDetection:
    def test_jwt_detected(self, detector):
        r = detector.scan(f"Authorization: Bearer {FAKE_JWT}")
        assert any(s.secret_id == "JWT_TOKEN" for s in r)

    def test_jwt_must_have_three_segments(self, detector):
        # Only two segments — not a valid JWT
        r = detector.scan("eyJhbGci.eyJzdWIi")
        assert not any(s.secret_id == "JWT_TOKEN" for s in r)

    def test_jwt_minimum_length_enforced(self, detector):
        # Very short eyJ... — below min_length
        r = detector.scan("eyJa.eyJb.eyJc")
        assert not any(s.secret_id == "JWT_TOKEN" for s in r)

    def test_generic_bearer_token_detected(self, detector):
        r = detector.scan("access_token = " + "A" * 40)
        assert any(s.secret_id == "GENERIC_BEARER_TOKEN" for s in r)


# ════════════════════════════════════════════════════════════════════════════
# DATABASE CREDENTIAL DETECTION
# ════════════════════════════════════════════════════════════════════════════

class TestDatabaseCredentialDetection:
    def test_postgres_url_detected(self, detector):
        r = detector.scan(FAKE_DB_URL)
        assert any(s.secret_id == "DATABASE_URL" for s in r)

    def test_mysql_url_detected(self, detector):
        r = detector.scan("mysql://admin:password123@db.example.com/mydb")
        assert any(s.secret_id == "DATABASE_URL" for s in r)

    def test_mongodb_url_detected(self, detector):
        r = detector.scan("mongodb://user:strongpassword@mongo.example.com/db")
        assert any(s.secret_id == "DATABASE_URL" for s in r)

    def test_redis_url_detected(self, detector):
        r = detector.scan("redis://user:redispassword@cache.example.com:6379")
        assert any(s.secret_id == "DATABASE_URL" for s in r)

    def test_db_url_without_password_not_detected(self, detector):
        # No password — nothing sensitive to flag
        r = detector.scan("postgres://localhost/mydb")
        assert not any(s.secret_id == "DATABASE_URL" for s in r)

    def test_db_url_short_password_filtered(self, detector):
        # Password too short to be real
        r = detector.scan("postgres://user:pw@host/db")
        assert not any(s.secret_id == "DATABASE_URL" for s in r)

    def test_database_category_label(self, detector):
        r = detector.scan(FAKE_DB_URL)
        db = next(s for s in r if s.secret_id == "DATABASE_URL")
        assert db.category == Category.DATABASE


# ════════════════════════════════════════════════════════════════════════════
# ETHICAL GUARDRAIL: no plaintext stored
# ════════════════════════════════════════════════════════════════════════════

class TestEthicalGuardrail:
    def test_returns_DetectedSecret_objects(self, detector):
        results = detector.scan(FAKE_RSA)
        for r in results:
            assert isinstance(r, DetectedSecret)

    def test_no_raw_value_in_result(self, detector):
        results = detector.scan(FAKE_RSA)
        for r in results:
            assert not hasattr(r, "raw_value")
            assert not hasattr(r, "plaintext")
            assert not hasattr(r, "key_body")

    def test_sha256_is_64char_hex(self, detector):
        results = detector.scan(FAKE_OPENSSH)
        for r in results:
            assert len(r.sha256_fingerprint) == 64
            assert all(c in "0123456789abcdef" for c in r.sha256_fingerprint)

    def test_redacted_sample_masks_value(self, detector):
        results = detector.scan(f"token = {FAKE_GITHUB_PAT_CLASSIC}")
        gh = next(s for s in results if s.secret_id == "GITHUB_PAT")
        # Sample has 4 chars + ****
        assert "****" in gh.redacted_sample
        # Should NOT contain the full token
        assert FAKE_GITHUB_PAT_CLASSIC not in gh.redacted_sample

    def test_redacted_sample_shows_type_prefix(self, detector):
        results = detector.scan(f"token = {FAKE_GITHUB_PAT_CLASSIC}")
        gh = next(s for s in results if s.secret_id == "GITHUB_PAT")
        # First 4 chars of "ghp_AAAA..." should be "ghp_"
        assert gh.redacted_sample.startswith("ghp_")

    def test_aws_key_redacted_shows_prefix(self, detector):
        results = detector.scan(f"key = {FAKE_AWS_KEY_ID}")
        aws = next(s for s in results if s.secret_id == "AWS_ACCESS_KEY_ID")
        # First 4 chars of "AKIAIOSFODNN7EXAMPLE" = "AKIA"
        assert aws.redacted_sample.startswith("AKIA")


# ════════════════════════════════════════════════════════════════════════════
# DEDUPLICATION
# ════════════════════════════════════════════════════════════════════════════

class TestDeduplication:
    def test_duplicate_in_same_file_counted_once(self, detector):
        doubled = FAKE_OPENSSH + "\n" + FAKE_OPENSSH
        results = detector.scan(doubled)
        openssh_results = [s for s in results if s.secret_id == "OPENSSH_PRIVATE_KEY"]
        assert len(openssh_results) == 1

    def test_different_types_both_counted(self, detector):
        combined = FAKE_OPENSSH + "\n" + FAKE_RSA
        results = detector.scan(combined)
        ids = {s.secret_id for s in results}
        assert "OPENSSH_PRIVATE_KEY" in ids
        assert "RSA_PRIVATE_KEY" in ids

    def test_fingerprints_unique_across_different_secrets(self, detector):
        combined = FAKE_OPENSSH + "\n" + FAKE_RSA + "\n" + FAKE_EC
        results = detector.scan(combined)
        fps = [s.sha256_fingerprint for s in results]
        assert len(fps) == len(set(fps))


# ════════════════════════════════════════════════════════════════════════════
# FAST PRE-SCREEN (performance gate)
# ════════════════════════════════════════════════════════════════════════════

class TestPrescreen:
    def test_empty_string_returns_empty(self, detector):
        assert detector.scan("") == []

    def test_clean_content_returns_empty(self, detector):
        assert detector.scan(NOT_A_SECRET) == []

    def test_partial_pem_header_no_footer_empty(self, detector):
        assert detector.scan("-----BEGIN RSA PRIVATE KEY-----\nABCD") == []

    def test_contains_secret_true(self, detector):
        assert detector.contains_secret(FAKE_OPENSSH) is True

    def test_contains_secret_false(self, detector):
        assert detector.contains_secret(NOT_A_SECRET) is False

    def test_contains_secret_empty(self, detector):
        assert detector.contains_secret("") is False

    def test_contains_key_backward_compat(self, detector):
        # contains_key() is an alias for contains_secret()
        assert detector.contains_key(FAKE_RSA) is True
        assert detector.contains_key(NOT_A_SECRET) is False


# ════════════════════════════════════════════════════════════════════════════
# UTILITY METHODS
# ════════════════════════════════════════════════════════════════════════════

class TestUtilityMethods:
    def test_estimate_key_count_pem_only(self, detector):
        combined = FAKE_OPENSSH + FAKE_RSA + FAKE_EC
        assert detector.estimate_key_count_in_file(combined) == 3

    def test_estimate_key_count_zero_no_pem(self, detector):
        # AWS key is not a PEM block — count should be 0
        assert detector.estimate_key_count_in_file(FAKE_AWS_KEY_ID) == 0

    def test_estimate_key_count_empty(self, detector):
        assert detector.estimate_key_count_in_file("") == 0

    def test_group_by_category(self, detector):
        combined = FAKE_OPENSSH + "\n" + f"key = {FAKE_AWS_KEY_ID}" + "\n" + f"token = {FAKE_GITHUB_PAT_CLASSIC}"
        results = detector.scan(combined)
        groups = KeyDetector.group_by_category(results)
        assert Category.PRIVATE_KEY in groups
        assert Category.CLOUD in groups
        assert Category.VCS_TOKEN in groups

    def test_all_search_queries_returns_dict(self):
        q = KeyDetector.all_search_queries()
        assert isinstance(q, dict)
        assert len(q) >= 20    # at least 20 secret types defined
        assert "OPENSSH_PRIVATE_KEY" in q
        assert "AWS_ACCESS_KEY_ID" in q
        assert "GITHUB_PAT" in q
        assert "STRIPE_SECRET_KEY" in q

    def test_all_search_queries_no_empty_values(self):
        q = KeyDetector.all_search_queries()
        for key, val in q.items():
            assert val, f"Empty search query for {key}"

    def test_categories_returns_all_six(self):
        cats = KeyDetector.categories()
        assert Category.PRIVATE_KEY in cats
        assert Category.CLOUD in cats
        assert Category.API_KEY in cats
        assert Category.VCS_TOKEN in cats
        assert Category.OAUTH_TOKEN in cats
        assert Category.DATABASE in cats

    def test_confidence_levels_valid(self):
        from src.key_detector import _SECRET_DEFS
        valid = {"high", "medium", "low"}
        for d in _SECRET_DEFS:
            assert d["confidence"] in valid, f"{d['id']} has invalid confidence: {d['confidence']}"

    def test_all_definitions_have_required_fields(self):
        from src.key_detector import _SECRET_DEFS
        required = {"id", "category", "label", "pattern", "confidence",
                    "search_query", "min_length", "max_length"}
        for d in _SECRET_DEFS:
            missing = required - set(d.keys())
            assert not missing, f"{d.get('id','?')} missing fields: {missing}"
