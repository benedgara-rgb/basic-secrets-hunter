# CTI Secrets Hunter

A production-ready Cyber Threat Intelligence tool for identifying exposed secrets and credentials on GitHub. Detects **30 secret types across 6 categories** — private keys, cloud credentials (AWS/GCP/Azure), API keys, VCS tokens, OAuth/JWT, and database connection strings. Classifies findings as **leaked/stolen** (threat actor dumps) or **accidental commits** (developers who need notification), and performs behavioral trend analysis to profile threat actor infrastructure.

> **Ethical Use Only.** This tool is designed for security researchers, threat intelligence analysts, and responsible disclosure programs. Secret values are never stored — only SHA-256 fingerprints and redacted samples (`prefix****`). See [Ethical Guardrails](#ethical-guardrails).

## Supported Secret Types

| Category | Secret Types |
|----------|-------------|
| 🔑 **Private Keys** | OpenSSH, RSA, EC, DSA, PKCS#8, Encrypted PKCS#8, PGP |
| ☁️ **Cloud Credentials** | AWS Access Key ID + Secret, GCP Service Account + API Key + OAuth Client Secret, Azure Client Secret + Connection String |
| 🔐 **API Keys** | Stripe (live/test/restricted), Twilio SID + Auth Token, SendGrid, Slack, Telegram, Mailgun, Heroku |
| 🔗 **VCS / Registry Tokens** | GitHub PAT (classic + fine-grained), GitLab PAT, NPM, PyPI |
| 🎫 **OAuth / JWT** | JWT tokens, Generic Bearer / Access tokens |
| 🗄️ **Database** | Connection strings with embedded credentials (Postgres, MySQL, MongoDB, Redis, MSSQL, Oracle) |

Run `python -m src.main --list-secrets` to see every type with confidence tier.

---

## Features

| Capability | Description |
|-----------|-------------|
| 🔍 **Key Detection** | Regex-based detection of OPENSSH, RSA, EC, DSA, PKCS8 private keys |
| 🏷️ **Classification** | Heuristic scoring: LEAKED vs ACCIDENTAL vs UNCERTAIN |
| 📊 **Trend Analysis** | Account profiling, naming patterns, language distribution, temporal heatmaps |
| 📧 **Disclosure Targets** | CSV of accidental committers for responsible notification |
| 🔒 **No Key Storage** | Only SHA-256 fingerprints stored — never plaintext key material |
| 🐳 **Docker-Ready** | Multi-stage build, non-root user, read-only filesystem |
| ⚡ **Rate-Limit Safe** | Exponential backoff, configurable delay, respects GitHub API limits |

---

## Quick Start

### Option 1: Docker (Recommended)

```bash
# 1. Clone the repository
git clone https://github.com/your-org/cti-ssh-hunter.git
cd cti-ssh-hunter

# 2. Configure your GitHub token
cp .env.example .env
# Edit .env and set GITHUB_TOKEN=ghp_your_token_here

# 3. Create output directory
mkdir -p output logs

# 4. Build the image
docker build -t cti-ssh-hunter:latest .

# 5. Run a scan
docker run --rm \
  --env-file .env \
  -v $(pwd)/output:/app/output \
  cti-ssh-hunter:latest

# 6. View reports
ls -la output/
```

### Option 2: Docker Compose

```bash
cp .env.example .env
# Edit .env — set GITHUB_TOKEN

mkdir -p output logs
docker-compose up
```

### Option 3: Local Python

```bash
# Python 3.11+ required
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
# Edit .env — set GITHUB_TOKEN

python -m src.main
```

---

## GitHub Token Setup

1. Go to [GitHub Settings → Tokens (classic)](https://github.com/settings/tokens/new)
2. Select scope: **`public_repo`** (read-only access to public repositories)
3. No write permissions are needed or should be granted
4. Copy the token to your `.env` file

For fine-grained tokens: **Contents: Read-only** on public repositories.

---

## CLI Usage

```bash
# Scan all key types (default)
python -m src.main

# Scan specific key types only
python -m src.main --key-types OPENSSH RSA

# Limit results (faster for testing)
python -m src.main --max-results 100

# Verbose debug logging
python -m src.main --log-level DEBUG

# Health endpoint only (no scan — useful for container readiness checks)
python -m src.main --health-only

# Full options
python -m src.main --help
```

### Docker Run Examples

```bash
# Basic scan
docker run --rm \
  -e GITHUB_TOKEN=ghp_xxxxxxxxxxxxx \
  -v $(pwd)/output:/app/output \
  cti-ssh-hunter:latest

# With .env file
docker run --rm \
  --env-file .env \
  -v $(pwd)/output:/app/output \
  cti-ssh-hunter:latest

# Specific key types + debug logging
docker run --rm \
  --env-file .env \
  -v $(pwd)/output:/app/output \
  cti-ssh-hunter:latest \
  --key-types OPENSSH RSA --log-level DEBUG

# Run test suite inside container
docker run --rm \
  -e GITHUB_TOKEN=ghp_test_dummy \
  --entrypoint python \
  cti-ssh-hunter:latest \
  -m pytest tests/ -v

# Security scan the image with Trivy
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image cti-ssh-hunter:latest
```

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GITHUB_TOKEN` | ✅ Yes | — | GitHub PAT with `public_repo` read scope |
| `LOG_LEVEL` | No | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `OUTPUT_DIR` | No | `/app/output` | Report output directory |
| `RATE_LIMIT_PAUSE` | No | `6.5` | Seconds between API requests |
| `MAX_RESULTS` | No | `1000` | Max results per key-type query |
| `ENABLE_HEALTH_ENDPOINT` | No | `false` | Start HTTP `/health` on port 8080 |
| `HEALTH_PORT` | No | `8080` | Health endpoint port |

---

## Output Files

Each scan produces three files in `OUTPUT_DIR`, timestamped in UTC:

### `findings_YYYYMMDDTHHMMSSZ.json`
Complete findings record. Contains all metadata per finding. **No key material.**

```json
{
  "metadata": {
    "total_findings": 47,
    "leaked_count": 31,
    "accidental_count": 12,
    "uncertain_count": 4
  },
  "findings": [
    {
      "classification": "LEAKED",
      "confidence_score": 0.85,
      "signals": ["repo name contains dump keyword 'stealer'", "account only 7 days old"],
      "repo_url": "https://github.com/...",
      "file_path": "logs/ssh_keys.txt",
      "commit_sha": "abc123...",
      "key_count": 84,
      "key_sha256_fingerprints": ["3f4a..."],
      "owner_login": "xk7f2mzq91"
    }
  ]
}
```

### `disclosure_targets_YYYYMMDDTHHMMSSZ.csv`
Responsible-disclosure mailing list. **ACCIDENTAL and UNCERTAIN findings only.**
Contains developer email addresses for notification. LEAKED findings excluded.

```csv
author_email,author_name,repo_url,file_path,commit_sha,classification,key_count
dev@example.com,Jane Dev,https://github.com/jdev/api,.ssh/id_rsa,def456,ACCIDENTAL,1
```

### `trend_analysis_YYYYMMDDTHHMMSSZ.md`
Human-readable analytical summary for LEAKED findings. Includes account profiles,
naming patterns, language distribution, temporal heatmaps, and threat actor assessment.
**No email addresses in this file — aggregated/anonymised data only.**

---

## Architecture

```
cti-ssh-hunter/
├── src/
│   ├── api_client.py      # GitHub API + rate limiting + exponential backoff
│   ├── key_detector.py    # Regex detection + SHA-256 hashing (no plaintext stored)
│   ├── classifier.py      # LEAKED vs ACCIDENTAL heuristic scoring
│   ├── trend_analyzer.py  # Account profiling + temporal + volumetric analysis
│   ├── reporter.py        # JSON / CSV / Markdown report generation
│   └── main.py            # CLI orchestration + signal handling + health endpoint
├── tests/
│   ├── test_key_detector.py
│   ├── test_classifier.py
│   ├── test_trend_analyzer.py
│   ├── test_api_client.py
│   └── test_reporter.py
├── sample_output/
│   └── trend_analysis_sample.json
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
├── .env.example
└── requirements.txt
```

---

## Running Tests

```bash
# Local
pytest tests/ -v --cov=src --cov-report=term-missing

# Inside Docker (no live network calls — all mocked)
docker run --rm \
  -e GITHUB_TOKEN=ghp_test_dummy \
  --entrypoint python \
  cti-ssh-hunter:latest \
  -m pytest tests/ -v --cov=src

# Via docker-compose
docker-compose run --rm test
```

Tests use `unittest.mock` throughout — **no live GitHub API calls are made.**
Coverage target: ≥ 80%.

---

## Security Scanning

```bash
# Scan image for CVEs with Trivy (recommended)
trivy image cti-ssh-hunter:latest

# Or via Docker
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image cti-ssh-hunter:latest

# Scan for CRITICAL and HIGH severity only
trivy image --severity CRITICAL,HIGH cti-ssh-hunter:latest
```

---

## Ethical Guardrails

This tool is built with the following non-negotiable constraints:

| Guardrail | Implementation |
|-----------|---------------|
| **No key storage** | `key_detector.py` hashes key material with SHA-256 immediately and discards plaintext. The hash is never used to reconstruct the key — only for deduplication. |
| **Read-only API** | Token requires only `public_repo` read scope. No write operations exist in the codebase. |
| **Rate limiting** | Default 6.5s delay between requests. Exponential backoff on 403/429 responses. Respects `X-RateLimit-Reset` headers. |
| **No email in trend reports** | Author email addresses appear only in `disclosure_targets.csv` — never in the aggregated trend analysis Markdown. |
| **Responsible disclosure intent** | ACCIDENTAL findings are separated specifically so developers can be notified to rotate their keys. |

---

## Recommended Resource Limits

```bash
# Docker run with resource constraints
docker run --rm \
  --memory=512m \
  --cpus=1.0 \
  --env-file .env \
  -v $(pwd)/output:/app/output \
  cti-ssh-hunter:latest
```

For Kubernetes, see `DEPLOYMENT.md`.

---

## Disclaimer

This tool is intended for authorized security research, threat intelligence analysis, and responsible disclosure programs. Users are responsible for ensuring their use complies with applicable laws, GitHub's Terms of Service, and their organization's policies. The authors are not responsible for misuse.
