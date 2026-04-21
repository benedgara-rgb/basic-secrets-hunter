# ═══════════════════════════════════════════════════════════════════════════
# CTI SSH Key Hunter — Dockerfile
#
# Base image: python:3.11-slim-bookworm
#   • Debian 12 (Bookworm) — stable, well-patched base
#   • slim variant — ~150 MB vs ~900 MB for full image; minimal CVE surface
#   • python:3.11 — modern Python with active security support until 2027
#   • Alternative: python:3.11-alpine (ultra-small ~50 MB but some PyPI
#     wheels need recompilation; use if image size is critical)
#
# Pattern: multi-stage build
#   Stage 1 (builder) — installs build tools and compiles dependencies
#   Stage 2 (runtime) — copies only the venv; no build tools in final image
#
# Security posture:
#   • Non-root user (UID/GID 1000) — principle of least privilege
#   • No secrets baked in — credentials always injected at runtime
#   • Read-only filesystem supported (tmpfs for /tmp via docker-compose)
#   • Explicit COPY ordering for maximum layer cache efficiency
# ═══════════════════════════════════════════════════════════════════════════

# ──────────────────────────────────────────────────────────────────────────
# STAGE 1: builder
# Installs Python dependencies into an isolated virtual environment.
# Build tools (gcc, pip) stay in this stage and are excluded from the
# final image, dramatically reducing the attack surface.
# ──────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm AS builder

# Set working directory for the build stage
WORKDIR /build

# Install only the OS packages required to compile Python C extensions.
# --no-install-recommends keeps the layer lean.
# Clean apt lists immediately to avoid bloating this layer.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create an isolated virtual environment — prevents system Python pollution
# and makes the whole dependency tree copyable as a single directory tree.
RUN python -m venv /opt/venv

# Activate the venv for all subsequent RUN commands in this stage
ENV PATH="/opt/venv/bin:$PATH"

# ── Copy only the requirements file first.
# Docker caches layers: if requirements.txt hasn't changed, pip install
# is skipped on subsequent builds, saving significant time in CI/CD.
COPY requirements.txt .

# Upgrade pip silently, then install pinned dependencies.
# --no-cache-dir reduces layer size by ~20%.
RUN pip install --upgrade pip --quiet \
    && pip install --no-cache-dir -r requirements.txt


# ──────────────────────────────────────────────────────────────────────────
# STAGE 2: runtime (final image)
# Copies only the application code and the pre-built venv.
# No compiler, no build tools, no pip — minimal attack surface.
# ──────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm AS runtime

# ── Labels for image metadata and registry discoverability ────────────────
LABEL org.opencontainers.image.title="CTI SSH Key Hunter" \
      org.opencontainers.image.description="Ethical GitHub SSH key exposure scanner with threat actor trend analysis" \
      org.opencontainers.image.authors="CTI Research Team" \
      org.opencontainers.image.source="https://github.com/your-org/cti-ssh-hunter" \
      org.opencontainers.image.licenses="MIT"

# ── Non-root user setup ───────────────────────────────────────────────────
# Never run application containers as root.  Create a dedicated user and
# group with fixed UID/GID 1000 for reproducibility across environments.
RUN groupadd --gid 1000 ctiuser \
    && useradd  --uid 1000 \
                --gid 1000 \
                --no-create-home \
                --shell /bin/false \
                ctiuser

# ── Application directory structure ──────────────────────────────────────
# /app       — application source code (read-only at runtime)
# /app/output — report output (mounted as volume in production)
# /app/logs   — optional log volume
RUN mkdir -p /app/output /app/logs \
    && chown -R ctiuser:ctiuser /app

WORKDIR /app

# ── Copy the compiled virtual environment from the builder stage ──────────
# This single COPY brings in all Python packages without any build tools.
COPY --from=builder /opt/venv /opt/venv

# ── Copy application source code ──────────────────────────────────────────
# Ordered from least-to-most-frequently-changed for cache efficiency.
# src/ is copied last because it changes on every code edit.
COPY --chown=ctiuser:ctiuser src/ ./src/

# ── Activate the virtual environment for the container's PATH ─────────────
ENV PATH="/opt/venv/bin:$PATH" \
    # Prevent Python from writing .pyc bytecode to disk (read-only fs friendly)
    PYTHONDONTWRITEBYTECODE=1 \
    # Force stdout/stderr to be unbuffered — critical for log streaming in Docker
    PYTHONUNBUFFERED=1 \
    # Default configuration (overridden via docker run -e or docker-compose)
    LOG_LEVEL=INFO \
    OUTPUT_DIR=/app/output \
    RATE_LIMIT_PAUSE=6.5

# ── Drop to non-root user ──────────────────────────────────────────────────
# All subsequent instructions and the container process run as ctiuser.
USER ctiuser

# ── Expose health endpoint port ───────────────────────────────────────────
# The lightweight HTTP health server listens on 8080 when
# --enable-health flag or ENABLE_HEALTH_ENDPOINT=true is set.
EXPOSE 8080

# ── Docker health check ───────────────────────────────────────────────────
# Verifies the GitHub API token is valid and the scanner can authenticate.
# start_period gives the app 15s to initialise before health checks begin.
HEALTHCHECK --interval=30s \
            --timeout=10s \
            --start-period=15s \
            --retries=3 \
    CMD python -c "import urllib.request, json, sys; \
        r=urllib.request.urlopen('http://localhost:8080/health',timeout=5); \
        d=json.loads(r.read()); \
        sys.exit(0 if d.get('status')=='ok' else 1)" \
    || exit 1

# ── Default entrypoint ────────────────────────────────────────────────────
# Run the scanner as a Python module so relative imports resolve correctly.
# All CLI arguments can be appended: docker run <image> --key-types RSA
ENTRYPOINT ["python", "-m", "src.main"]

# ── Default arguments (can be overridden on docker run command line) ──────
CMD ["--enable-health"]
