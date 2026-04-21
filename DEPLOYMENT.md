# Deployment Guide — CTI SSH Key Hunter

---

## Container Registry Publishing

### GitHub Container Registry (ghcr.io)

```bash
# Authenticate
echo $GITHUB_TOKEN | docker login ghcr.io -u YOUR_GITHUB_USERNAME --password-stdin

# Build and tag
docker build -t ghcr.io/YOUR_ORG/cti-ssh-hunter:latest .
docker build -t ghcr.io/YOUR_ORG/cti-ssh-hunter:v1.0.0 .

# Push
docker push ghcr.io/YOUR_ORG/cti-ssh-hunter:latest
docker push ghcr.io/YOUR_ORG/cti-ssh-hunter:v1.0.0
```

### Docker Hub

```bash
docker login
docker build -t YOUR_DOCKERHUB_USER/cti-ssh-hunter:latest .
docker push YOUR_DOCKERHUB_USER/cti-ssh-hunter:latest
```

---

## Kubernetes Deployment

### Secret (GitHub Token)

```yaml
# k8s/secret.yaml
# Create with: kubectl create secret generic cti-ssh-hunter-secrets \
#   --from-literal=github-token=ghp_your_token_here
apiVersion: v1
kind: Secret
metadata:
  name: cti-ssh-hunter-secrets
  namespace: security-tools
type: Opaque
stringData:
  github-token: "ghp_your_token_here"  # Replace — never commit real token
```

### CronJob (Scheduled Scans)

```yaml
# k8s/cronjob.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: cti-ssh-hunter
  namespace: security-tools
spec:
  # Run daily at 02:00 UTC
  schedule: "0 2 * * *"
  concurrencyPolicy: Forbid          # Never run two scans simultaneously
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 3
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure

          # Run as non-root (matches Dockerfile UID 1000)
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            runAsGroup: 1000
            fsGroup: 1000

          containers:
            - name: hunter
              image: ghcr.io/YOUR_ORG/cti-ssh-hunter:latest
              imagePullPolicy: Always

              args:
                - "--key-types"
                - "OPENSSH"
                - "RSA"
                - "EC"
                - "DSA"
                - "--enable-health"

              env:
                - name: GITHUB_TOKEN
                  valueFrom:
                    secretKeyRef:
                      name: cti-ssh-hunter-secrets
                      key: github-token
                - name: LOG_LEVEL
                  value: "INFO"
                - name: OUTPUT_DIR
                  value: "/app/output"
                - name: RATE_LIMIT_PAUSE
                  value: "6.5"

              # Resource limits — prevent runaway scan from consuming cluster resources
              resources:
                requests:
                  memory: "128Mi"
                  cpu: "250m"
                limits:
                  memory: "512Mi"
                  cpu: "1000m"

              # Security hardening
              securityContext:
                allowPrivilegeEscalation: false
                readOnlyRootFilesystem: true
                capabilities:
                  drop:
                    - ALL

              volumeMounts:
                - name: output
                  mountPath: /app/output
                - name: tmp
                  mountPath: /tmp

              # Liveness probe using the built-in health endpoint
              livenessProbe:
                httpGet:
                  path: /health
                  port: 8080
                initialDelaySeconds: 15
                periodSeconds: 30
                timeoutSeconds: 10
                failureThreshold: 3

          volumes:
            - name: output
              persistentVolumeClaim:
                claimName: cti-ssh-hunter-output
            - name: tmp
              emptyDir:
                medium: Memory
                sizeLimit: 64Mi
```

### PersistentVolumeClaim (Report Storage)

```yaml
# k8s/pvc.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: cti-ssh-hunter-output
  namespace: security-tools
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 5Gi
  storageClassName: standard
```

### Apply to cluster

```bash
kubectl create namespace security-tools

kubectl apply -f k8s/secret.yaml
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/cronjob.yaml

# Trigger a manual run immediately
kubectl create job --from=cronjob/cti-ssh-hunter cti-ssh-hunter-manual -n security-tools

# Watch logs
kubectl logs -f -l job-name=cti-ssh-hunter-manual -n security-tools

# Retrieve reports
kubectl cp security-tools/$(kubectl get pods -n security-tools -l job-name=cti-ssh-hunter-manual -o name | head -1 | cut -d/ -f2):/app/output ./output
```

---

## Resource Limit Recommendations

| Deployment | Memory | CPU | Notes |
|-----------|--------|-----|-------|
| Local dev  | 256 MB | 0.5 | `--max-results 100` for quick tests |
| CI/CD      | 256 MB | 0.5 | Mocked tests only — no API calls |
| Full scan  | 512 MB | 1.0 | All key types, 1000 results/type |
| Scheduled  | 512 MB | 1.0 | Recommended for production cron |

---

## Production Security Checklist

### Image Security
- [ ] Base image pinned to specific digest (not just `slim-bookworm` tag)
- [ ] Trivy scan passes with no CRITICAL CVEs before deployment
- [ ] Image signed with cosign or Notary
- [ ] Multi-platform build tested (amd64 + arm64 if needed)

### Secret Management
- [ ] `GITHUB_TOKEN` stored in Kubernetes Secret or external vault (HashiCorp Vault, AWS Secrets Manager)
- [ ] Token has minimum required scope: `public_repo` read-only
- [ ] Token rotated on a schedule (90-day maximum recommended)
- [ ] No secrets in environment variables visible via `docker inspect`

### Runtime Security
- [ ] Container runs as UID 1000 (non-root)
- [ ] `readOnlyRootFilesystem: true` enforced
- [ ] `allowPrivilegeEscalation: false`
- [ ] All Linux capabilities dropped (`drop: [ALL]`)
- [ ] Network policy restricts egress to `api.github.com` and `raw.githubusercontent.com` only

### Output Security
- [ ] Output volume has appropriate filesystem permissions (750)
- [ ] `disclosure_targets.csv` treated as sensitive PII — restrict access
- [ ] Reports are not publicly accessible (no web-facing storage bucket)
- [ ] Retention policy in place for old reports

### Operational
- [ ] Health endpoint (`/health`) monitored by alerting system
- [ ] Log output shipped to SIEM
- [ ] Scan results reviewed by a human analyst before any disclosure emails are sent
- [ ] Incident response plan in place if a false-positive disclosure is sent

---

## Upgrading

```bash
# Pull latest image
docker pull ghcr.io/YOUR_ORG/cti-ssh-hunter:latest

# Or rebuild from source
docker build --no-cache -t cti-ssh-hunter:latest .

# In Kubernetes — rolling update
kubectl set image cronjob/cti-ssh-hunter \
  hunter=ghcr.io/YOUR_ORG/cti-ssh-hunter:v1.1.0 \
  -n security-tools
```
