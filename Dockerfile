FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates git jq \
    && rm -rf /var/lib/apt/lists/*

# Semgrep (PyPI)
RUN pip install --no-cache-dir semgrep

# Gitleaks (release binary)
ARG GITLEAKS_VERSION=8.30.1
RUN curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks

# OSV-Scanner (release binary)
ARG OSV_SCANNER_VERSION=2.5.1
RUN curl -sSL -o /usr/local/bin/osv-scanner \
    "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" \
    && chmod +x /usr/local/bin/osv-scanner

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# No USER directive by design: GitHub requires Docker container actions to run
# as root — the runner mounts GITHUB_WORKSPACE and the output files with
# root-owned paths, and a non-root USER breaks them. This container only ever
# runs inside the ephemeral Actions VM. (Scanner false-positive: suppress.)
ENTRYPOINT ["/entrypoint.sh"]
