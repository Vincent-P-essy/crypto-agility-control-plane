# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89

ARG PYTHON_IMAGE=python:3.12.13-slim-trixie@sha256:423ed6ab25b1921a477529254bfeeabf5855151dc2c3141699a1bfc852199fbf

FROM ${PYTHON_IMAGE} AS oqs-builder
ARG LIBOQS_VERSION=0.16.0
ARG LIBOQS_SHA256=162d5b510518ee5f285f82fa1f16402a885176e818bf1b1a4c3c91c9a2f01eae
RUN apt-get update \
    && apt-get install --yes --no-install-recommends build-essential ca-certificates cmake curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
RUN curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
      "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VERSION}.tar.gz" \
      --output liboqs.tar.gz \
    && printf '%s  %s\n' "${LIBOQS_SHA256}" liboqs.tar.gz | sha256sum --check --status \
    && tar -xzf liboqs.tar.gz \
    && cmake -S "liboqs-${LIBOQS_VERSION}" -B output \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/opt/oqs \
      -DBUILD_SHARED_LIBS=ON \
      -DOQS_BUILD_ONLY_LIB=ON \
      -DOQS_DIST_BUILD=ON \
      -DOQS_USE_OPENSSL=OFF \
      -DOQS_MINIMAL_BUILD='KEM_ml_kem_768;SIG_ml_dsa_65' \
    && cmake --build output --parallel 2 \
    && cmake --install output \
    && test -f /opt/oqs/lib/liboqs.so.0.16.0

FROM ${PYTHON_IMAGE} AS python-builder
ARG UV_VERSION=0.11.28
RUN python -m pip install --no-cache-dir "uv==${UV_VERSION}"
ENV UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /build
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
COPY data ./data
COPY config ./config
COPY schemas ./schemas
RUN uv sync --frozen --no-dev --no-editable --compile-bytecode

FROM ${PYTHON_IMAGE} AS runtime
LABEL org.opencontainers.image.title="crypto-agility-control-plane" \
      org.opencontainers.image.description="Evidence-driven cryptographic inventory and measured PQC migration lab" \
      org.opencontainers.image.source="https://github.com/Vincent-P-essy/crypto-agility-control-plane" \
      org.opencontainers.image.licenses="MIT"
RUN groupadd --gid 10001 crypto-agility \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin crypto-agility \
    && mkdir -p /app /state \
    && chown 10001:10001 /state
COPY --from=oqs-builder /opt/oqs /opt/oqs
COPY --from=python-builder /app/.venv /app/.venv
COPY --chown=10001:10001 fixtures /app/fixtures
ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    OQS_INSTALL_PATH=/opt/oqs \
    LD_LIBRARY_PATH=/opt/oqs/lib \
    CAP_STATE_DIR=/state \
    CAP_ALLOWED_ROOTS=/app/fixtures
WORKDIR /app
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=20s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).read()"]
ENTRYPOINT ["crypto-agility"]
CMD ["api", "--host", "0.0.0.0", "--port", "8080", "--state-dir", "/state", "--allowed-root", "/app/fixtures", "--oqs-install-path", "/opt/oqs"]
