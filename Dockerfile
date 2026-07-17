# syntax=docker/dockerfile:1.7
FROM ghcr.io/astral-sh/uv:0.11.16 AS uv

FROM python:3.14-slim-bookworm AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    PATH=/app/.venv/bin:$PATH \
    PYTHONPATH=/app/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates \
        dnsmasq-base \
        iproute2 \
        nftables \
        openssh-client \
        wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY VERSION ./
COPY src ./src
# sshuttle's fixed CLI calls this method "tproxy". Replace that method module
# with shuttle-gate's native nftables implementation; no legacy firewall
# frontend is installed in this image.
RUN cp /app/src/shuttle_gate/sshuttle_method_shim.py \
    /app/.venv/lib/python3.14/site-packages/sshuttle/methods/tproxy.py

ENTRYPOINT ["python", "-m", "shuttle_gate"]
CMD ["--help"]

FROM runtime AS test
RUN uv sync --frozen --group dev --no-install-project
COPY shuttle-gate test config.example.yaml docker-compose.yml ./
COPY tests ./tests
