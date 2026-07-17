# syntax=docker/dockerfile:1.7
ARG PYTHON_VERSION=3.14
FROM ghcr.io/astral-sh/uv:0.11.16 AS uv

FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

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
RUN python -c \
    "from pathlib import Path; from sshuttle import methods; \
    source = Path('/app/src/shuttle_gate/sshuttle_method_shim.py'); \
    target = Path(methods.__file__).with_name('tproxy.py'); \
    target.write_bytes(source.read_bytes())"

ENTRYPOINT ["python", "-m", "shuttle_gate"]
CMD ["--help"]

FROM runtime AS test
RUN uv sync --frozen --group dev --no-install-project
COPY shuttle-gate test config.example.yaml docker-compose.yml ./
COPY tests ./tests
