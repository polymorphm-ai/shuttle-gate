# syntax=docker/dockerfile:1.7
ARG PYTHON_VERSION=3.14
FROM ghcr.io/astral-sh/uv:0.11.16 AS uv

FROM python:${PYTHON_VERSION}-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        iproute2 \
        nftables \
        openssh-client \
        wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app
COPY test test.lock ./
RUN ./test --prepare-environment

COPY pyproject.toml config.example.yaml docker-compose.yml ./
COPY src ./src
COPY tests ./tests

ENV UV_OFFLINE=1
ENTRYPOINT ["./test", "--container-integration"]
