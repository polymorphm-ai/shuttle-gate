"""Deterministic WireGuard and phone configuration rendering."""

from __future__ import annotations

import json
from collections.abc import Mapping
from hashlib import sha256
from ipaddress import IPv6Address, ip_address

from .config import PeerConfig, ProjectConfig, effective_routes


def endpoint(config: ProjectConfig) -> str:
    """Render a WireGuard endpoint with correct IPv6 brackets."""

    host = config.wireguard.endpoint_host
    try:
        address = ip_address(host)
    except ValueError:
        rendered_host = host
    else:
        rendered_host = f"[{address}]" if isinstance(address, IPv6Address) else str(address)
    return f"{rendered_host}:{config.wireguard.listen_port}"


def peer_allowed_routes(config: ProjectConfig) -> tuple[str, ...]:
    """Return deterministic phone AllowedIPs."""

    networks = list(effective_routes(config))
    return tuple(str(network) for network in networks)


def render_server_config(
    config: ProjectConfig,
    server_private_key: str,
    peer_keys: Mapping[str, tuple[str, str]],
) -> str:
    """Render the private configuration consumed by ``wg setconf``."""

    lines = [
        "[Interface]",
        f"PrivateKey = {server_private_key}",
        f"ListenPort = {config.wireguard.listen_port}",
    ]
    for peer in config.wireguard.peers:
        public_key, preshared_key = peer_keys[peer.name]
        lines.extend(
            [
                "",
                "[Peer]",
                f"# {peer.name}",
                f"PublicKey = {public_key}",
                f"PresharedKey = {preshared_key}",
                "AllowedIPs = " + ", ".join(str(address) for address in peer.addresses),
            ]
        )
    return "\n".join(lines) + "\n"


def render_phone_config(
    config: ProjectConfig,
    peer: PeerConfig,
    server_public_key: str,
    peer_private_key: str,
    preshared_key: str,
) -> str:
    """Render an official WireGuard client configuration."""

    lines = [
        "[Interface]",
        f"PrivateKey = {peer_private_key}",
        "Address = " + ", ".join(str(address) for address in peer.addresses),
    ]
    if config.dns.enabled and config.dns.upstream is not None:
        lines.append(f"DNS = {config.dns.upstream}")
    lines.extend(
        [
            "",
            "[Peer]",
            f"PublicKey = {server_public_key}",
            f"PresharedKey = {preshared_key}",
            f"Endpoint = {endpoint(config)}",
            "AllowedIPs = " + ", ".join(peer_allowed_routes(config)),
            f"PersistentKeepalive = {peer.persistent_keepalive_seconds}",
        ]
    )
    return "\n".join(lines) + "\n"


def phone_fingerprint(
    config: ProjectConfig,
    peer: PeerConfig,
    server_public_key: str,
    peer_public_key: str,
    preshared_key: str,
) -> str:
    """Hash all values whose change requires phone configuration re-import."""

    value = {
        "addresses": [str(address) for address in peer.addresses],
        "allowed_routes": list(peer_allowed_routes(config)),
        "dns": str(config.dns.upstream) if config.dns.enabled else None,
        "endpoint": endpoint(config),
        "keepalive": peer.persistent_keepalive_seconds,
        "peer_public_key": peer_public_key,
        "preshared_key_digest": sha256(preshared_key.encode("ascii")).hexdigest(),
        "server_public_key": server_public_key,
    }
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(encoded).hexdigest()
