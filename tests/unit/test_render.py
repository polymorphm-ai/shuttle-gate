from __future__ import annotations

from copy import deepcopy

from shuttle_gate.config import ProjectConfig
from shuttle_gate.render import (
    endpoint,
    peer_allowed_routes,
    phone_fingerprint,
    render_phone_config,
    render_server_config,
)

from .conftest import config_data


def test_endpoint_formats_ipv6_literal() -> None:
    data = config_data()
    data["wireguard"]["endpoint_host"] = "2001:db8::10"
    config = ProjectConfig.model_validate(data)

    assert endpoint(config) == "[2001:db8::10]:51820"


def test_phone_config_contains_dual_stack_dns_routes_and_no_server_private_key(
    config: ProjectConfig,
) -> None:
    peer = config.wireguard.peers[0]
    rendered = render_phone_config(config, peer, "server-public", "phone-private", "psk")

    assert "PrivateKey = phone-private" in rendered
    assert "Address = 10.77.0.2/32, fd77::2/128" in rendered
    assert "DNS = 10.77.0.1, fd77::1" in rendered
    assert "Endpoint = gate.example.test:51820" in rendered
    assert "AllowedIPs = 10.0.0.0/8, fd20:1234::/48" in rendered
    assert "server-private" not in rendered


def test_dns_gateway_route_is_added_when_not_covered() -> None:
    data = config_data()
    data["routing"]["networks"] = ["192.168.0.0/16", "fd20:1234::/48"]
    data["dns"]["upstream"] = "fd20:1234::53"
    config = ProjectConfig.model_validate(data)

    assert peer_allowed_routes(config) == (
        "192.168.0.0/16",
        "fd20:1234::/48",
        "10.77.0.1/32",
        "fd77::1/128",
    )


def test_server_config_contains_only_public_peer_material(config: ProjectConfig) -> None:
    rendered = render_server_config(
        config,
        "server-private",
        {"phone": ("phone-public", "phone-psk"), "tablet": ("tablet-public", "tablet-psk")},
    )

    assert rendered.count("[Peer]") == 2
    assert "AllowedIPs = 10.77.0.2/32, fd77::2/128" in rendered
    assert "phone-private" not in rendered


def test_fingerprint_changes_for_operator_visible_phone_setting(config: ProjectConfig) -> None:
    peer = config.wireguard.peers[0]
    first = phone_fingerprint(config, peer, "server", "peer", "psk")
    data = deepcopy(config_data())
    data["wireguard"]["endpoint_host"] = "other.example.test"
    changed = ProjectConfig.model_validate(data)

    second = phone_fingerprint(changed, changed.wireguard.peers[0], "server", "peer", "psk")
    assert first != second
