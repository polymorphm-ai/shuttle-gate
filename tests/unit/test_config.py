from __future__ import annotations

from copy import deepcopy
from ipaddress import IPv4Network, IPv6Network
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from shuttle_gate.config import ProjectConfig, effective_routes, load_config
from shuttle_gate.errors import ConfigurationError

from .conftest import config_data


def test_valid_dual_stack_config_is_immutable() -> None:
    config = ProjectConfig.model_validate(config_data())

    assert config.project == "test-gate"
    assert [address.version for address in config.wireguard.gateway_addresses] == [4, 6]
    with pytest.raises(ValidationError):
        config.project = "changed"


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda data: data.update(version=2), "expected 1"),
        (lambda data: data.update(project="Bad_Name"), "must match"),
        (lambda data: data["wireguard"].update(bind_addresses=["0.0.0.0"]), "unicast"),
        (lambda data: data["wireguard"].update(endpoint_host="bad host"), "valid DNS"),
        (
            lambda data: data["wireguard"]["gateway_addresses"].append("10.78.0.1/24"),
            "at most one",
        ),
        (
            lambda data: data["wireguard"]["peers"][1].update(addresses=["10.77.0.2/32"]),
            "duplicate peer address",
        ),
        (
            lambda data: data["wireguard"]["peers"][0].update(addresses=["10.88.0.2/32"]),
            "outside gateway network",
        ),
        (
            lambda data: data["routing"].update(networks=["0.0.0.0/0"]),
            "default routes require",
        ),
        (
            lambda data: data["dns"].update(upstream="192.0.2.53"),
            "not covered",
        ),
        (
            lambda data: data["wireguard"]["peers"][0].update(addresses=["10.77.0.2/32"]),
            "peers lack IPv6",
        ),
        (
            lambda data: data["routing"].update(networks=["224.0.0.0/4"]),
            "multicast",
        ),
        (
            lambda data: data["backend"].update(method="nft"),
            "only sshuttle",
        ),
    ],
)
def test_rejects_unsafe_configuration(mutate: object, message: str) -> None:
    data = deepcopy(config_data())
    mutate(data)  # type: ignore[operator]

    with pytest.raises(ValueError, match=message):
        ProjectConfig.model_validate(data)


def test_full_mode_derives_both_default_routes() -> None:
    data = config_data()
    data["routing"] = {"mode": "full"}
    data["dns"] = {"enabled": False}
    config = ProjectConfig.model_validate(data)

    assert effective_routes(config) == (
        IPv4Network("0.0.0.0/0"),
        IPv6Network("::/0"),
    )


def test_full_mode_rejects_explicit_networks() -> None:
    data = config_data()
    data["routing"] = {"mode": "full", "networks": ["10.0.0.0/8"]}

    with pytest.raises(ValueError, match="must be omitted"):
        ProjectConfig.model_validate(data)


def test_load_config_rejects_unknown_and_oversized_files(tmp_path: Path) -> None:
    data = config_data()
    data["unknown"] = True
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")

    with pytest.raises(ConfigurationError, match="Extra inputs"):
        load_config(path, private=False)

    path.write_bytes(b"x" * (1024 * 1024 + 1))
    with pytest.raises(ConfigurationError, match="maximum"):
        load_config(path, private=False)


@pytest.mark.parametrize("content", ["- item\n", "[bad", "\udcff"])
def test_load_config_reports_invalid_documents(tmp_path: Path, content: str) -> None:
    path = tmp_path / "config.yaml"
    if content == "\udcff":
        path.write_bytes(b"\xff")
    else:
        path.write_text(content, encoding="utf-8")

    with pytest.raises(ConfigurationError):
        load_config(path, private=False)


def test_load_config_requires_a_private_regular_file(tmp_path: Path) -> None:
    data = yaml.safe_dump(config_data())
    path = tmp_path / "config.yaml"
    path.write_text(data, encoding="utf-8")

    with pytest.raises(ConfigurationError, match="permissions"):
        load_config(path)

    path.chmod(0o600)
    assert load_config(path).project == "test-gate"

    link = tmp_path / "config-link.yaml"
    link.symlink_to(path)
    with pytest.raises(ConfigurationError, match="non-symlink"):
        load_config(link)

    directory = tmp_path / "config-dir"
    directory.mkdir()
    with pytest.raises(ConfigurationError, match="regular non-symlink"):
        load_config(directory, private=False)


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("wireguard", "peers", 0, "name"), "Bad_peer", "must match"),
        (("wireguard", "peers", 0, "addresses"), [], "at least one"),
        (
            ("wireguard", "peers", 0, "addresses"),
            ["10.77.0.2/32", "10.77.0.4/32"],
            "at most one",
        ),
        (("wireguard", "peers", 0, "addresses"), ["10.77.0.2/24"], "must use /32"),
        (("wireguard", "bind_addresses"), [], "must not be empty"),
        (("wireguard", "bind_addresses"), ["127.0.0.1", "127.0.0.1"], "unique"),
        (("wireguard", "gateway_addresses"), [], "must not be empty"),
        (("wireguard", "gateway_addresses"), ["10.77.0.0/24"], "network address"),
        (("wireguard", "gateway_addresses"), ["10.77.0.255/24"], "broadcast"),
        (("wireguard", "peers"), [], "peers must not be empty"),
        (("ssh", "user"), "bad user", "unsupported"),
        (("ssh", "remote_python"), "python3 -x", "safe executable"),
        (("ssh", "remote_python"), "--help", "safe executable"),
        (("ssh", "remote_python"), "relative/python3", "safe executable"),
        (("ssh", "remote_python"), "/opt//python3", "safe executable"),
        (("ssh", "identity_file"), "../outside", "instance-relative"),
        (("ssh", "identity_file"), "secrets/line\nbreak", "printable"),
        (("ssh", "known_hosts_file"), "other/known_hosts", "below the instance secrets"),
        (("routing", "networks"), [], "at least one"),
        (("routing", "networks"), ["10.0.0.0/8", "10.0.0.0/8"], "unique"),
        (("dns",), {"enabled": True}, "requires one explicit upstream"),
        (("dns",), {"enabled": False, "upstream": "10.0.0.53"}, "must not define"),
    ],
)
def test_validation_matrix_rejects_ambiguous_or_unsafe_values(
    path: tuple[str | int, ...],
    value: object,
    message: str,
) -> None:
    data = config_data()
    target: object = data
    for key in path[:-1]:
        target = target[key]  # type: ignore[index]
    target[path[-1]] = value  # type: ignore[index]

    with pytest.raises(ValueError, match=message):
        ProjectConfig.model_validate(data)


@pytest.mark.parametrize("remote_python", ["python3", "python3.14", "/opt/python/bin/python3"])
def test_accepts_unambiguous_remote_python(remote_python: str) -> None:
    data = config_data()
    data["ssh"]["remote_python"] = remote_python

    assert ProjectConfig.model_validate(data).ssh.remote_python == remote_python


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("bind_addresses", ["127.0.0.1", "fe80::1"], "%INTERFACE"),
        ("bind_addresses", ["127.0.0.1", "2001:db8::1%eth0"], "only"),
        (
            "bind_addresses",
            ["127.0.0.1", "fe80::1%0123456789abcdef"],
            "safe Linux interface",
        ),
        ("endpoint_host", "fe80::1", "%INTERFACE"),
        ("endpoint_host", "2001:db8::1%wlan0", "only"),
        ("endpoint_host", "fe80::1%0123456789abcdef", "safe interface"),
    ],
)
def test_ipv6_scopes_are_explicit_and_link_local_only(
    field: str,
    value: object,
    message: str,
) -> None:
    data = config_data()
    data["wireguard"][field] = value

    with pytest.raises(ValueError, match=message):
        ProjectConfig.model_validate(data)


def test_accepts_scoped_link_local_bind_endpoint_and_ssh_host() -> None:
    data = config_data()
    data["wireguard"]["bind_addresses"] = ["127.0.0.1", "fe80::1%eth0"]
    data["wireguard"]["endpoint_host"] = "fe80::2%wlan0"
    data["ssh"]["host"] = "fe80::3%enp0s1"

    config = ProjectConfig.model_validate(data)

    assert str(config.wireguard.bind_addresses[1]) == "fe80::1%eth0"
    assert config.wireguard.endpoint_host == "fe80::2%wlan0"
    assert config.ssh.host == "fe80::3%enp0s1"


def test_rejects_duplicate_peer_name_missing_family_and_non_unicast_endpoints() -> None:
    duplicate = config_data()
    duplicate["wireguard"]["peers"][1]["name"] = "phone"
    with pytest.raises(ValueError, match="duplicate peer name"):
        ProjectConfig.model_validate(duplicate)

    missing_family = config_data()
    missing_family["wireguard"]["gateway_addresses"] = ["10.77.0.1/24"]
    with pytest.raises(ValueError, match="without a gateway"):
        ProjectConfig.model_validate(missing_family)

    route_without_gateway = config_data()
    route_without_gateway["wireguard"]["gateway_addresses"] = ["10.77.0.1/24"]
    for peer in route_without_gateway["wireguard"]["peers"]:
        peer["addresses"] = [address for address in peer["addresses"] if ":" not in address]
    route_without_gateway["dns"] = {"enabled": False}
    with pytest.raises(ValueError, match="routing uses IPv6 without"):
        ProjectConfig.model_validate(route_without_gateway)

    endpoint = config_data()
    endpoint["wireguard"]["endpoint_host"] = "ff02::1"
    with pytest.raises(ValueError, match="unicast"):
        ProjectConfig.model_validate(endpoint)

    dns = config_data()
    dns["dns"]["upstream"] = "ff02::53"
    with pytest.raises(ValueError, match="unicast"):
        ProjectConfig.model_validate(dns)
