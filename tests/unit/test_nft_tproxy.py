from __future__ import annotations

import shutil
import socket
import struct
import subprocess
from typing import Any, cast

import pytest
from sshuttle.helpers import Fatal  # type: ignore[import-untyped]

import shuttle_gate.nft_tproxy as nft_tproxy
from shuttle_gate.nft_tproxy import Method, nft_table_name, render_tproxy_table


def test_render_ipv4_native_tproxy_has_atomic_hooks_and_udp() -> None:
    rendered = render_tproxy_table(
        port=12300,
        dns_port=12299,
        name_servers=[(socket.AF_INET, "10.20.30.53")],
        family=socket.AF_INET,
        subnets=[
            (socket.AF_INET, 8, False, "10.0.0.0", 0, 0),
            (socket.AF_INET, 24, True, "10.8.1.0", 443, 443),
        ],
        udp=True,
        mark="0x1",
    )

    assert "table ip shuttle_gate_tproxy_12300" in rendered
    assert "type route hook output priority mangle" in rendered
    assert "type filter hook prerouting priority mangle" in rendered
    assert "socket transparent 1" in rendered
    assert "udp dport 53 tproxy to :12299" in rendered
    assert "ip daddr 10.0.0.0/8 meta l4proto udp tproxy to :12300" in rendered
    assert rendered.index("10.8.1.0/24") < rendered.index("10.0.0.0/8")


def test_render_ipv6_uses_family_specific_address_expression() -> None:
    rendered = render_tproxy_table(
        port=12301,
        dns_port=12302,
        name_servers=[],
        family=socket.AF_INET6,
        subnets=[(socket.AF_INET6, 48, False, "fd20:1234::", 8000, 8080)],
        udp=False,
        mark="0x2a",
    )

    assert "table ip6 shuttle_gate_tproxy_12301" in rendered
    assert "ip6 daddr fd20:1234::/48 tcp dport 8000-8080" in rendered
    assert "meta l4proto udp" not in rendered


@pytest.mark.parametrize("port", [0, 65536])
def test_table_name_rejects_invalid_port(port: int) -> None:
    with pytest.raises(ValueError, match="port"):
        nft_table_name(port)


def test_render_rejects_wrong_family_and_mark() -> None:
    with pytest.raises(ValueError, match="mark"):
        render_tproxy_table(
            port=12300,
            dns_port=12301,
            name_servers=[],
            family=socket.AF_INET,
            subnets=[],
            udp=True,
            mark="1",
        )
    with pytest.raises(ValueError, match="wrong address family"):
        render_tproxy_table(
            port=12300,
            dns_port=12301,
            name_servers=[],
            family=socket.AF_INET,
            subnets=[(socket.AF_INET6, 64, False, "fd00::", 0, 0)],
            udp=True,
            mark="0x1",
        )


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"family": -1}, "address family"),
        ({"dns_port": 0, "name_servers": [(socket.AF_INET, "10.0.0.53")]}, "DNS"),
        ({"subnets": [(socket.AF_INET, 33, False, "10.0.0.0", 0, 0)]}, "width"),
        ({"subnets": [(socket.AF_INET, 8, False, "10.0.0.0", 90, 80)]}, "port range"),
        ({"name_servers": [(socket.AF_INET, "fd00::53")]}, "family mismatch"),
    ],
)
def test_render_rejects_invalid_dynamic_inputs(kwargs: dict[str, Any], message: str) -> None:
    values: dict[str, Any] = {
        "port": 12300,
        "dns_port": 12301,
        "name_servers": [],
        "family": socket.AF_INET,
        "subnets": [],
        "udp": True,
        "mark": "0x1",
    }
    values.update(kwargs)
    with pytest.raises(ValueError, match=message):
        render_tproxy_table(**values)


def test_method_reports_features_and_programs_checked_atomic_rules(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], str | None, bool]] = []
    monkeypatch.setattr(
        nft_tproxy,
        "_run_nft",
        lambda arguments, *, rules=None, check=True: calls.append((arguments, rules, check)),
    )
    method = Method("tproxy")

    features = method.get_supported_features()
    assert features.ipv6 and features.udp and features.dns
    method.setup_firewall(
        12300,
        12301,
        [],
        socket.AF_INET,
        [(socket.AF_INET, 8, False, "10.0.0.0", 0, 0)],
        True,
        None,
        None,
        "0x1",
    )

    assert calls[0] == (
        ["delete", "table", "ip", "shuttle_gate_tproxy_12300"],
        None,
        False,
    )
    assert calls[1][0] == ["--check", "--file", "-"]
    assert calls[2][0] == ["--file", "-"]
    with pytest.raises(Fatal, match="user/group"):
        method.setup_firewall(12300, 12301, [], socket.AF_INET, [], True, "1000", None, "0x1")


class FakeSocket:
    def __init__(self, family: int = socket.AF_INET) -> None:
        self.family = family
        self.options: list[tuple[int, int, int]] = []
        self.bound: Any = None
        self.sent: tuple[bytes, Any] | None = None
        self.closed = False
        self.recv_value: Any = None

    def setsockopt(self, level: int, option: int, value: int) -> None:
        self.options.append((level, option, value))

    def bind(self, address: Any) -> None:
        self.bound = address

    def sendto(self, data: bytes, destination: Any) -> None:
        self.sent = (data, destination)

    def close(self) -> None:
        self.closed = True

    def getsockname(self) -> tuple[str, int]:
        return "10.0.0.1", 443

    def recvmsg(self, _size: int, _control_size: int) -> Any:
        return self.recv_value


class FakeMultiListener:
    def __init__(self) -> None:
        self.v4 = FakeSocket(socket.AF_INET)
        self.v6 = FakeSocket(socket.AF_INET6)
        self.options: list[tuple[int, int, int]] = []

    def setsockopt(self, level: int, option: int, value: int) -> None:
        self.options.append((level, option, value))


def test_method_configures_transparent_sockets_and_udp_sender(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created = FakeSocket()
    monkeypatch.setattr(socket, "socket", lambda *_args: created)
    method = Method("tproxy")
    listener = FakeMultiListener()

    method.setup_tcp_listener(listener)
    method.setup_udp_listener(listener)
    method.send_udp(
        cast("socket.socket", FakeSocket()),
        ("10.77.0.2", 5555),
        ("10.20.0.1", 53),
        b"data",
    )
    method.send_udp(
        cast("socket.socket", FakeSocket()),
        None,
        ("10.20.0.1", 53),
        b"ignored",
    )

    assert listener.options.count((socket.SOL_IP, nft_tproxy.IP_TRANSPARENT, 1)) == 2
    assert listener.v4.options[-1] == (socket.SOL_IP, nft_tproxy.IP_RECVORIGDSTADDR, 1)
    assert listener.v6.options[-1] == (
        nft_tproxy.SOL_IPV6,
        nft_tproxy.IPV6_RECVORIGDSTADDR,
        1,
    )
    assert created.bound == ("10.77.0.2", 5555)
    assert created.sent == (b"data", ("10.20.0.1", 53))
    assert created.closed
    assert method.get_tcp_dstip(cast("socket.socket", FakeSocket())) == ("10.0.0.1", 443)


def test_method_decodes_original_ipv4_and_ipv6_udp_destinations() -> None:
    method = Method("tproxy")
    ipv4 = FakeSocket()
    ipv4_payload = (
        struct.pack("=H", socket.AF_INET)
        + struct.pack("!H", 53)
        + socket.inet_pton(socket.AF_INET, "10.20.30.53")
        + b"\x00" * 8
    )
    ipv4.recv_value = (
        b"query",
        [(socket.SOL_IP, nft_tproxy.IP_ORIGDSTADDR, ipv4_payload)],
        0,
        ("10.77.0.2", 50000),
    )
    source, destination, data = method.recv_udp(cast("socket.socket", ipv4), 4096)
    assert source == ("10.77.0.2", 50000)
    assert destination == ("10.20.30.53", 53)
    assert data == b"query"

    ipv6 = FakeSocket(socket.AF_INET6)
    ipv6_payload = (
        struct.pack("=H", socket.AF_INET6)
        + struct.pack("!H", 5353)
        + b"\x00" * 4
        + socket.inet_pton(socket.AF_INET6, "fd20::53")
    )
    ipv6.recv_value = (
        b"query6",
        [(nft_tproxy.SOL_IPV6, nft_tproxy.IPV6_ORIGDSTADDR, ipv6_payload)],
        0,
        ("fd77::2", 50001),
    )
    assert method.recv_udp(cast("socket.socket", ipv6), 4096)[1] == ("fd20::53", 5353)

    missing = FakeSocket()
    missing.recv_value = (b"none", [], 0, ("10.77.0.2", 1))
    assert method.recv_udp(cast("socket.socket", missing), 4096) is None


def test_native_command_runner_reports_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(["nft"], 0, "", ""),
    )
    nft_tproxy._run_nft(["list", "tables"])

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(["nft"], 1, "", "bad rule"),
    )
    with pytest.raises(Fatal, match="bad rule"):
        nft_tproxy._run_nft(["--file", "-"], rules="bad")

    def missing(*_args: Any, **_kwargs: Any) -> Any:
        raise FileNotFoundError

    monkeypatch.setattr(subprocess, "run", missing)
    with pytest.raises(Fatal, match="cannot execute"):
        nft_tproxy._run_nft(["list", "tables"])


def test_method_support_check_uses_only_native_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/sbin/nft")
    assert Method.is_supported()
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    assert not Method.is_supported()
