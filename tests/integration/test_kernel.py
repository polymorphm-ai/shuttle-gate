"""Exercise real disposable network namespaces and kernel primitives."""

from __future__ import annotations

import socket
import subprocess
import tempfile
from pathlib import Path

import pytest

from shuttle_gate.nft_tproxy import Method
from shuttle_gate.runtime import nft_filter

pytestmark = pytest.mark.integration


def run(
    arguments: list[str],
    *,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run one fixed integration command and retain useful diagnostics."""

    return subprocess.run(
        arguments,
        input=input_text,
        check=True,
        text=True,
        capture_output=True,
        timeout=10,
    )


def cleanup(arguments: list[str]) -> None:
    """Best-effort cleanup that cannot hide the original test failure."""

    subprocess.run(
        arguments,
        check=False,
        text=True,
        capture_output=True,
        timeout=10,
    )


def test_kernel_wireguard_dual_stack_policy_routing_and_native_tproxy() -> None:
    """Apply and remove every privileged primitive used by the gateway."""

    interface = "wg0"
    method = Method("tproxy")
    run(["ip", "link", "add", "dev", interface, "type", "wireguard"])
    try:
        run(["ip", "-4", "address", "add", "10.254.77.1/24", "dev", interface])
        run(["ip", "-6", "address", "add", "fdfe:77::1/64", "dev", interface])
        run(["ip", "link", "set", "dev", interface, "up"])
        server_private = run(["wg", "genkey"]).stdout.strip()
        peer_private = run(["wg", "genkey"]).stdout.strip()
        peer_public = run(["wg", "pubkey"], input_text=peer_private + "\n").stdout.strip()
        preshared = run(["wg", "genpsk"]).stdout.strip()
        configuration = (
            "[Interface]\n"
            f"PrivateKey = {server_private}\n"
            "ListenPort = 51999\n\n"
            "[Peer]\n"
            f"PublicKey = {peer_public}\n"
            f"PresharedKey = {preshared}\n"
            "AllowedIPs = 10.254.77.2/32, fdfe:77::2/128\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", encoding="ascii") as config_file:
            config_file.write(configuration)
            config_file.flush()
            run(["wg", "setconf", interface, str(Path(config_file.name))])
        assert peer_public in run(["wg", "show", interface, "dump"]).stdout
        run(["ip", "-4", "route", "replace", "local", "default", "dev", "lo", "table", "199"])
        run(["ip", "-6", "route", "replace", "local", "default", "dev", "lo", "table", "199"])
        run(["ip", "-4", "rule", "add", "fwmark", "0x1", "lookup", "199"])
        run(["ip", "-6", "rule", "add", "fwmark", "0x1", "lookup", "199"])
        filter_rules = nft_filter()
        run(["nft", "--check", "--file", "-"], input_text=filter_rules)
        run(["nft", "--file", "-"], input_text=filter_rules)

        method.setup_firewall(
            12101,
            12102,
            [(socket.AF_INET, "10.20.30.53")],
            socket.AF_INET,
            [(socket.AF_INET, 8, False, "10.0.0.0", 0, 0)],
            True,
            None,
            None,
            "0x1",
        )
        method.setup_firewall(
            12103,
            12104,
            [(socket.AF_INET6, "fd20::53")],
            socket.AF_INET6,
            [(socket.AF_INET6, 48, False, "fd20::", 0, 0)],
            True,
            None,
            None,
            "0x1",
        )
        assert "shuttle_gate_tproxy_12101" in run(["nft", "list", "tables"]).stdout
        assert "shuttle_gate_tproxy_12103" in run(["nft", "list", "tables"]).stdout
        ipv4_rules = run(["nft", "list", "table", "ip", "shuttle_gate_tproxy_12101"]).stdout
        ipv6_rules = run(["nft", "list", "table", "ip6", "shuttle_gate_tproxy_12103"]).stdout
        for rules in (ipv4_rules, ipv6_rules):
            assert "hook prerouting" in rules
            assert "hook output" not in rules
            assert 'iifname != "wg0" return' in rules
        namespace_rules = run(["nft", "list", "table", "inet", "shuttle_gate"]).stdout
        assert "hook input" in namespace_rules
        assert "direct WireGuard access to namespace" in namespace_rules
        assert "hook forward" in namespace_rules
        assert "udp dport 53 tproxy to :12102" in ipv4_rules
        assert ipv4_rules.count("tproxy to :12101") == 2
    finally:
        method.restore_firewall(12101, socket.AF_INET, True, None, None)
        method.restore_firewall(12103, socket.AF_INET6, True, None, None)
        cleanup(["nft", "delete", "table", "inet", "shuttle_gate"])
        cleanup(["ip", "-4", "rule", "del", "fwmark", "0x1", "lookup", "199"])
        cleanup(["ip", "-6", "rule", "del", "fwmark", "0x1", "lookup", "199"])
        cleanup(["ip", "-4", "route", "flush", "table", "199"])
        cleanup(["ip", "-6", "route", "flush", "table", "199"])
        cleanup(["ip", "link", "del", "dev", interface])


def test_runtime_injects_native_method_without_modifying_sshuttle() -> None:
    """Guard the in-memory replacement of sshuttle's fixed method name."""

    from shuttle_gate.sshuttle_entry import install_native_method

    install_native_method()
    from sshuttle.methods.tproxy import Method as InstalledMethod  # type: ignore[import-untyped]

    assert InstalledMethod is Method
