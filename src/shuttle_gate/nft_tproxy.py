"""Native nftables transparent-proxy method for sshuttle.

sshuttle 1.3.2 provides the TCP/UDP proxy engine but its upstream TPROXY
method programs a legacy firewall frontend.  The runtime injects this method
module in memory before sshuttle starts, and uses only native ``nft`` rules.
"""

from __future__ import annotations

import shutil
import socket
import struct
import subprocess
from collections.abc import Sequence
from ipaddress import ip_network
from typing import Any

from sshuttle.helpers import Fatal  # type: ignore[import-untyped]
from sshuttle.methods import BaseMethod  # type: ignore[import-untyped]

IP_TRANSPARENT = 19
IP_ORIGDSTADDR = 20
IP_RECVORIGDSTADDR = IP_ORIGDSTADDR
SOL_IPV6 = 41
IPV6_ORIGDSTADDR = 74
IPV6_RECVORIGDSTADDR = IPV6_ORIGDSTADDR
NFT_TIMEOUT_SECONDS = 10.0

type Subnet = tuple[int, int, bool, str, int, int]
type NameServer = tuple[int, str]


def nft_table_name(port: int) -> str:
    """Return a deterministic identifier made only from a validated port."""

    if not 1 <= port <= 65535:
        raise ValueError(f"invalid transparent proxy port: {port}")
    return f"shuttle_gate_tproxy_{port}"


def _family_tokens(family: int) -> tuple[str, str, int]:
    if family == socket.AF_INET:
        return "ip", "ip", 32
    if family == socket.AF_INET6:
        return "ip6", "ip6", 128
    raise ValueError(f"unsupported address family: {family}")


def _subnet_weight(subnet: Subnet) -> tuple[int, int, bool]:
    """Match sshuttle's most-specific-first route precedence."""

    _family, width, exclude, _network, first_port, last_port = subnet
    return (-last_port + (first_port or -65535), width, exclude)


def _match(protocol: str, address_token: str, network: str, first: int, last: int) -> str:
    parts = [f"{address_token} daddr {network}"]
    if first:
        port_expression = str(first) if first == last else f"{first}-{last}"
        parts.append(f"{protocol} dport {port_expression}")
    else:
        parts.append(f"meta l4proto {protocol}")
    return " ".join(parts)


def render_tproxy_table(
    *,
    port: int,
    dns_port: int,
    name_servers: Sequence[NameServer],
    family: int,
    subnets: Sequence[Subnet],
    udp: bool,
    mark: str,
) -> str:
    """Render one atomic family-specific nftables table."""

    nft_family, address_token, max_width = _family_tokens(family)
    if (
        not mark.startswith("0x")
        or not mark[2:]
        or any(character not in "0123456789abcdefABCDEF" for character in mark[2:])
    ):
        raise ValueError(f"invalid packet mark: {mark}")
    if not 1 <= dns_port <= 65535 and any(item[0] == family for item in name_servers):
        raise ValueError(f"invalid DNS proxy port: {dns_port}")

    table = nft_table_name(port)
    output_rules: list[str] = []
    prerouting_rules: list[str] = []
    host_width = 32 if family == socket.AF_INET else 128

    for server_family, address in name_servers:
        if server_family != family:
            continue
        server = ip_network(f"{address}/{host_width}", strict=False)
        if server.version != (4 if family == socket.AF_INET else 6):
            raise ValueError(f"name-server family mismatch: {address}")
        dns_match = f"{address_token} daddr {server.network_address} udp dport 53"
        output_rules.append(f"    {dns_match} meta mark set {mark} accept")
        prerouting_rules.append(
            f"    {dns_match} tproxy to :{dns_port} meta mark set {mark} accept"
        )

    output_rules.append("    fib daddr type local return")
    prerouting_rules.extend(
        [
            "    fib daddr type local return",
            f"    socket transparent 1 meta mark set {mark} accept",
        ]
    )

    for subnet in sorted(subnets, key=_subnet_weight, reverse=True):
        subnet_family, width, exclude, network, first_port, last_port = subnet
        if subnet_family != family:
            raise ValueError("sshuttle passed a subnet for the wrong address family")
        if not 0 <= width <= max_width:
            raise ValueError(f"invalid subnet width: {width}")
        parsed = ip_network(f"{network}/{width}", strict=False)
        if parsed.version != (4 if family == socket.AF_INET else 6):
            raise ValueError(f"subnet family mismatch: {network}/{width}")
        if not 0 <= first_port <= last_port <= 65535:
            raise ValueError(f"invalid port range: {first_port}-{last_port}")
        for protocol in ("tcp", "udp") if udp else ("tcp",):
            match = _match(
                protocol,
                address_token,
                str(parsed),
                first_port,
                last_port,
            )
            if exclude:
                output_rules.append(f"    {match} return")
                prerouting_rules.append(f"    {match} return")
            else:
                output_rules.append(f"    {match} meta mark set {mark} accept")
                prerouting_rules.append(
                    f"    {match} tproxy to :{port} meta mark set {mark} accept"
                )

    lines = [
        f"table {nft_family} {table} {{",
        "  chain output {",
        "    type route hook output priority mangle; policy accept;",
        *output_rules,
        "  }",
        "  chain prerouting {",
        "    type filter hook prerouting priority mangle; policy accept;",
        *prerouting_rules,
        "  }",
        "}",
    ]
    return "\n".join(lines) + "\n"


def _run_nft(arguments: list[str], *, rules: str | None = None, check: bool = True) -> None:
    try:
        completed = subprocess.run(
            ["nft", *arguments],
            input=rules,
            text=True,
            capture_output=True,
            timeout=NFT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Fatal(f"cannot execute native nftables command: {exc}") from exc
    if check and completed.returncode != 0:
        diagnostic = (completed.stderr or completed.stdout).strip()[:4096]
        raise Fatal(
            f"native nftables command failed with status {completed.returncode}: {diagnostic}"
        )


def _receive_udp(listener: socket.socket, buffer_size: int) -> tuple[Any, Any, bytes]:
    data, ancillary, _flags, source = listener.recvmsg(buffer_size, socket.CMSG_SPACE(24))
    destination: tuple[str, int] | None = None
    for level, kind, payload in ancillary:
        if level == socket.SOL_IP and kind == IP_ORIGDSTADDR:
            family, network_port = struct.unpack("=HH", payload[0:4])
            if family != socket.AF_INET:
                raise Fatal(f"unsupported original IPv4 socket family: {family}")
            destination = (
                socket.inet_ntop(family, payload[4:8]),
                socket.htons(network_port),
            )
            break
        if level == SOL_IPV6 and kind == IPV6_ORIGDSTADDR:
            family, network_port = struct.unpack("=HH", payload[0:4])
            if family != socket.AF_INET6:
                raise Fatal(f"unsupported original IPv6 socket family: {family}")
            destination = (
                socket.inet_ntop(family, payload[8:24]),
                socket.htons(network_port),
            )
            break
    return source, destination, data


class Method(BaseMethod):  # type: ignore[misc]
    """sshuttle method with transparent TCP/UDP sockets and native nftables."""

    def get_supported_features(self) -> Any:
        result = super().get_supported_features()
        result.ipv6 = True
        result.udp = True
        result.dns = True
        return result

    @staticmethod
    def get_tcp_dstip(sock: socket.socket) -> Any:
        return sock.getsockname()

    @staticmethod
    def recv_udp(udp_listener: socket.socket, buffer_size: int) -> Any:
        source, destination, data = _receive_udp(udp_listener, buffer_size)
        if destination is None:
            return None
        return source, destination, data

    @staticmethod
    def setsockopt_error(error: PermissionError) -> None:
        raise Fatal("NET_ADMIN is required for transparent proxy sockets") from error

    def send_udp(self, sock: socket.socket, source: Any, destination: Any, data: bytes) -> None:
        if source is None:
            return
        sender = socket.socket(sock.family, socket.SOCK_DGRAM)
        try:
            sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sender.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
            except PermissionError as exc:
                self.setsockopt_error(exc)
            sender.bind(source)
            sender.sendto(data, destination)
        finally:
            sender.close()

    def setup_tcp_listener(self, listener: Any) -> None:
        try:
            listener.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
        except PermissionError as exc:
            self.setsockopt_error(exc)

    def setup_udp_listener(self, listener: Any) -> None:
        try:
            listener.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
        except PermissionError as exc:
            self.setsockopt_error(exc)
        if listener.v4 is not None:
            listener.v4.setsockopt(socket.SOL_IP, IP_RECVORIGDSTADDR, 1)
        if listener.v6 is not None:
            listener.v6.setsockopt(SOL_IPV6, IPV6_RECVORIGDSTADDR, 1)

    def setup_firewall(
        self,
        port: int,
        dnsport: int,
        nslist: list[NameServer],
        family: int,
        subnets: list[Subnet],
        udp: bool,
        user: str | None,
        group: str | None,
        tmark: str,
    ) -> None:
        if user is not None or group is not None:
            raise Fatal("native nft-tproxy does not support user/group filters")
        self.restore_firewall(port, family, udp, user, group)
        rules = render_tproxy_table(
            port=port,
            dns_port=dnsport,
            name_servers=nslist,
            family=family,
            subnets=subnets,
            udp=udp,
            mark=tmark,
        )
        _run_nft(["--check", "--file", "-"], rules=rules)
        _run_nft(["--file", "-"], rules=rules)

    def restore_firewall(
        self,
        port: int,
        family: int,
        udp: bool,
        user: str | None,
        group: str | None,
    ) -> None:
        del udp, user, group
        nft_family, _address_token, _width = _family_tokens(family)
        _run_nft(
            ["delete", "table", nft_family, nft_table_name(port)],
            check=False,
        )

    @staticmethod
    def is_supported() -> bool:
        return shutil.which("nft") is not None
