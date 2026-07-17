"""Strict, immutable shuttle-gate configuration."""

from __future__ import annotations

import re
from enum import StrEnum
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
    ip_address,
    ip_network,
)
from pathlib import Path
from typing import Annotated, Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .errors import ConfigurationError

MAX_CONFIG_BYTES = 1024 * 1024
PROJECT_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
PEER_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
USER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
PYTHON_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.+-]{0,254}$")
PYTHON_PATH_PATTERN = re.compile(r"^/[A-Za-z0-9_./+-]{1,254}$")
HOST_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
MULTICAST_NETWORKS = (ip_network("224.0.0.0/4"), ip_network("ff00::/8"))

IPAddress = IPv4Address | IPv6Address
IPInterface = IPv4Interface | IPv6Interface
IPNetwork = IPv4Network | IPv6Network
Port = Annotated[int, Field(ge=1, le=65535)]


class StrictModel(BaseModel):
    """Base model that rejects silent configuration drift."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class PeerConfig(StrictModel):
    """One declared WireGuard peer."""

    name: str
    addresses: tuple[IPInterface, ...]
    persistent_keepalive_seconds: int = Field(default=25, ge=0, le=65535)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not PEER_PATTERN.fullmatch(value):
            raise ValueError("must match [a-z][a-z0-9-]{0,62}")
        return value

    @model_validator(mode="after")
    def validate_addresses(self) -> PeerConfig:
        if not self.addresses:
            raise ValueError("addresses must contain at least one IPv4 or IPv6 address")
        families: set[int] = set()
        for interface in self.addresses:
            if interface.version in families:
                raise ValueError("a peer may have at most one address per IP family")
            families.add(interface.version)
            required_prefix = 32 if interface.version == 4 else 128
            if interface.network.prefixlen != required_prefix:
                raise ValueError(f"peer address {interface} must use /{required_prefix}")
        return self


class WireGuardConfig(StrictModel):
    """Phone-facing WireGuard configuration."""

    bind_addresses: tuple[IPAddress, ...]
    endpoint_host: str
    listen_port: Port = 51820
    gateway_addresses: tuple[IPInterface, ...]
    mtu: int = Field(default=1420, ge=1280, le=9000)
    peers: tuple[PeerConfig, ...]

    @field_validator("endpoint_host")
    @classmethod
    def validate_endpoint_host(cls, value: str) -> str:
        host = value.strip()
        if not host or host != value or len(host) > 253:
            raise ValueError("must be a non-empty host without surrounding whitespace")
        try:
            address = ip_address(host)
        except ValueError:
            labels = host.rstrip(".").split(".")
            if not labels or any(not HOST_LABEL_PATTERN.fullmatch(label) for label in labels):
                raise ValueError("must be an IPv4/IPv6 address or valid DNS hostname") from None
            return host
        if address.is_unspecified or address.is_multicast:
            raise ValueError("must be an explicit unicast address")
        return host

    @model_validator(mode="after")
    def validate_network(self) -> WireGuardConfig:
        if not self.bind_addresses:
            raise ValueError("bind_addresses must not be empty")
        if len(set(self.bind_addresses)) != len(self.bind_addresses):
            raise ValueError("bind_addresses must be unique")
        if any(address.is_unspecified or address.is_multicast for address in self.bind_addresses):
            raise ValueError("bind addresses must be explicit unicast addresses")
        if not self.gateway_addresses:
            raise ValueError("gateway_addresses must not be empty")
        if not self.peers:
            raise ValueError("peers must not be empty")

        gateways: dict[int, IPInterface] = {}
        for interface in self.gateway_addresses:
            if interface.version in gateways:
                raise ValueError("gateway_addresses may contain at most one address per family")
            if interface.ip == interface.network.network_address:
                raise ValueError(f"gateway address {interface} is the network address")
            if interface.ip.is_unspecified or interface.ip.is_multicast:
                raise ValueError(f"gateway address {interface} must be unicast")
            if (
                isinstance(interface, IPv4Interface)
                and interface.ip == interface.network.broadcast_address
            ):
                raise ValueError(f"gateway address {interface} is the broadcast address")
            gateways[interface.version] = interface

        peer_names: set[str] = set()
        peer_addresses: set[IPAddress] = set()
        gateway_ips = {interface.ip for interface in self.gateway_addresses}
        for peer in self.peers:
            if peer.name in peer_names:
                raise ValueError(f"duplicate peer name: {peer.name}")
            peer_names.add(peer.name)
            for interface in peer.addresses:
                if interface.ip.is_unspecified or interface.ip.is_multicast:
                    raise ValueError(f"peer {peer.name} address must be unicast")
                gateway = gateways.get(interface.version)
                if gateway is None:
                    raise ValueError(
                        f"peer {peer.name} has IPv{interface.version} without a gateway address"
                    )
                if interface.ip not in gateway.network:
                    raise ValueError(
                        f"peer address {interface.ip} is outside gateway network {gateway.network}"
                    )
                if interface.ip in gateway_ips:
                    raise ValueError(f"peer {peer.name} reuses a gateway address")
                if interface.ip in peer_addresses:
                    raise ValueError(f"duplicate peer address: {interface.ip}")
                peer_addresses.add(interface.ip)
        return self


class SSHConfig(StrictModel):
    """SSH transport and authentication settings."""

    host: str
    user: str
    port: Port = 22
    identity_file: Path
    known_hosts_file: Path
    remote_python: str = "python3"
    connect_timeout_seconds: int = Field(default=10, ge=1, le=300)
    server_alive_interval_seconds: int = Field(default=15, ge=1, le=300)
    server_alive_count_max: int = Field(default=3, ge=1, le=20)

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        return WireGuardConfig.validate_endpoint_host(value)

    @field_validator("user")
    @classmethod
    def validate_user(cls, value: str) -> str:
        if not USER_PATTERN.fullmatch(value):
            raise ValueError("contains unsupported characters")
        return value

    @field_validator("remote_python")
    @classmethod
    def validate_remote_python(cls, value: str) -> str:
        safe_name = PYTHON_NAME_PATTERN.fullmatch(value) is not None
        path_parts = value.split("/")[1:]
        safe_absolute_path = (
            PYTHON_PATH_PATTERN.fullmatch(value) is not None
            and bool(path_parts)
            and all(part not in {"", ".", ".."} for part in path_parts)
        )
        if not safe_name and not safe_absolute_path:
            raise ValueError("must be a safe executable name or absolute path without arguments")
        return value

    @field_validator("identity_file", "known_hosts_file")
    @classmethod
    def validate_secret_path(cls, value: Path) -> Path:
        if not str(value).isprintable():
            raise ValueError("must contain only printable path characters")
        if value.is_absolute() or ".." in value.parts:
            raise ValueError("must be an instance-relative path below secrets/")
        if len(value.parts) < 2 or value.parts[0] != "secrets":
            raise ValueError("must be located below the instance secrets/ directory")
        return value


class RoutingMode(StrEnum):
    """Supported route selection modes."""

    SELECTED = "selected"
    FULL = "full"


class RoutingConfig(StrictModel):
    """Networks presented to phone peers and sshuttle."""

    mode: RoutingMode = RoutingMode.SELECTED
    networks: tuple[IPNetwork, ...] = ()

    @model_validator(mode="after")
    def validate_routes(self) -> RoutingConfig:
        if self.mode is RoutingMode.SELECTED and not self.networks:
            raise ValueError("selected routing requires at least one network")
        if self.mode is RoutingMode.FULL and self.networks:
            raise ValueError("full routing derives default routes; networks must be omitted")
        if len(set(self.networks)) != len(self.networks):
            raise ValueError("routing networks must be unique")
        if self.mode is RoutingMode.SELECTED and any(
            network.prefixlen == 0 for network in self.networks
        ):
            raise ValueError("default routes require routing.mode: full")
        if self.mode is RoutingMode.SELECTED and any(
            route.version == multicast.version and route.overlaps(multicast)
            for route in self.networks
            for multicast in MULTICAST_NETWORKS
        ):
            raise ValueError("selected routing networks must not include multicast space")
        return self


class DNSConfig(StrictModel):
    """Phone DNS settings routed directly through the gateway."""

    enabled: bool = False
    upstream: IPAddress | None = None

    @model_validator(mode="after")
    def validate_upstream(self) -> DNSConfig:
        if self.enabled and self.upstream is None:
            raise ValueError("enabled DNS requires one explicit upstream")
        if not self.enabled and self.upstream is not None:
            raise ValueError("disabled DNS must not define an upstream")
        if self.upstream is not None and (
            self.upstream.is_unspecified or self.upstream.is_multicast
        ):
            raise ValueError("DNS upstream must be an explicit unicast address")
        return self


class BackendConfig(StrictModel):
    """Pinned egress backend settings."""

    mode: str = "sshuttle"
    method: str = "nft-tproxy"
    startup_timeout_seconds: int = Field(default=45, ge=5, le=300)

    @model_validator(mode="after")
    def validate_backend(self) -> BackendConfig:
        if self.mode != "sshuttle" or self.method != "nft-tproxy":
            raise ValueError("only sshuttle with the native nft-tproxy method is supported")
        return self


class ProjectConfig(StrictModel):
    """Complete validated instance configuration."""

    version: int
    project: str
    wireguard: WireGuardConfig
    ssh: SSHConfig
    routing: RoutingConfig
    dns: DNSConfig = DNSConfig()
    backend: BackendConfig = BackendConfig()

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: int) -> int:
        if value != 1:
            raise ValueError("unsupported configuration version; expected 1")
        return value

    @field_validator("project")
    @classmethod
    def validate_project(cls, value: str) -> str:
        if not PROJECT_PATTERN.fullmatch(value):
            raise ValueError("must match [a-z][a-z0-9-]{0,62}")
        return value

    @model_validator(mode="after")
    def validate_cross_fields(self) -> ProjectConfig:
        routes = effective_routes(self)
        gateway_families = {interface.version for interface in self.wireguard.gateway_addresses}
        unsupported_route_families = {
            route.version for route in routes if route.version not in gateway_families
        }
        if unsupported_route_families:
            rendered = ", ".join(f"IPv{family}" for family in sorted(unsupported_route_families))
            raise ValueError(f"routing uses {rendered} without a WireGuard gateway address")
        if (
            self.dns.enabled
            and self.dns.upstream is not None
            and not any(
                route.version == self.dns.upstream.version and self.dns.upstream in route
                for route in routes
            )
        ):
            raise ValueError("DNS upstream is not covered by configured routing")
        if self.dns.enabled and self.dns.upstream is not None:
            family = self.dns.upstream.version
            incompatible = [
                peer.name
                for peer in self.wireguard.peers
                if all(address.version != family for address in peer.addresses)
            ]
            if incompatible:
                raise ValueError(
                    f"DNS upstream is IPv{family}, but peers lack IPv{family}: "
                    + ", ".join(incompatible)
                )
        return self


def effective_routes(config: ProjectConfig) -> tuple[IPNetwork, ...]:
    """Return explicit networks passed to peers and sshuttle."""

    if config.routing.mode is RoutingMode.SELECTED:
        return config.routing.networks
    families = {interface.version for interface in config.wireguard.gateway_addresses}
    routes: list[IPNetwork] = []
    if 4 in families:
        routes.append(IPv4Network("0.0.0.0/0"))
    if 6 in families:
        routes.append(IPv6Network("::/0"))
    return tuple(routes)


def load_config(path: Path) -> ProjectConfig:
    """Load one bounded YAML document and return an immutable model."""

    try:
        size = path.stat().st_size
        if size > MAX_CONFIG_BYTES:
            raise ConfigurationError(
                f"configuration is {size} bytes; maximum is {MAX_CONFIG_BYTES}"
            )
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigurationError(f"configuration file does not exist: {path}") from exc
    except (OSError, UnicodeError) as exc:
        raise ConfigurationError(f"cannot read configuration {path}: {exc}") from exc

    try:
        value: Any = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ConfigurationError("configuration root must be a mapping")
    try:
        return ProjectConfig.model_validate(value)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
            for error in exc.errors(include_url=False)
        )
        raise ConfigurationError(details) from exc
