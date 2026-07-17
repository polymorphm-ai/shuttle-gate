# Architecture

## Components and isolation

```text
phone WireGuard app
        |
        | encrypted UDP to one exact laptop address
        v
Docker-published WireGuard socket
        |
        v
gateway container network namespace
  wg0 -> native nftables TPROXY -> sshuttle client -> SSH connection
                                  |
                                  v
                       temporary remote Python process
                                  |
                                  v
                         target network service
```

The host launcher is a dependency-free Python script. It validates local launch
metadata and calls Docker Compose. Pydantic, YAML, WireGuard tools, sshuttle,
dnsmasq, nft, tests, Ruff, and mypy stay inside Docker images.

The static Compose file defines separate roles:

- `tool`: unprivileged, no network, read-write access to the project directory;
- `doctor`: disposable network check with `NET_ADMIN` and read-only credentials;
- `gateway`: long-running, read-only filesystem, tmpfs runtime, minimal
  capabilities, and read-only secrets/state;
- `test`: no-network quality environment;
- `integration-test`: opt-in disposable kernel test with only `NET_ADMIN`.

## Packet flow

1. Kernel WireGuard authenticates a named peer and enforces its peer address.
2. The native nftables method sees TCP or UDP for configured routes in
   `prerouting`.
3. The rule applies a packet mark and TPROXY delivery to sshuttle's transparent
   listener. Family-specific policy routes send marked packets to loopback.
4. sshuttle multiplexes TCP or UDP data through the authenticated SSH session.
5. A temporary Python process on the SSH server opens connections from that
   server's normal user context. No remote root permission is required.
6. Responses return through sshuttle and WireGuard to the original peer.

The SSH endpoint, WireGuard peer networks, multicast, and limited broadcast are
explicit exclusions. A separate `inet shuttle_gate` forward chain has a drop
policy. Intended traffic is delivered locally to TPROXY; any packet that would
otherwise be routed directly out of the container fails closed at `forward`.

## Native nftables method

sshuttle 1.3.2 has a fixed command-line method name for Linux TPROXY. During the
image build, shuttle-gate replaces that installed method module with its own
implementation. Transparent TCP/UDP socket behavior is retained, but firewall
transactions are rendered as family-specific native nftables tables. Each
transaction is syntax-checked with `nft --check` before atomic application.

No legacy firewall executable or compatibility frontend is installed or
invoked by shuttle-gate.

## DNS and IPv6

When enabled, dnsmasq binds only to configured `wg0` gateway addresses. It uses
one explicit upstream, whose UDP traffic follows the same sshuttle path. Phone
configuration receives only DNS addresses for IP families assigned to that
peer.

IPv4-only, IPv6-only, and dual-stack peers and routes are supported. IPv6 also
requires working host addressing, Docker IPv6 port publication, reachability
to the SSH endpoint, and target-network IPv6 access. IPv6 is never silently
disabled.

## Lifecycle

Startup validates configuration, SSH files, generated fingerprints, remote
Python, key material, WireGuard, policy routes, and nftables before reporting
ready. Docker waits for the health check. Failure at any stage triggers cleanup.
Shutdown stops dnsmasq and sshuttle, removes owned nftables and policy routing,
deletes `wg0`, and removes volatile status. The container namespace is the final
isolation and cleanup boundary.
