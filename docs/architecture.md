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

## Persistent state and publication

WireGuard keys, peer configurations, fingerprints, and completed operation
receipts live in immutable directories below `state/generations/`. Writers copy
the current generation into a private staging directory, apply the complete
change, validate it, fsync files and directories, and atomically replace the
`state/current` symlink. The old generation remains authoritative until that
single publish step. Incomplete and unreferenced generations are reconciled by
the next writer.

A project `flock` serializes writers. Readers hold a shared lock while their
generation is in use; the gateway holds it for its entire lifetime.
Non-idempotent key rotations publish a request receipt in the same generation,
so retrying an operation ID cannot rotate twice. The two-file SSH identity
replacement uses a durable journal and backups, then records its request
receipt before removing recovery data.

Launch preparation writes an immutable, content-addressed Compose override and
then atomically publishes `state/runtime/launch.json`. The manifest binds the
configuration, state generation, SSH identity, known-hosts file, and override
by SHA-256 digest. Both the dependency-free host launcher and gateway validate
this plan. Concurrent `up` and `down` calls are serialized by a separate
lifecycle lock; `up` resumes an already-running valid plan instead of preparing
a conflicting one.

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

Startup first reconciles old owned runtime objects. It installs the fail-closed
nftables forward policy while `wg0` is down, validates remote Python, prepares
WireGuard and policy routing, waits for sshuttle (and DNS when enabled), and
activates `wg0` last. Postconditions are checked before readiness is published.
Failure triggers best-effort cleanup of every independent effect. Shutdown
stops dnsmasq and sshuttle, removes owned nftables and policy routing, deletes
`wg0`, and removes volatile status. The container namespace is the final
isolation and cleanup boundary.
