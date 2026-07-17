# Architecture

## Process and isolation model

```text
phone WireGuard app
        |
        | encrypted UDP to exact laptop address/port
        v
pasta (rootless user + network namespace)
        |
        v
bubblewrap runtime sandbox
  wg0 -> native nftables TPROXY -> sshuttle -> SSH session
                                      |
                                      v
                           temporary remote Python
                                      |
                                      v
                              target service
```

`./shuttle-gate` is a locked PEP 723 script. uv supplies Python and application
packages from its user cache. The launcher validates host inputs, creates an
immutable application zip and launch manifest below `XDG_RUNTIME_DIR`, and asks
the systemd user manager to start one transient service.

`pasta` creates the rootless user/network namespace. ID 0 inside maps to the
calling user outside; it grants no host root access. Automatic TCP and reverse
port forwarding are disabled. Only each validated WireGuard UDP address/port is
forwarded. `bubblewrap` then drops all capabilities except namespace-local
`CAP_NET_ADMIN` and exposes only system runtime files, the immutable application
zip, read-only configuration/secrets/state, the exact state lock, and writable
volatile output. The project tree is not mounted into the service.

Production never invokes Docker. Docker Compose exists only for a second,
disposable integration-test environment.

## Durable state and launch publication

WireGuard keys, peer configurations, fingerprints, and operation receipts live
in immutable directories under `state/generations/`. A writer constructs and
validates a private staging generation, fsyncs it, renames it, then atomically
replaces `state/current`. A project `flock` serializes writers. Readers hold a
shared lock while using the resolved generation.

Non-idempotent rotations publish an operation-ID receipt with their result, so
a retry cannot rotate twice. SSH identity replacement uses a durable journal
and backups until both key files and the state receipt are verified.

The host builds a deterministic application zip and atomically publishes a
schema-versioned launch manifest. Digests bind the launch ID, systemd unit,
configuration, credentials, state generation, application bundle, and exact
bind sockets. The sandbox validates every digest again before changing its
network namespace. Lifecycle calls use a separate host lock; a valid running
launch is resumed rather than replaced.

## Packet flow

1. Kernel WireGuard authenticates the peer and enforces its peer address.
2. Family-specific native nftables rules match TCP/UDP in declared routes.
3. Packet marks, TPROXY, and namespace-local policy routes deliver traffic to
   sshuttle's transparent listener.
4. sshuttle multiplexes flows over authenticated SSH.
5. A temporary Python process opens connections from the remote user's normal
   context; it writes no remote file and exits with the session.

The SSH endpoint, peer networks, multicast, and limited broadcast are excluded.
An owned nftables forward chain defaults to drop, so uncaptured traffic cannot
escape directly through pasta.

sshuttle's fixed `nft-tproxy` method name is redirected in memory to the
project implementation. No installed package or cache file is patched. Each
nftables transaction is syntax-checked with `nft --check` before atomic apply;
no legacy firewall frontend is used.

## DNS and IPv6

There is no local DNS forwarder. When DNS is enabled, phone configurations name
the explicit upstream IP directly. That address must be inside selected routes
and its family must exist on every peer, so queries use the same WireGuard,
TPROXY, and SSH path as other UDP traffic.

The sandbox separately needs bootstrap name resolution when `ssh.host` is a
hostname. A host loopback resolver cannot be reached from the namespace, so the
launcher mounts systemd-resolved's uplink resolver file when present, otherwise
the resolved host `/etc/resolv.conf`. This data is read-only and is never sent
to phone peers.

IPv4-only, IPv6-only, and dual-stack routed traffic is supported. IPv6 target
traffic requires peer/gateway addressing, an IPv6 route, and remote target
access. An IPv6 outer WireGuard endpoint additionally requires an exact IPv6
host bind. IPv6 is never silently disabled.

## Lifecycle and recovery

Startup reconciles owned namespace objects, installs the drop policy while
`wg0` is down, verifies remote Python, prepares WireGuard/routing/sshuttle, and
activates `wg0` last. Readiness is published only after postcondition checks.
Status is a bounded, secret-free atomic snapshot.

Permanent validation failures stop immediately. Classified transient failures
publish `retrying` and exit with status 75; systemd alone retries that status
within fixed limits. The host waits through these attempts instead of treating
the first temporary failure as final.
Shutdown attempts every independent cleanup step. Destroying the private
namespace is the final cleanup boundary, so host routing and firewall state are
never involved.
