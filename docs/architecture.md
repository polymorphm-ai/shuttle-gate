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

`./shuttle-gate` is a locked PEP 723 script; uv supplies Python and packages
from its user cache. Application code is immutable and separate from each
instance's `config.yaml`, `secrets/`, `state/`, and `exports/`. The canonical
instance path determines transient service and runtime identities.

The launcher validates host inputs, builds an immutable application bundle and
launch manifest below `XDG_RUNTIME_DIR`, and starts a transient systemd user
service. A supervisor holds each exact host UDP socket claim for the service
lifetime. Overlap fails before pasta starts and does not disturb other
instances.

`pasta` creates the rootless user and network namespaces. ID 0 inside maps to
the calling user and grants no host root access. Only configured WireGuard UDP
sockets are forwarded. `bubblewrap` retains namespace-local `CAP_NET_ADMIN` and
mounts the bundle, configuration, credentials, and state read-only.
Host-backed write access is limited to the state lock and bounded runtime
output; temporary files stay in the private namespace.

Short-lived operator commands use a separate bubblewrap sandbox. Host paths
remain stable for truthful output, while unrelated parent and sibling content
is hidden.

Production never invokes Docker. Docker Compose exists only for a second,
disposable integration-test environment.

## Durable state and launch publication

Only `init` may create the known default instance. Explicit instance
directories must already exist, preventing accidental creation from mistyped
paths.

WireGuard keys, peer configurations, fingerprints, and operation receipts live
in immutable `state/generations/` directories. Writers validate and fsync a
private staging generation before atomically publishing `state/current`.
Readers bind to one generation under a shared lock; writers are serialized.
Peer-scoped commands change only the named peer, while startup requires every
declared peer to be complete and current.

Non-idempotent rotations publish an operation-ID receipt with their result, so
a retry cannot rotate twice. SSH identity replacement uses a durable journal
and backups until both key files and the state receipt are verified.

The launch manifest binds the service, configuration, credentials, state
generation, application bundle, and host sockets by digest. The sandbox checks
it again before changing networking. A compatible running launch is reused;
changed code or inputs require an intentional restart.

## Packet flow

1. Kernel WireGuard authenticates the peer and enforces its peer address.
2. Family-specific native nftables `prerouting` rules consider only decrypted
   traffic entering through `wg0` and match TCP/UDP in declared routes.
3. Packet marks, TPROXY, and namespace-local policy routes deliver traffic to
   sshuttle's transparent listener.
4. sshuttle multiplexes flows over authenticated SSH.
5. A temporary Python process opens connections from the remote user's normal
   context; it writes no remote file and exits with the session.

The transparent proxy has only a `wg0`-scoped `prerouting` hook. Local
WireGuard and SSH control traffic therefore follows normal namespace routing
and cannot loop into sshuttle. Peer networks, multicast, and limited broadcast
are excluded. Input and forward chains drop uncaptured peer traffic, preventing
direct pasta egress or access to namespace-local services.

The project nftables adapter creates family-specific TPROXY rules. Each ruleset
is syntax-checked before atomic application. Required compatibility settings
are limited to the private namespace; host routing, firewall, and sysctls are
unchanged.

## Address families and DNS

When DNS is enabled, phone configurations name one explicit upstream IP. DNS
uses the same routed TCP/UDP path as other traffic; no separate forwarder is
started.

If `ssh.host` is a name, the sandbox receives a read-only uplink resolver file
for SSH bootstrap. Host resolver settings are never copied to phone peers.

IPv4-only, IPv6-only, and dual-stack routing are supported. Each family needs
matching gateway/peer addresses and routes; the SSH host must be able to reach
the target. An IPv6 WireGuard endpoint also needs an exact reachable host bind.

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
