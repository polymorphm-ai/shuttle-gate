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
packages from its user cache. The application root contains code and the
configuration template; the canonical instance root contains `config.yaml`,
`secrets/`, `state/`, and `exports/`. They are always separate. The application
is immutable; the default instance is the private XDG configuration profile at
`${XDG_CONFIG_HOME:-$HOME/.config}/shuttle-gate/default`, and `--instance PATH`
selects another existing directory. The canonical instance path hashes to its
transient unit and XDG runtime names.

The launcher validates host inputs, creates an immutable application zip and
launch manifest below `XDG_RUNTIME_DIR`, and asks the systemd user manager to
start one transient service. It first probes every exact UDP socket without
address reuse, detecting an existing non-toolkit listener. An immutable
supervisor then locks every tuple through deterministic session-local claim
files and starts pasta. It holds all claims until pasta exits. Ordered
non-blocking locks allow independent instances and reject overlap without
disturbing an existing owner.

Short-lived operator commands also run in bubblewrap. The application is
mounted read-only; the instance is read-only for `doctor` and writable for local
management commands. Both retain their absolute host pathnames, so printed
paths remain valid after the sandbox exits. Parent directories are
namespace-only scaffolding; sibling host content is not exposed.

The outer launcher allowlists public operator commands. Runtime-only entry
points cannot be dispatched into this sandbox because their fixed mount paths
exist only in the long-running service sandbox.

`pasta` creates the rootless user/network namespace. ID 0 inside maps to the
calling user outside; it grants no host root access. Automatic TCP and reverse
port forwarding are disabled. Only each validated WireGuard UDP address/port is
forwarded. `bubblewrap` then drops all capabilities except namespace-local
`CAP_NET_ADMIN` and exposes only system runtime files, the immutable application
zip, read-only configuration/secrets/state, the exact state lock, and writable
volatile output. Neither the application tree nor the full instance tree is
mounted into the service.

Production never invokes Docker. Docker Compose exists only for a second,
disposable integration-test environment.

## Durable state and launch publication

Only an exact `init` request may create a missing default instance. It creates
private XDG parent directories in ordered, fsynced steps; interruption can leave
only safe directories, and retry converges. Explicit instance directories must
already exist, preventing accidental path creation from mistyped arguments.

WireGuard keys, peer configurations, fingerprints, and operation receipts live
in immutable directories under `state/generations/`. A writer constructs and
validates a private staging generation, fsyncs it, renames it, then atomically
replaces `state/current`. An instance `flock` serializes writers. Readers hold a
shared lock while using the resolved generation. A generation is structurally
complete but may represent partial provisioning: selected-peer commands change
only their named peer. Startup separately requires every declared peer key and
phone configuration to be complete and current.

Non-idempotent rotations publish an operation-ID receipt with their result, so
a retry cannot rotate twice. SSH identity replacement uses a durable journal
and backups until both key files and the state receipt are verified.

The host builds a deterministic application zip and atomically publishes a
schema-versioned launch manifest. Digests bind the launch ID, systemd unit,
configuration, credentials, state generation, application bundle, and exact
bind sockets. The sandbox validates every digest again before changing its
network namespace. Lifecycle calls use a separate instance lock; a valid running
launch is resumed rather than replaced. Resumption also compares the active
bundle digest with current application source, so another code version cannot
silently take over an active instance.

## Packet flow

1. Kernel WireGuard authenticates the peer and enforces its peer address.
2. Family-specific native nftables `prerouting` rules consider only decrypted
   traffic entering through `wg0` and match TCP/UDP in declared routes.
3. Packet marks, TPROXY, and namespace-local policy routes deliver traffic to
   sshuttle's transparent listener.
4. sshuttle multiplexes flows over authenticated SSH.
5. A temporary Python process opens connections from the remote user's normal
   context; it writes no remote file and exits with the session.

The namespace has no transparent-proxy `output` hook. WireGuard transport
replies, SSH, and other locally generated control traffic therefore use normal
kernel routing and cannot loop into sshuttle. The SSH endpoint, peer networks,
multicast, and limited broadcast are excluded from forwarded selection. An
owned nftables forward chain defaults to drop, so uncaptured traffic cannot
escape directly through pasta. An input chain also drops unmarked `wg0` traffic
to namespace-local services; only packets already selected by TPROXY can reach
the wildcard proxy sockets.

sshuttle's fixed `nft-tproxy` method name is redirected in memory to the
project implementation. sshuttle re-executes its own `argv[0]` for the firewall
manager, but a module path inside the immutable zip bundle is not a real file.
The adapter therefore atomically publishes a static two-line entry script in
the namespace-private `/tmp` and points sshuttle at it. The script imports the
same read-only bundle through `PYTHONPATH`; namespace destruction removes it.
No installed package or cache file is patched. Each nftables transaction is
syntax-checked with `nft --check` before atomic apply; no legacy firewall
frontend is used.

For dual-stack listeners, the runtime enables `net.ipv6.bindv6only` inside the
private network namespace so sshuttle can bind distinct IPv4 and IPv6 sockets
to one selected port. This does not change the host sysctl.

The adapter disables sshuttle's local system-resolver cache flush. No resolver
daemon or cache runs inside the namespace, and phone DNS uses sshuttle's
in-process path to the configured upstream, so a host-oriented `resolvectl`
call has no target or useful effect there.

## DNS and IPv6

There is no standalone DNS forwarder. When DNS is enabled, phone configurations
name the explicit upstream IP directly. For packets entering through `wg0`,
UDP port 53 is transparently delivered to sshuttle's namespace-local DNS socket;
TCP port 53 follows the ordinary transparent TCP path. The upstream address must
be inside selected routes and its family must exist on every peer.

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
