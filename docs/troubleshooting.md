# Troubleshooting

Start with:

```console
./shuttle-gate config validate
./shuttle-gate doctor
./shuttle-gate status
./shuttle-gate logs --tail 200
```

## The default instance is not initialized

Run `./shuttle-gate init`. It creates the private default at
`${XDG_CONFIG_HOME:-$HOME/.config}/shuttle-gate/default` and prints the exact
configuration path. A relative `XDG_CONFIG_HOME` is invalid under the XDG base
directory rules and is ignored in favor of `$HOME/.config`.

The default does not depend on CWD or the application installation path. For a
different profile, first create a private directory and then consistently use
`--instance PATH`. Explicit paths are never created implicitly.

## uv or a runtime program is unavailable

Install the runtime packages listed in the README. The first launch may need
network access while uv obtains a compatible Python 3.14+ interpreter and locked
packages. Later runs use uv's user cache. Do not create a project virtual
environment or substitute unreviewed package versions.

`doctor` reports each missing command. In particular, the executable supplied
by the `passt` package must also provide pasta mode, and bubblewrap must permit
unprivileged user namespaces.

## The systemd user service cannot start

Run from a normal login session and confirm `XDG_RUNTIME_DIR` exists and
`systemctl --user is-system-running` can reach the user manager. The toolkit
does not start a user manager or enable lingering.

Inspect `./shuttle-gate logs`. A transient unit may retry only classified
network/SSH failures; configuration and integrity errors deliberately remain
failed until corrected. `./shuttle-gate down` is safe when the unit is already
stopped.

## Namespace, WireGuard, or TPROXY checks fail

The host must allow unprivileged user namespaces and provide kernel WireGuard,
nftables socket matching/TPROXY, IPv4 policy routing, and IPv6 policy routing
when configured. pasta and bubblewrap cannot add missing kernel features.

The project uses current native nftables interfaces only. A legacy firewall
compatibility package does not repair a failed check.

The configured port must be at or above
`/proc/sys/net/ipv4/ip_unprivileged_port_start`. Every bind address must already
exist on the host. The toolkit will not add addresses or firewall rules.

## SSH check fails

- Confirm the private key is mode `0600`.
- Confirm the public key is already authorized for the configured user.
- Verify `known_hosts` for the exact host and port through a trusted channel.
- Test whether server policy permits non-interactive public-key SSH.
- Confirm the configured remote executable is Python 3.9+.

For an SSH hostname, confirm the host's uplink resolver file contains reachable
non-loopback nameservers. The sandbox prefers
`/run/systemd/resolve/resolv.conf`; a stub-only `127.0.0.53` resolver cannot be
contacted across a private network namespace.

Do not ask the toolkit to change the server. Key authorization or policy changes
must be separate actions by an authorized administrator.

## Phone has no WireGuard handshake

- Confirm every bind address still belongs to the laptop.
- Confirm `endpoint_host` reaches that laptop address from the phone.
- Permit the exact UDP port through operator-managed firewall, Wi-Fi isolation,
  NAT, and mobile-network policy.
- Re-import the newest phone configuration after any key change.

Pasta exposes only those exact UDP sockets. It does not automatically publish
TCP, reverse traffic, gateway addresses, or additional UDP ports.

## Handshake works, but routed traffic fails

The destination must be inside a configured route. Confirm the remote SSH
account can reach the target. Review logs for sshuttle failures. Ping is not a
valid test because ICMP is unsupported; use a real TCP or UDP client.

For DNS, the configured upstream must be an explicit IP covered by routing and
reachable from the SSH server. The phone names it directly, and both UDP and
TCP use the ordinary routed proxy. There is no separately exposed resolver,
cache, or imported host search domain. Re-import the phone configuration after
changing DNS.

Only unicast UDP is captured. Broadcast/multicast discovery, ICMP, raw
protocols, unusually long idle flows, very large datagrams, and applications
that depend on exact source-address behavior may not work through sshuttle.

## IPv6 fails

Check each layer: an exact reachable IPv6 bind/endpoint on the laptop, IPv6
gateway and peer addresses, an IPv6 route, and reachability from the SSH server
to the target. Pasta receives an explicit IPv6 UDP forward. No IPv4 fallback is
performed for IPv6 destinations.

An IPv6 link-local bind requires `%HOST_INTERFACE`. A link-local
`endpoint_host` separately requires the interface scope used by the client;
using the laptop's interface name there is normally wrong for a phone.

## State or shutdown was interrupted

Run `./shuttle-gate down`, then repeat the operation. Namespace destruction
removes all runtime networking; persistent keys are not deleted. State writers
reconcile staging directories and publish only through atomic `state/current`.
Never hand-edit a generation or remove lock files.

Stop the gateway before moving or renaming its instance directory. The canonical
instance path identifies its transient unit and XDG runtime directory; a moved
directory is intentionally a new instance. Moving application source does not
change instance identity, but `up` refuses to resume an active gateway when its
current application bundle differs. Run `down` for that instance, then start the
new code intentionally.

If `up` reports that a host UDP socket is unavailable or already in use, another
instance or host process owns the same exact address/port tuple. Select another
bind address or listen port. Do not remove claim files: they are session-local
under `XDG_RUNTIME_DIR`, and the supervising service holds the actual lock for
its complete lifetime.

Reuse the printed operation ID when a key command's outcome is unknown. A busy
state means the gateway or another writer owns the lock; stop it or wait. If
`up` reports changed prepared inputs, use `down` and then `up` so a fresh
manifest can be published.

If `up` reports missing or stale peer material, inspect `peers list`. Use
`keys generate --peer NAME` for missing keys and `phone-config NAME` for a
missing, modified, or stale generated configuration.

## Docker integration tests fail

Docker is not part of production. It is required only by
`./test --integration`, after the native pasta/bubblewrap tests pass. Confirm the
daemon and Compose plugin are available. The disposable service runs as fixed
`0:0` inside its isolated test environment; host UID/GID values are not read.
