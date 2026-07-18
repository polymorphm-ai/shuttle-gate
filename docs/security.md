# Security and Isolation

## Trust boundaries and secrets

The operator controls this repository, local configuration, phone peers, and
the SSH account. Target-network and SSH-server policy still apply. Use the
gateway only with authorization.

Phone configurations, WireGuard private/preshared keys, and the SSH private key
are secrets. They are ignored by Git, stored in mode-restricted paths, mounted
read-only at runtime, and never copied into the application bundle or test
image. Operation receipts contain identifiers, paths, hashes, and non-secret
results only.

## Clean host contract

Production uses only the system tools listed in the README plus uv-managed
Python and packages in the user cache. Instance data stays in the selected
directory; launch inputs, socket claims, and status stay below
`XDG_RUNTIME_DIR`. Nothing persistent is written beside application code.

Every command that reads `config.yaml` opens it without following its final
symbolic link and requires a regular file with owner-only permissions. SSH
identities and known-hosts files are likewise checked before use; secret
symlinks may not escape the selected instance.

The toolkit creates no host interface, route, nftables rule, DNS process,
container, or root-owned file. ID 0 inside the pasta user namespace maps to the
unprivileged caller. Do not clean the uv cache while a gateway is active; stop
the service first so a later restart can reproduce its locked environment.

Docker and Compose are testing dependencies only.

## Runtime boundaries

The transient systemd user unit supplies bounded restart and resource policy.
Only classified transient failures are retried. A supervisor holds every exact
host UDP tuple for the child lifetime; conflicts start no gateway and leave
unrelated instances running. `pasta` forwards only validated WireGuard UDP
sockets into the private user/network namespace.

Inside that namespace, bubblewrap retains only namespace-local
`CAP_NET_ADMIN`. Configuration, credentials, state, code, and launch metadata
are read-only; the full application and instance trees are absent. Host-backed
write access is limited to the state lock and bounded volatile output. Inputs
are validated both before service creation and inside the sandbox.

Operator sandboxes expose immutable code and only the selected instance at
their original paths. Roots must be separate; broad paths, control characters,
and symbolic-link escapes are rejected. Sensitive exports are restricted to a
direct file below the private `exports/` directory.

The host launcher allowlists public operator commands and rejects hidden
runtime-only entry points, preventing code from running with the wrong mount
contract.

## Remote SSH server contract

The toolkit never installs packages, copies files, edits `authorized_keys`,
changes firewall/routing, starts services, or leaves a persistent process on
the SSH server. sshuttle starts a temporary Python process through the existing
session; it exits with that session. Normal authentication and audit records are
unavoidable observations.

`ssh-key instructions` prints setup commands but executes none. If an authorized
operator runs `ssh-copy-id`, that separate action changes the remote account. If
absolute immutability is required, use a key already authorized by the owner.

## Network policy

Native nftables captures only TCP/UDP entering through `wg0` inside declared
routes. It has no transparent-proxy output hook, so namespace control traffic
such as WireGuard transport and SSH cannot be captured. Peer networks,
multicast, and limited broadcast are excluded from forwarded
selection. Forwarding defaults to drop, so proxy failure cannot become direct
pasta egress. The toolkit never edits the host firewall; external reachability
remains an explicit operator decision.

DNS follows the same routed TCP/UDP path as other traffic. ICMP, raw protocols,
multicast, broadcast, and Layer 2 are unsupported. Broader routes increase the
confidentiality and availability trust placed in the laptop, SSH account, and
remote server; this remains a stream proxy rather than a packet-level VPN.

## Operational guidance

- Verify SSH host keys out of band and bind only trusted laptop addresses.
- Use one WireGuard peer per device and rotate only a lost peer where possible.
- Re-run `doctor` after kernel, systemd, namespace-tool, SSH, or IPv6 changes.
- Keep operation IDs until completion; reuse one only to reconcile its operation.
- Treat phone configurations, status, and logs as operator-sensitive data.
