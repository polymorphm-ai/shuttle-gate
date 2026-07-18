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

Production requires only the system tools listed in the README. uv stores its
managed Python and locked packages in the normal user cache. Intentional
instance state is limited to `config.yaml`, `secrets/`, `state/`, and explicit
sensitive copies below ignored `exports/`. Transient launch inputs, the
immutable code bundle, socket claims, and status live below `XDG_RUNTIME_DIR`;
persistent state and lifecycle lock files remain below instance `state/`. The
default instance is private under
`${XDG_CONFIG_HOME:-$HOME/.config}/shuttle-gate/default`; no persistent data is
written beside application code.

Every command that reads `config.yaml` opens it without following its final
symbolic link and requires a regular file with owner-only permissions. SSH
identities and known-hosts files are likewise checked before use; secret
symlinks may not escape the selected instance.

The toolkit creates no host interface, route, nftables rule, DNS process,
container, or root-owned file. ID 0 inside the pasta user namespace maps to the
unprivileged caller. Do not clean the uv cache while a gateway is active; stop
the service first so a later restart can reproduce its locked environment.

Docker and Compose are testing dependencies only. Integration containers use
fixed IDs rather than importing host UID/GID values.

## Runtime boundaries

The transient systemd user unit supplies bounded restart and resource policy.
It retries only exit status 75, reserved for classified transient failures.
An immutable outer supervisor holds ordered advisory locks for every exact host
UDP tuple throughout the child lifetime. A conflict is permanent and starts no
gateway runtime; unrelated instances retain their locks and processes.
`pasta` creates the private user/network namespace with automatic TCP, reverse
TCP/UDP, and gateway mappings disabled; only validated WireGuard UDP sockets are
forwarded from exact host addresses.

Inside that namespace, bubblewrap drops all capabilities and restores only
namespace-local `CAP_NET_ADMIN`. The application and full instance trees are
absent. System files, configuration, credentials, the state tree, code bundle,
and launch manifest are read-only. The runtime resolves and locks one immutable
state generation.
Only that exact lock file and a volatile output directory are writable. Digests
and schema bounds are checked both before service creation and inside the
sandbox.

Short-lived operator sandboxes expose immutable application code read-only and
the selected instance at their original absolute host paths. The roots must be
separate and non-overlapping. This makes printed paths truthful without exposing
sibling or parent host content. Sensitive exports are restricted to one direct
file below the private `exports/` directory; paths outside it and symbolic links
are rejected. Broad paths, missing explicit instance directories, overlaps, and
control characters are rejected before mounting. Only an exact `init` command
may create the known default path; retries after interruption remain safe.

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

Native nftables captures only TCP/UDP inside declared routes. The SSH endpoint,
peer networks, multicast, and limited broadcast are excluded. Forwarding
defaults to drop, so proxy failure cannot become direct pasta egress. The
toolkit never edits the host firewall; external reachability remains an explicit
operator decision.

Phone DNS uses one configured upstream through the ordinary routed UDP path. No
host resolver data or DNS forwarder is exposed to peers. The sandbox reads a
host uplink resolver file only to bootstrap an SSH hostname; it is read-only and
private to the namespace. ICMP, raw protocols, multicast, broadcast, and Layer
2 are unsupported.

Selected routing minimizes impact. Full routing expands the confidentiality and
availability trust placed in the laptop, SSH account, and remote server, while
still not providing a packet-level VPN.

## Operational guidance

- Verify SSH host keys out of band and bind only trusted laptop addresses.
- Use one WireGuard peer per device and rotate only a lost peer where possible.
- Re-run `doctor` after kernel, systemd, namespace-tool, SSH, or IPv6 changes.
- Keep operation IDs until completion; reuse one only to reconcile its operation.
- Treat phone configurations, status, and logs as operator-sensitive data.
