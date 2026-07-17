# Security and Isolation

## Trust boundaries

The operator controls this repository, local configuration, phone peers, and
the SSH account. Target-network policy and SSH-server policy still apply. Use
the gateway only with authorization from the owners of those systems.

The phone configuration, WireGuard private/preshared keys, and SSH private key
are secrets. They are excluded by `.gitignore`, stored in mode-restricted local
paths, mounted read-only into the runtime, and never copied into an image.
Generated WireGuard key text is validated before it can enter a configuration.

## Clean host contract

The host needs Docker, Compose, `uv`, and Python 3.14. It does not need a Python
environment, WireGuard tools, sshuttle, dnsmasq, nftables user tools, or test
packages. Docker images, containers, networks, and published ports are expected
Docker-managed effects. Project-local `config.yaml`, `secrets/`, and `state/`
are intentional persistent data.

The launcher uses an offline, no-cache `uv run --script` shebang with an empty
dependency list. Application dependency resolution and all quality checks occur
inside locked Docker images.

## Remote SSH server contract

The toolkit does not install packages, copy files, edit `authorized_keys`, alter
firewall/routing, start services, or leave a persistent process on the SSH
server. sshuttle starts a temporary Python process over the existing SSH
session; it exits with that session. Normal SSH authentication/audit records are
an unavoidable server-side observation.

`./shuttle-gate ssh-key instructions` prints commands but executes neither of
them. If the operator runs `ssh-copy-id`, that explicit setup action changes the
remote account. If remote immutability must be absolute, use a key already
authorized by the server owner instead.

## Container permissions

The gateway drops all capabilities, then adds only:

- `NET_ADMIN` for WireGuard, routes, transparent sockets, and nftables;
- `NET_BIND_SERVICE` for the private DNS listener on port 53;
- `DAC_READ_SEARCH` to read host-owned credentials mounted read-only.

The root filesystem is read-only. `/run` and `/tmp` are tmpfs. Configuration,
secrets, and persistent state are read-only in the gateway. `no-new-privileges`
is enabled. The VPN port is published only on the exact configured host
addresses; wildcard binds are rejected.

## Network policy

Native nftables captures only TCP and UDP for declared routes. SSH recursion,
peer networks, multicast, and limited broadcast are excluded. The forward path
defaults to drop, preventing a transparent-proxy failure from becoming direct
Docker egress. ICMP, raw protocols, multicast, broadcast, and Layer 2 are not
forwarded.

Selected routing is recommended. Full routing expands the confidentiality and
availability impact of the laptop, SSH account, and target server. It still
does not provide a general packet VPN.

## Operational guidance

- Verify SSH host keys out of band; never trust raw `ssh-keyscan` output alone.
- Bind only to a trusted LAN/VPN address and keep the host firewall restrictive.
- Use one WireGuard peer per device; rotate only the lost device when possible.
- Treat `phone.conf`, status endpoints, and logs as operator data. Status omits
  private and preshared keys but includes public keys, endpoints, and counters.
- Run `down` before changing sensitive routing and re-run `doctor` after kernel,
  Docker, SSH, or IPv6 changes.
