# Configuration Reference

The schema version is `1`. Unknown fields are errors. IP addresses and networks
are normalized and validated before any network state changes.

## Top level

- `version`: must be `1`.
- `project`: lowercase name used as the Docker Compose project name; use letters,
  digits, and hyphens.

## `wireguard`

- `bind_addresses`: one or more exact unicast addresses already present on the
  laptop. `0.0.0.0`, `::`, and multicast addresses are rejected.
- `endpoint_host`: laptop address or DNS name placed in phone configurations.
  IPv6 literals are bracketed automatically.
- `listen_port`: UDP port, default `51820`.
- `gateway_addresses`: at most one IPv4 and one IPv6 interface address, such as
  `10.77.0.1/24` and `fd77::1/64`.
- `mtu`: WireGuard MTU, `1280` through `9000`.
- `peers`: non-empty list of named phone peers. Each peer has unique host
  addresses (`/32` for IPv4, `/128` for IPv6) inside the gateway networks and a
  `persistent_keepalive_seconds` value.

Multiple peers are declared in YAML and generated separately. Removing a peer
from YAML does not immediately delete its secret state. Review and run:

```console
./shuttle-gate keys prune --yes
```

## `ssh`

- `host`, `user`, and `port`: SSH destination.
- `identity_file`: project-relative private key path below `secrets/`.
- `known_hosts_file`: project-relative verified host-key file below `secrets/`.
- `remote_python`: safe executable name or absolute path, without arguments.
- `connect_timeout_seconds`, `server_alive_interval_seconds`, and
  `server_alive_count_max`: bounded SSH failure detection.

Authentication is batch-only, public-key-only, uses `IdentitiesOnly=yes`, and
requires strict host-key checking. Password and keyboard-interactive prompts
are disabled.

## `routing`

Selected routing is the safe default:

```yaml
routing:
  mode: selected
  networks:
    - 10.0.0.0/8
    - "fd20:1234::/48"
```

Networks must be unique, cannot be default routes, and cannot overlap multicast
space. Use full routing explicitly and omit `networks`:

```yaml
routing:
  mode: full
```

Full mode derives a default route only for address families configured on the
WireGuard gateway. Multicast and limited broadcast ranges remain excluded, and
uncaptured forwarding is dropped.

## `dns`

DNS is either disabled:

```yaml
dns:
  enabled: false
```

or uses exactly one explicit unicast upstream covered by the selected routes:

```yaml
dns:
  enabled: true
  upstream: "fd20:1234::53"
```

Phones query the WireGuard gateway address. A private dnsmasq instance forwards
only to this upstream; host resolver configuration is not imported.

## `backend`

The only supported backend is fixed deliberately:

```yaml
backend:
  mode: sshuttle
  method: nft-tproxy
  startup_timeout_seconds: 45
```

The method supports TCP, unicast UDP, DNS, IPv4, and IPv6 with native nftables.
Other backend strings are rejected instead of silently changing behavior.

After route, endpoint, DNS, peer, or key changes, regenerate phone configs.
Startup rejects stale fingerprints so an old imported configuration is not used
by accident.
