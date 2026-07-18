# Configuration Reference

The schema version is `1`. Unknown fields are errors. Addresses and networks are
normalized before any namespace is started.

## Top level

- `version`: must be `1`.
- `project`: lowercase logical instance name using letters, digits, and hyphens.

The canonical instance-directory path, not `project` or the application path,
identifies its transient systemd unit and XDG runtime directory. Symlink aliases
therefore select the same instance. Without `--instance`, the directory is
`${XDG_CONFIG_HOME:-$HOME/.config}/shuttle-gate/default`. Use `--instance PATH`
before the command to select an existing alternative. Application and instance
directories must be separate and non-overlapping.

The operational `config.yaml` must be a regular, non-symlink file whose mode
does not grant group or other access (normally `0600`). Every command that
parses it applies this check first. The public `config.example.yaml` is only a
template and is not used as an operational configuration.

## `wireguard`

- `bind_addresses`: exact unicast addresses already present on the laptop.
  Wildcards and multicast are rejected. Each address becomes one explicit pasta
  UDP forward. An IPv6 link-local bind must use `ADDRESS%HOST_INTERFACE`; scopes
  are rejected on other addresses.
- `endpoint_host`: laptop address or DNS name placed in phone configurations.
  IPv6 literals are bracketed automatically. A link-local endpoint requires an
  explicit client-side `%INTERFACE` scope, which may differ from the host bind
  interface; prefer IPv4, global IPv6, or DNS for portable multi-client configs.
- `listen_port`: UDP port, default `51820`. It must be at or above the host's
  unprivileged-port threshold.
- `gateway_addresses`: at most one IPv4 and one IPv6 interface address, such as
  `10.77.0.1/24` and `fd77::1/64`.
- `mtu`: WireGuard MTU, `1280` through `9000`.
- `peers`: named devices with unique `/32` and/or `/128` addresses inside the
  gateway networks and a bounded keepalive value.

Removing a YAML peer does not immediately remove secret state. Review and run:

```console
./shuttle-gate keys prune --yes
```

## `ssh`

- `host`, `user`, and `port`: SSH destination. A link-local IPv6 host requires
  the laptop-side `%INTERFACE` scope.
- `identity_file`: instance-relative private key below `secrets/`.
- `known_hosts_file`: instance-relative verified host-key file below `secrets/`.
- `remote_python`: safe executable name or absolute path, without arguments.
- timeout and keepalive fields: bounded SSH failure detection.

Authentication is batch-only and public-key-only, with `IdentitiesOnly=yes` and
strict host-key checking. Interactive password mechanisms are disabled.
Secret paths may contain unusual printable filename characters, but control
characters are rejected so commands and diagnostics remain unambiguous. Path
resolution must remain below the selected instance's `secrets/` directory;
symbolic-link escapes are rejected.

## `routing`

Selected routing is the safe default:

```yaml
routing:
  mode: selected
  networks:
    - 10.0.0.0/8
    - "fd20:1234::/48"
```

Networks must be unique, non-default, outside multicast space, and use only
families present in `wireguard.gateway_addresses`. Full routing is explicit and
omits `networks`:

```yaml
routing:
  mode: full
```

Full mode derives defaults only for configured WireGuard families. Multicast
and limited broadcast stay excluded; unmatched forwarding is dropped.

## `dns`

DNS is disabled or names one explicit unicast upstream:

```yaml
dns:
  enabled: true
  upstream: "fd20:1234::53"
```

The phone names this upstream directly; it never uses a gateway DNS address.
Inside the namespace, nftables sends UDP port 53 to sshuttle's in-process DNS
path, while TCP port 53 uses ordinary transparent TCP. The upstream address
must be covered by routing, and every peer must have the same address family.
Host resolvers and search domains are never imported.

## `backend`

The backend is deliberately fixed:

```yaml
backend:
  mode: sshuttle
  method: nft-tproxy
  startup_timeout_seconds: 45
```

It supports TCP, unicast UDP, DNS, IPv4, and IPv6 with native nftables. Unknown
backend values are rejected.

After a route, endpoint, DNS, peer, or key change, regenerate and re-import phone
configurations. Startup rejects missing, modified, or stale generated configs
and their fingerprints. Run `down` before persistent state changes. If a key
operation is interrupted, retry with its printed `--operation-id`; use a fresh
ID for a new intentional operation.
