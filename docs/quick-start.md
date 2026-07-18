# Quick Start

Install the [runtime requirements](../README.md#runtime-requirements). Commands
without `--instance` use the private default at
`${XDG_CONFIG_HOME:-$HOME/.config}/shuttle-gate/default`. This location is
independent of the application directory and current working directory.

For another instance, create a dedicated directory and put the global option
before every command:

```console
mkdir -m 700 -- /home/me/shuttle-gate-office
cd -- /home/me/shuttle-gate-office
/path/to/shuttle-gate --instance . init
```

The remaining examples use the XDG default. For an explicit instance, add
`--instance PATH` to every invocation.

## 1. Prepare the local instance

```console
./shuttle-gate init
```

This creates private `config.yaml`, `secrets/`, and `state/` paths without
writing to the application directory or changing host networking. Edit the
configuration path printed by `init`:

- bind only exact addresses already owned by the laptop;
- set an endpoint address or name reachable by the phone;
- set the SSH account and selected target networks;
- give every device unique `/32` and/or `/128` peer addresses;
- choose one routed DNS upstream, or disable DNS.

See [Configuration](configuration.md) for all fields.

An explicit instance must already exist and must not overlap the application
directory. Printable unusual paths are supported; quote them in the shell.

## 2. Prepare SSH authentication

```console
./shuttle-gate ssh-key generate
./shuttle-gate ssh-key instructions
```

Generation prints an operation ID. If interrupted, repeat with
`--operation-id ID`; use `--force` only for intentional replacement.

The instructions command only prints commands. The toolkit never runs
`ssh-copy-id`, `ssh-keyscan`, or anything that modifies the SSH server. If you
are authorized, run the printed setup command yourself. Verify collected host
key fingerprints through a separate trusted channel: `ssh-keyscan` alone does
not authenticate them.

An existing dedicated key may instead be placed at its configured path under
`secrets/` with mode `0600`, accompanied by verified `known_hosts` data.

## 3. Generate WireGuard material

```console
./shuttle-gate config validate
./shuttle-gate keys generate
./shuttle-gate peers list
./shuttle-gate phone-config phone
```

Repeated generation preserves existing keys. Each peer receives separate key
material and a configuration under `state/current/peers/NAME/`; never edit
generated state. `keys generate --peer NAME` affects only that peer, while the
command without `--peer` covers every declared peer. `peers list` reports each
configuration as `current`, `stale`, or `missing`.

`phone-config NAME` regenerates only that peer's derived configuration. Other
peer files remain unchanged, even if they are missing or stale. Startup checks
that every declared peer is complete and current.

`phone-config --output exports/FILE` writes a mode-`0600` copy below the
private, ignored `exports/` directory. Other destinations are rejected.
`--stdout` exposes private material to the terminal and should normally be
avoided. Transfer the file securely and remove extra copies.

Stop the gateway before generating, rotating, pruning, or regenerating state.
If a rotation outcome is unknown, repeat the same operation ID:

```console
./shuttle-gate keys rotate-peer phone --yes --operation-id ID
```

Peer rotation changes and regenerates only the named peer. Re-import that
peer's new configuration. Server rotation necessarily regenerates every peer
configuration; re-import all of them.

## 4. Check and start

```console
./shuttle-gate doctor
./shuttle-gate up
./shuttle-gate status
```

`doctor` checks host programs, UDP binding, namespace networking, strict SSH,
and remote Python. Its remote action is a bounded version check and writes no
remote file.

`up` starts a transient systemd user service. It exposes only the configured UDP
socket through pasta; all gateway networking stays in its rootless namespace.
The phone still needs firewall/NAT permission to reach that socket. The toolkit
does not modify host firewall policy.

Instances have independent services, state, namespaces, and credentials. Their
inner addresses may repeat, but exact host address/UDP-port tuples must not.

## 5. Operate and stop

```console
./shuttle-gate status --json
./shuttle-gate logs --follow
./shuttle-gate down
```

Logs come from the systemd user journal. Use `down` for normal shutdown; it is
safe to retry. Namespace destruction is the final network-cleanup boundary.

The service normally follows the lifetime of the user manager. The toolkit does
not enable lingering. If explicit host policy requires operation after logout,
the operator may separately enable lingering for that account.
