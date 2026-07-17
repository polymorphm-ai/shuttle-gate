# Quick Start

Install the [runtime requirements](../README.md#runtime-requirements). Commands
without `--instance` use the application checkout as the instance directory.
For separate state, create a dedicated directory and put the global option
before every command:

```console
mkdir -m 700 -- /home/me/shuttle-gate-office
cd -- /home/me/shuttle-gate-office
/path/to/shuttle-gate --instance . init
```

The remaining examples use the colocated default; for the separate layout,
replace `./shuttle-gate` with `/path/to/shuttle-gate --instance .`.

## 1. Prepare the local instance

```console
./shuttle-gate init
```

This creates intentional persistent `config.yaml`, `secrets/`, and `state/`
paths. It does not install host packages or change host networking. Edit the
configuration:

- bind only exact addresses already owned by the laptop;
- set an endpoint address or name reachable by the phone;
- set the SSH account and selected target networks;
- give every device unique `/32` and/or `/128` peer addresses;
- choose one routed DNS upstream, or disable DNS.

See [Configuration](configuration.md) for all fields.

Instance paths are canonicalized, so symlink aliases select the same instance.
Spaces, Unicode, shell punctuation, and components beginning with whitespace or
`-` are supported. Quote such paths in the calling shell. Control characters,
missing directories, `/`, the user's home directory, and paths overlapping a
separate application checkout are rejected.

## 2. Prepare SSH authentication

```console
./shuttle-gate ssh-key generate
./shuttle-gate ssh-key instructions
```

Generation prints an operation ID before changing local files. If interrupted,
repeat with `--operation-id ID`; a durable receipt prevents a second key from
being generated. Use `--force` only for intentional replacement.

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
material and a configuration under `state/current/peers/NAME/`. `current` is an
atomic pointer to a complete generation; never edit below it.

`phone-config --output exports/FILE` writes an atomic mode-`0600` copy below
the private, ignored `exports/` directory. Absolute, nested, and symlinked
destinations are rejected because paths outside the operator sandbox cannot be
published safely. `--stdout` exposes private material to the terminal and
should normally be avoided. Transfer the file securely and remove extra copies.

Stop the gateway before generating, rotating, pruning, or regenerating state.
If a rotation outcome is unknown, repeat the same operation ID:

```console
./shuttle-gate keys rotate-peer phone --yes --operation-id ID
```

## 4. Check and start

```console
./shuttle-gate doctor
./shuttle-gate up
./shuttle-gate status
```

`doctor` checks host programs, the systemd user manager, exact UDP binding, and
then uses a disposable pasta/bubblewrap namespace to test WireGuard, native
nftables TPROXY for configured IP families, strict SSH, and remote Python. Its
remote action is a bounded version check; it writes no remote file.

`up` starts a transient systemd user service. It exposes only the configured UDP
socket through pasta; all gateway networking stays in its rootless namespace.
The phone still needs firewall/NAT permission to reach that socket. The toolkit
does not modify host firewall policy.

Different instances have independent units, locks, state, namespaces, and
credentials. Their inner addresses may repeat, but their exact host
address/UDP-port tuples must not. A lifetime lock rejects duplicate tuples
before starting pasta and leaves existing instances running.

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
