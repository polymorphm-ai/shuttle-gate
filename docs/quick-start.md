# Quick Start

## 1. Prepare the local instance

Run commands from the repository root:

```console
./shuttle-gate init
```

This creates `config.yaml`, `secrets/`, and `state/` in the project directory.
It does not install Python packages or network tools on the host. Edit
`config.yaml` before continuing:

- set every `wireguard.bind_addresses` item to an address that already belongs
  to the laptop; wildcard addresses are rejected;
- set `wireguard.endpoint_host` to the address or DNS name the phone can reach;
- set the SSH host, user, and target networks;
- declare each phone or tablet as a named peer with unique `/32` and/or `/128`
  addresses;
- select one explicit DNS upstream, or disable DNS.

See [Configuration](configuration.md) for every field.

## 2. Prepare SSH authentication

Generate a dedicated local key:

```console
./shuttle-gate ssh-key generate
./shuttle-gate ssh-key instructions
```

The generate command prints an operation ID before changing files. Keep it
until the command finishes. If execution is interrupted, repeat the command
with `--operation-id ID`; the recorded result is returned without generating a
second key. Use `--force` only for an intentional replacement.

The second command only prints instructions. The toolkit never runs
`ssh-copy-id`, `ssh-keyscan`, or any command that edits the SSH server. Run the
printed `ssh-copy-id` command yourself if you are authorized to add the key.
That user action changes `authorized_keys`; it is outside toolkit execution.

The printed host-key collection command writes `secrets/known_hosts` locally.
`ssh-keyscan` does not authenticate the result. Verify its fingerprint through
a separate trusted channel before continuing.

If you already have a dedicated key, place it at the configured path below
`secrets/`, use mode `0600`, and create a verified `known_hosts` file.

## 3. Generate WireGuard material

```console
./shuttle-gate config validate
./shuttle-gate keys generate
./shuttle-gate peers list
```

Key generation is explicit and non-destructive. A repeated command keeps
existing keys. Each peer gets a separate private key, preshared key, phone
configuration, and configuration fingerprint under
`state/current/peers/NAME/`. `current` is an atomic pointer to one complete,
validated generation; never edit files below it directly.

Export or print one peer only when needed:

```console
./shuttle-gate phone-config phone
./shuttle-gate phone-config phone --output ./private-transfer/phone.conf
```

`--stdout` is available for controlled automation, but it exposes private key
material to the terminal and should normally be avoided.

Key rotations also print an operation ID. If their outcome is unknown, retry
with the same ID, for example:

```console
./shuttle-gate keys rotate-peer phone --yes --operation-id ID
```

Stop the gateway before generating, rotating, pruning, or regenerating state.
The running gateway holds a read lock on its exact generation.

## 4. Check and start

```console
./shuttle-gate doctor
./shuttle-gate up
./shuttle-gate status
```

`doctor` uses a disposable privileged container to test kernel WireGuard,
native nftables IPv4/IPv6 TPROXY, strict SSH authentication, and remote Python.
Its remote command is a bounded Python version check; it writes no remote file.

Import the generated `phone.conf` into the official WireGuard app and activate
it. The phone must be able to reach the configured endpoint on UDP port 51820
or the configured alternative. A host or network firewall may still need an
operator-approved rule outside this toolkit.

## 5. Operate and stop

```console
./shuttle-gate status --json
./shuttle-gate logs --follow
./shuttle-gate down
```

Always use `down` for a normal shutdown. The gateway also cleans its owned
interface, policy routes, and nftables tables on signals and startup failures.
Container namespace destruction provides a final cleanup boundary.
