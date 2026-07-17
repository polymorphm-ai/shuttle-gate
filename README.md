# shuttle-gate

`shuttle-gate` is a local WireGuard-to-SSH gateway for Linux. A phone connects
to a laptop with the official WireGuard client. The gateway sends selected or
full-route IPv4/IPv6 TCP, unicast UDP, and DNS traffic through an existing SSH
account with sshuttle.

The host stays clean: application packages, networking tools, nftables rules,
and quality tools run in Docker. Only intentional `config.yaml`, `secrets/`,
and `state/` files live in this directory. The remote SSH server is not
installed, configured, or changed by the toolkit.

## Requirements

- Linux host with kernel WireGuard, nftables TPROXY, and IPv6 support when used
- Docker Engine with Docker Compose
- `uv` and Python 3.14 or newer for the dependency-free host launchers
- an SSH account with Python 3.9+ and normal TCP/UDP egress to target networks
- a phone that can reach one exact laptop address on the configured UDP port

No host virtual environment or host network package is used.

## Start here

```console
./shuttle-gate init
# Edit config.yaml.
./shuttle-gate ssh-key generate
./shuttle-gate ssh-key instructions
# Run the printed setup commands yourself and verify the SSH host fingerprint.
./shuttle-gate config validate
./shuttle-gate keys generate
./shuttle-gate phone-config phone
./shuttle-gate doctor
./shuttle-gate up
./shuttle-gate status
```

Import `state/current/peers/phone/phone.conf` into the WireGuard mobile app.
This file contains private key material; transfer it through a trusted channel
and delete extra copies.

Stop the gateway with `./shuttle-gate down`. Use `./shuttle-gate logs` for
startup diagnostics.

## Traffic contract

Supported traffic is TCP, general unicast UDP, and optional DNS over selected
IPv4/IPv6 routes. `routing.mode: full` derives `0.0.0.0/0` and/or `::/0`, but
this is not a packet-level VPN: ICMP/ping, raw IP, multicast, broadcast, and
Layer-2 protocols are deliberately not forwarded. UDP applications that need
long-lived flows or unusual socket behavior may still be incompatible with
sshuttle.

## Documentation

- [Quick start and phone setup](docs/quick-start.md)
- [Configuration reference](docs/configuration.md)
- [Architecture and packet flow](docs/architecture.md)
- [Security and isolation model](docs/security.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Development guide](docs/development.md)
