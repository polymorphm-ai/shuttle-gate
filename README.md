# shuttle-gate

`shuttle-gate` is a rootless WireGuard-to-SSH gateway for Linux. A phone
connects to one exact laptop address. Selected or full-route IPv4/IPv6 TCP,
unicast UDP, and DNS traffic then travels through an existing SSH account by
way of sshuttle.

Production does not use Docker and does not change host networking. A transient
systemd user service starts `pasta`, which creates a private user/network
namespace, and `bubblewrap`, which exposes only the required files. WireGuard,
nftables, policy routing, and sshuttle live inside that namespace. Python and
application packages are supplied by locked `uv` scripts and remain in the uv
cache. The remote SSH server is never installed, configured, or modified.

## Runtime requirements

- a current systemd-based Linux host with unprivileged user namespaces;
- kernel WireGuard, native nftables TPROXY, and IPv6 support when configured;
- `uv`, `passt`/`pasta`, `bubblewrap`, `iproute2`, `nftables`,
  `wireguard-tools`, and the OpenSSH client;
- an active systemd user session with `XDG_RUNTIME_DIR`;
- an SSH account with Python 3.9+ and normal target-network egress;
- a phone that can reach the configured laptop address and UDP port.

No host Python, virtual environment, sshuttle installation, DNS forwarder, or
Docker runtime is required. On Arch Linux, install the runtime tools with:

```console
sudo pacman -S --needed uv passt bubblewrap iproute2 nftables wireguard-tools openssh
```

The first command may download a compatible Python 3.14+ interpreter and locked
packages into uv's user cache. Later launches reuse that cache.

Docker Engine with Compose is required only for `./test --integration`. Those
tests use fixed container IDs and do not derive UID/GID values from the host.

## Start here

```console
./shuttle-gate init
# Edit config.yaml.
./shuttle-gate ssh-key generate
./shuttle-gate ssh-key instructions
# Run the printed setup commands yourself; verify the SSH host fingerprint.
./shuttle-gate config validate
./shuttle-gate keys generate
./shuttle-gate phone-config phone
./shuttle-gate doctor
./shuttle-gate up
./shuttle-gate status
```

Import `state/current/peers/phone/phone.conf` into the WireGuard app. It contains
private key material; use a trusted transfer channel and delete extra copies.
Stop with `./shuttle-gate down`; inspect the systemd journal with
`./shuttle-gate logs`.

The service belongs to the current user manager and normally stops with that
manager. The toolkit never enables lingering. If operation after logout is
required, the operator may explicitly run `loginctl enable-linger "$USER"`
after reviewing the host-policy impact.

## Traffic contract

Supported traffic is TCP, general unicast UDP, and optional DNS over declared
IPv4/IPv6 routes. Full routing derives `0.0.0.0/0` and/or `::/0`, but this is
not a packet-level VPN: ICMP, raw IP, multicast, broadcast, and Layer 2 are not
forwarded. Some long-lived or unusual UDP applications may be incompatible
with sshuttle.

## Documentation

- [Quick start and phone setup](docs/quick-start.md)
- [Configuration reference](docs/configuration.md)
- [Architecture and packet flow](docs/architecture.md)
- [Security and isolation model](docs/security.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Development guide](docs/development.md)
