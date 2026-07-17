# Troubleshooting

Start with these commands:

```console
./shuttle-gate config validate
./shuttle-gate doctor
./shuttle-gate status
./shuttle-gate logs --tail 200
```

## Docker or build fails

Confirm the Docker daemon is running and your user can access it. The first
build needs registry and package-index access; later runs use Docker's build
cache. The host launcher does not install missing components.

`docker compose config --quiet` checks the static file. Generated port bindings
are created by `./shuttle-gate up` after full local validation.

## WireGuard or TPROXY doctor check fails

The Linux host kernel must provide WireGuard, nftables socket matching, TPROXY,
IPv4 policy routing, and IPv6 policy routing when IPv6 is configured. The
doctor container cannot install or load unsupported host kernel features. Use a
kernel supplied and approved by the host administrator.

The project uses native nftables only. Installing a legacy compatibility tool
does not fix a failed doctor check.

## SSH check fails

- Confirm `secrets/id_ed25519` is mode `0600`.
- Confirm the public key is authorized for the configured user.
- Confirm `secrets/known_hosts` contains the verified key for the exact host and
  port.
- Test whether server policy permits a normal non-interactive SSH session.
- Confirm the configured remote Python executable exists and is Python 3.9+.

Do not fix this by asking the toolkit to change the server. Server-side key or
policy changes must be explicit actions by an authorized administrator.

## Phone has no WireGuard handshake

- `bind_addresses` must exist on the laptop.
- `endpoint_host` must resolve to an address the phone can reach.
- The configured UDP port must pass the laptop firewall, Wi-Fi client isolation,
  upstream NAT, and any mobile network filtering.
- The phone must use the newest generated configuration after a key rotation.

## Handshake works, but target TCP does not

Check that the destination is inside a configured route and not the SSH server
itself. Confirm the SSH account can reach the target from the remote server.
Review logs for sshuttle startup or connection errors. Ping is not a valid test;
ICMP is deliberately unsupported. Use an actual TCP client such as a browser or
SSH app.

## DNS does not work

The DNS upstream must be one explicit IP covered by routing. It must accept UDP
queries from the SSH server's network position. Re-import the phone config after
enabling DNS because the local gateway DNS address is part of that config.

The host resolver and search domains are not copied automatically. Query names
exactly as the selected upstream expects them.

## UDP application does not work

Only unicast UDP is captured. Broadcast discovery, multicast discovery, raw
protocols, and ICMP do not traverse the gateway. sshuttle maintains temporary
UDP flow mappings, so applications that depend on unusually long idle flows,
source-address behavior, fragmentation, or very large datagrams may fail even
when simple UDP and DNS work.

## IPv6 does not work

Check all four layers independently: a reachable IPv6 WireGuard endpoint on the
laptop, Docker IPv6 port publication, IPv6 addresses/routes for the peer, and
IPv6 reachability from the SSH server to the target. No IPv4 fallback is
performed for an IPv6 route.

## Stale state or interrupted shutdown

Run `./shuttle-gate down`, then `./shuttle-gate up`. Runtime networking lives in
the container namespace and is destroyed with the container. Persistent key
state is never deleted by `down`. Use `keys prune --yes` only after reviewing
peer names removed from YAML.
