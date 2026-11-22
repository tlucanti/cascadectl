The bootstrap runs from your control machine and provisions both VPSs through SSH. Its default operation installs software and starts project services. `--plan` is completely offline; `--check` performs read-only server checks, with local known-host recording if you request first-use trust.

Prepare two Ubuntu 24.04 VPSs with:

- Native IPv4 and globally reachable native IPv6 already assigned to the selected WAN interfaces, and working IPv6 default routes. Public IPv4 must be directly assigned, not merely a provider's external NAT mapping.
- `/dev/net/tun`, systemd, Python 3, `ip`, `ss`, and SSH. Both CPU architectures must match (`x86_64` or `aarch64`). Allow at least 512 MiB free disk on entry, 2 GiB on exit, and about 1 GiB RAM for the conservative single-worker source build.
- An allocated European IPv6 `/64` whose unused addresses the provider permits you to assign. An on-link `/48` or a single configured IPv6 address does not establish ownership of neighboring addresses.
- Administrative access: root or sudo on both servers. The exit must allow root **public-key** SSH login for the restricted rotation key. Bootstrap does not change `sshd_config` or enable root password login.
- A dedicated entry without Docker forwarding rules. The exit can already run Docker/Xray with its iptables `DOCKER-USER` chain. Its existing containers and port bindings are preserved.

Allow the entry UDP port from clients over IPv4, and the hop UDP port over IPv6 between the VPSs. The defaults are entry `443/UDP` and hop `51821/UDP`. Provider firewalls are separate from host rules. Essential ICMPv6 and neighbor discovery must work. The entry's route to the exit must select the configured entry IPv6 as its source.

The private address plan and interface names are reserved by this implementation: `10.77.0.0/24`, `10.78.0.0/30`, `fd67:a2e4:9b01:1::/64`, `awg-clients`, `awg-eu`, `awg-ru`, routing table `220`, and policy priorities `10000`, `10010`, `10020`. Preflight rejects overlaps and unrelated uses. Active UFW/firewalld or other input/forward drop policies need explicit integration; bootstrap does not remove a pre-existing host firewall.

Copy `examples/cascade.example.json` to `config.local.json`. Replace every documentation address. Fields are:

| Field | Meaning |
|---|---|
| `entry.ipv4`, `entry.ipv6`, `entry.wan` | Entry's assigned native addresses and WAN interface |
| `exit.ipv4`, `exit.ipv6`, `exit.wan` | Exit's IPv4 egress, stable primary IPv6, and WAN interface |
| `exit.ipv6_prefix` | Provider-confirmed allocated `/64` |
| `*.ssh.host`, `user`, `port` | SSH administrative destination; the SSH host may differ from the public endpoint |
| `*.ssh.identity_file` | Optional private-key path; otherwise the usual SSH agent/default identities are used |
| `*.ssh.password_file` | Optional one-line local password file; no password values are accepted in JSON |
| `entry_port`, `hop_port` | UDP ports; they must differ, and the hop port cannot be DNS port 53 |
| `mtu` | Shared tunnel/client MTU, default `1280`; requires encapsulation headroom on both WANs |
| `clients` | Device names to ensure exist, up to 15 letters/digits/underscores/hyphens each |

Relative credential paths resolve beside the configuration file; `~` expands to the control user's home. Password files must be owned by that user and have mode `0600` or `0400`. Passwords are provided through OpenSSH askpass and sudo stdin, never command arguments. The sudo password must match that host's password file; use passwordless sudo if the account uses a separate sudo password. Encrypted SSH keys should be unlocked in the agent.

For example, a host can use:

```json
"ssh": {
  "host": "198.51.100.10",
  "user": "ubuntu",
  "port": 22,
  "identity_file": null,
  "password_file": "~/.config/awg-cascade/entry.password"
}
```

Keep password files outside the checkout. `config.local.json`, `.local/`, exported `profiles/`, backups and private-key extensions are ignored by Git. No live VPN profiles are part of the source tree.

Review the plan:

```sh
./bootstrap.sh --config config.local.json --plan
```

For first-use SSH trust, compare the VPS SSH host fingerprints with your provider console. You can connect interactively using the dedicated known-host file:

```sh
mkdir -p .local
chmod 700 .local
ssh -o UserKnownHostsFile="$PWD/.local/known_hosts" ubuntu@ENTRY_IPV4
ssh -o UserKnownHostsFile="$PWD/.local/known_hosts" root@EXIT_IPV4
```

Alternatively, pass `--accept-new-host-keys` to the first check. This uses OpenSSH `accept-new`, which accepts unseen keys and rejects changed keys. It does not verify a fingerprint independently.

```sh
./bootstrap.sh --config config.local.json --check --accept-new-host-keys
./bootstrap.sh --config config.local.json --profiles-dir .local/profiles
```

Provisioning proceeds in this order:

1. Inspect both hosts and validate OS, architecture, assigned addresses, routes, ports, forwarding-policy compatibility and available space.
2. Save root-only baseline archives and firewall/routing snapshots under `/root/awg-cascade-backups/`.
3. Install required APT packages. Selected dependencies may be updated; a full distribution upgrade is not performed. Service restarts by needrestart are deferred.
4. Fetch the official source tags in `config/versions.json`, verify their exact commits, and build on the exit. Go's automatic toolchain selection supplies the version required by the pinned module. Builds use one worker and conservative garbage collection for small VPSs.
5. Transfer the three binaries through SSH and verify SHA-256 digests before installation on entry. Server private keys are generated and retained on their own hosts. Only the shared hop material crosses the administrative SSH sessions.
6. Install the checked-in services and DNS template, preserve or create databases, render peer configurations and ensure requested client profiles exist.
7. Install an Ed25519 key from entry to exit, restricted by source addresses, forced command, subnet ownership checks and OpenSSH `restrict`. Pin the exit host key and verify that this restricted command actually works.
8. Fetch and validate the RU prefix list; start exit before entry; check tunnel reachability and private DNS; enable health and country-list timers; create private current backups.

The exit's dedicated Unbound service binds only `10.78.0.2`. It uses its own trust-anchor file. An existing Unbound service is retained; a packaged default installed by this bootstrap is disabled in favor of the dedicated service. A wildcard DNS listener is rejected during preflight.

`--profiles-dir` explicitly exports private profiles. Inside this checkout, use `.local/` or `profiles/`; exports into other source directories are rejected. Each file is mode `0600`. If omitted, profiles remain on the entry at `/etc/cascade/profiles/`.

For matching trusted binaries already installed on the exit:

```sh
./bootstrap.sh --config config.local.json --skip-build
```

This checks reported versions and records checksums; it relies on the operator's trust in those preinstalled binaries. The normal source build verifies upstream commit IDs. No prebuilt binaries or signing keys are bundled.

Rerun the same configuration to resume an interrupted install or restore project files. Keys, profiles, overrides and owned aliases are retained. New names in `clients` are added; omitted existing names are not revoked. Use `clients: []` to retain existing devices without adding any. The ignored local configuration supplied in this prepared checkout uses that setting.

A rerun does not implicitly migrate public addresses, WAN interfaces, ports, subnet or client MTU. It also refuses missing live keys/databases, shared-key disagreement, unrecognized files in `/etc/cascade`, and a disagreement between the entry endpoint and exit's active transport source. Resolve those from a backup or through the documented recovery workflow first.

`--restart` restarts only the project tunnel services to apply updated binaries/service settings:

```sh
./bootstrap.sh --config config.local.json --skip-build --restart
```

The exit DNS service follows its tunnel restart. Docker is not restarted. If Docker is installed later, rerun bootstrap while Docker is running so its scoped forwarding integration is installed. Docker's experimental nftables backend requires separate integration.

After installing, test a real client, inspect `sudo cascadectl health`, and perform a controlled reboot when appropriate for your services. The bootstrap itself never reboots a VPS. See [testing](TESTING.md) for validation details and [usage](USAGE.md) for routine operations.
