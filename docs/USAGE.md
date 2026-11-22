`cascadectl` is installed as `/usr/local/sbin/cascadectl` on both hosts. The entry uses the internal role name `ru`; the exit uses `eu`, preserving the original on-server layout. Administrative commands require root. `cascadectl --help` works without root.

On entry:

```sh
sudo cascadectl status
sudo cascadectl health
sudo cascadectl client list
sudo cascadectl client add phone-04
```

Profiles are saved as `/etc/cascade/profiles/NAME.conf`. Each profile belongs to one device. There are 230 automatically allocated addresses (`10.77.0.10` through `.239`). Names use 1–15 letters, digits, underscores or hyphens. A failed live peer update restores the previous saved database/configuration.

For a non-root SSH account, copy an individual profile to that user's home with private permissions, then download it. Replace `ADMIN` with your login:

```sh
sudo install -m 600 -o ADMIN -g ADMIN /etc/cascade/profiles/phone-04.conf ./phone-04.conf
```

On your computer:

```sh
scp ADMIN@ENTRY_IPV4:phone-04.conf .
```

Remove the temporary copy in the login user's home after downloading. The canonical root-only copy remains available. To revoke a device:

```sh
sudo cascadectl client remove phone-04
```

Import a `.conf` file into an AmneziaWG 3.1-compatible client. Android can use **Always-on VPN** and **Block connections without VPN** to prevent bypass while disconnected. The profile captures both default routes; client Internet access uses IPv4. IPv6-only resources are unavailable. The interserver transport still uses native public IPv6.

Run rotation on the entry:

```sh
sudo cascadectl rotate
# Or choose an unused address inside the allocated /64:
sudo cascadectl rotate NEW_EXIT_IPV6
sudo cascadectl health
```

The automatic operation:

- Prepares/persists a new alias on exit through a restricted SSH command.
- Updates the entry's peer endpoint and IPv6 firewall set.
- Activates the exit's preferred transport source and clears its cached socket source.
- Probes the authenticated tunnel, persists the working endpoint, and retires the prior cascade-owned alias.
- Restores and probes the old endpoint/source if the candidate fails.

The primary exit IPv6 is retained, other services' IPv6 addresses are not claimed, and the active address cannot be retired. Client configuration files and entry routing policy remain unchanged. A brief traffic pause is possible. Rotation does not change the exit IPv4 address.

The entry tries management through the exit IPv4, then its primary IPv6, using the configured SSH port. If both paths are blocked, use the provider console. Record the old endpoint from entry `status`, then on the exit console:

```sh
cascadectl alias prepare NEW_EXIT_IPV6
cascadectl alias activate NEW_EXIT_IPV6
```

On the entry:

```sh
sudo cascadectl rotate --prepared NEW_EXIT_IPV6
sudo cascadectl health
```

The console workflow changes the exit source before the entry switches, so the interserver hop can pause between commands. If the prepared candidate fails, the entry restores its local old endpoint. Restore the exit source through its console as well:

```sh
cascadectl alias activate OLD_EXIT_IPV6
```

Then run entry `health`. Once working again, an unused owned candidate can be retired with `cascadectl alias drop FAILED_IPV6`. Inspect aliases on exit with `cascadectl alias status`. Use these management commands so ownership and persistence are recorded; adding an address with `ip` alone does not register it for boot restoration.

Destination exceptions are managed on entry:

```sh
sudo cascadectl override list
sudo cascadectl override add europe 77.88.8.8/32
sudo cascadectl override remove europe 77.88.8.8/32
sudo cascadectl override add russia 1.1.1.1/32
```

These are syntax examples; choose exceptions for your own services. Exceptions require globally routable IPv4 networks. Private/reserved destinations remain blocked. European exceptions take priority over Russian exceptions, then the RU country list, then the default European route. Existing connections retain their previous classification; new connections take the new decision. Failed applies restore the saved overrides.

The saved file is `/etc/cascade/overrides.json`, with `always_europe` and `always_russia` lists. Direct edits can be applied with `sudo cascadectl firewall`. The CLI validates changes and provides rollback. Refresh the country list manually with:

```sh
sudo cascadectl geo-update
```

The daily timer adds up to one hour of random delay. Failed/oversized downloads, malformed lists and address-count changes over 25% retain the last valid cache. Country lists classify destination IPs, so a Russian service hosted abroad or behind a foreign CDN can use the European exit.

A background health check runs every two minutes on entry. It probes both managed interfaces, the interserver link and DNS. Successful background checks suppress the detailed endpoint output; errors appear in the journal. It does not rotate addresses or send notifications.

```sh
sudo systemctl list-timers 'cascade-*'
sudo journalctl -u cascade-health.service -n 30 --no-pager
sudo journalctl -u cascade-awg@awg-eu.service -n 50 --no-pager
sudo ip -4 rule show
sudo ip -4 route show table 220
```

On exit, use `sudo cascadectl status`, `sudo journalctl -u cascade-dns.service`, and `ip -6 route get ENTRY_IPV6`. The last command should show the active transport IPv6 as its preferred source.

If the exit fails, foreign connections and the European DNS resolver become unavailable. Russian direct-IP or cached-name connections can continue; new Russian-domain lookups can fail because the DNS resolver is in Europe. The firewall prevents foreign traffic falling back to entry IPv4.

Create a private snapshot on each server after important changes:

```sh
sudo cascadectl backup
# Or select a new path outside the archived directories:
sudo cascadectl backup /root/backups/cascade-current.tar.gz
```

Archives are mode `0600` and include private keys, profiles, service definitions and binaries. A destination is never overwritten. Copy backups to your own protected storage. They are point-in-time snapshots; later client additions or rotations require a new snapshot.

Bootstrap also saves baseline archives and routing/firewall diagnostics under `/root/awg-cascade-backups/`. To restore a trusted current snapshot, stop the project tunnels and timers first, inspect the archive, extract it at `/`, reload systemd, and restart the exit alias/tunnel/DNS services before entry services. Restore both hosts from a matching point in time so keys and endpoints agree. Accounts created after the snapshot may need their newer profiles restored separately. Do not replace the global firewall with an old Docker ruleset; reload only `cascadectl firewall` and the scoped Docker permissions.

To take the project offline while keeping server management available, stop `cascade-awg@awg-clients`, `cascade-awg@awg-eu` and the two timers on entry. On exit, stop `cascade-dns` and `cascade-awg@awg-ru`. Its fail-closed guards remain loaded. A full uninstall, primary network changes and entry-IP migrations are outside the automatic commands.
