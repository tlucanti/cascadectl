Run `./scripts/check.sh` from the project checkout. It requires Python 3 and Bash, no root, no Python packages and no live SSH access.

The suite checks configuration validation, offline planning, read-only preflight, reserved routes/ports/interfaces, optional Docker integration, source pinning, restricted-command parsing, client/override rollback, cache retention, checksum validation before installation, and preservation of existing keys and rotated addresses. Bootstrap transport is mocked. Root-side filesystem actions use temporary directories and synthetic keys. No credentials are loaded and no kernel routing rules are applied. When systemd-analyze is available, the check script also verifies the real unit files against an inert temporary root with placeholder executables.

The reference VPS deployment was exercised with real IPv4/IPv6 traffic, HTTPS, STUN/UDP, UDP/TCP DNS, DNSSEC responses, full-MTU packets, a large transfer, metadata/IPv6 blocking, second-hop outage, address rotation, rejected candidates and reboots. Those results establish the origin of the routing implementation. They do not replace a fresh smoke test of this packaged installer on your target environment.

For an installation smoke test, use disposable Ubuntu 24.04 VPSs with real native IPv6 and a provider-allocated exit `/64`. Keep provider console access and run the documented preflight before provisioning. Check these observable outcomes:

1. Run bootstrap from a fresh configuration with private profile export; check entry `health` and active services on both hosts.
2. Connect a separate test client to entry IPv4. Confirm foreign HTTPS and UDP use exit IPv4 and RU-listed destinations use entry IPv4. Inspect only the relevant test packets/counters when tracing.
3. Exercise UDP and TCP private DNS and a full-MTU packet with fragmentation prohibited. Confirm a real application transfer succeeds.
4. Temporarily stop entry's `cascade-awg@awg-eu`. A foreign request with a pre-resolved address must fail, while a controlled direct-route request continues. Restore the hop in a `finally`/trap path.
5. Hash the exported client profiles, rotate the exit IPv6, and confirm the hashes and client entry endpoint are unchanged. Confirm exit's route to entry IPv6 uses the new source.
6. Block one specific candidate hop address temporarily on exit and verify automatic rollback, including source identity. Remove the test-only block afterward.
7. Rerun bootstrap with the same configuration. Confirm server keys, profiles, existing extra devices and the active alias remain unchanged. Verify a missing key or conflicting configuration is refused.
8. Reboot each VPS when appropriate for those disposable services and confirm aliases, policy rules, DNS and Docker permissions recover. Reconnect the test client.
9. Revoke and remove temporary test peers and files. Confirm other clients remain connected.

The bootstrap command does not perform outage, rotation or reboot tests automatically. `--check` checks server prerequisites; `health` checks the hop/DNS path, not end-device DPI behavior or every forwarded application. Public geolocation datasets and client operating-system routing also require real-world verification.

When changing version pins, review protocol/client compatibility and the upstream build requirements, run the local suite, and repeat the disposable-VPS smoke test. The sources are pinned by tag and exact commit in `config/versions.json`. The build verifies that the tag still resolves to that commit.
