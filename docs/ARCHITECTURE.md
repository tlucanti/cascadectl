Clients have a stable IPv4 endpoint on the Russian entry. AmneziaWG terminates there, allowing Linux to classify destinations. The European hop is a separate AmneziaWG peer with independent keys and obfuscation settings, carried over IPv6. The entry can see decrypted inner packets and makes the routing decision.

| Purpose | Address/interface |
|---|---|
| Client network | `10.77.0.0/24`, entry `awg-clients` at `.1` |
| Device addresses | `.10`–`.239`, individual peer `/32`s |
| Client IPv6 capture prefix | `fd67:a2e4:9b01:1::/64`, individual peer `/128`s |
| Hop network | `10.78.0.0/30` |
| Entry hop | `awg-eu`, `10.78.0.1` |
| Exit hop and DNS | `awg-ru`, `10.78.0.2` |
| Policy route table | `220` |
| Connection marks | `0x100` direct Russian exit; `0x200` European exit, mask `0x300` |

The entry's client peers accept only each device's assigned IPv4/IPv6 sources. Its exit peer has `AllowedIPs = 0.0.0.0/0`; automatic route installation is disabled. The exit peer accepts the client subnet and the entry's private hop address. The exit has a return route for the client subnet.

For each unclassified IPv4 flow arriving from `awg-clients`, nftables checks explicit tunnel services, rejects reserved/private destinations, applies European overrides, applies Russian overrides, checks the RU prefix set, and otherwise selects Europe. The decision is saved in the conntrack mark and restored on later original-direction packets. Return packets use ordinary connected routes.

Policy priority `10000` sends marked direct flows to `main`; `10010` selects table `220` for remaining client traffic; `10020` is terminal unreachable. Table `220` has an active default through `awg-eu` and a persistent high-metric unreachable default. The independent forwarding guard accepts client WAN egress only for direct-marked flows. Removing the hop interface cannot expose a fallback through entry's normal default route.

Direct connections receive SNAT on entry. Foreign connections keep their private source across the hop and receive SNAT on exit. IPv4 stays IPv4 inside the encrypted IPv6 transport, so NAT64 is unnecessary. Host SSH and normal management traffic follow native host routes.

Reverse-path filtering is disabled on entry's policy paths. Even loose filtering consulted the policy rules and rejected valid direct-path replies when the hop table became unreachable. Peer source restrictions and forwarding rules validate sources instead. Exit retains loose filtering.

An exit IPv6 alias is added as `/128` inside the provider-confirmed `/64`, without replacing the existing network configuration. A systemd oneshot restores owned aliases at boot. An explicit `/128` route to entry IPv6 pins the preferred source on exit. Resetting the peer endpoint clears the old sticky UDP socket source. These steps prevent new IPv6 address selection or rekeying from silently changing the transport source during preparation or rollback.

`cascadectl rotate` updates both transport identities, probes them and persists them. The entry firewall fences replies to the selected endpoint, preventing an authenticated old-address packet from roaming the peer back. The exit primary address is retained and unrelated aliases are not adopted. Rotation can help with an individual-address block; prefix/provider/protocol blocks can require a different remedy.

A dedicated Unbound process on exit binds only its tunnel IPv4 address, allows clients and the entry hop address, and uses IPv4 upstream transport with DNSSEC validation. Client IPv6 default routes are captured into the tunnel and Internet IPv6 forwarding is blocked; native host IPv6 remains available for the hop.

Host firewall changes are confined to `table inet cascade`. Docker coexistence adds two scoped `DOCKER-USER` permissions and an idempotent Docker startup hook. The project does not flush global rules or reconfigure Xray/container bindings. Other input/forward drop policies need separate integration because an accept verdict in one base chain cannot bypass a later drop in another.

On the servers, project secret files are root-only. Server private keys remain on their originating hosts. Rotation uses an entry-held Ed25519 key, source-address restrictions and a forced command accepting only `prepare`, `activate`, and `drop` for addresses in the allocated exit subnet. The exit host key is pinned. Shared hop secrets pass through the controller's memory over SSH during bootstrap, without being printed or written into the repository.
