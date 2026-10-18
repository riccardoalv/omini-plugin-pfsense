# omini-plugin-pfsense

[Omini](https://github.com/riccardoalv/omini) plugin for **pfSense** (CE and Plus), through the [pfSense REST API package](https://pfrest.org/) (v2). Each collection only reads (`GET`). It changes the firewall only when you apply a change from Omini — a VLAN's network, a fixed DHCP address, a local DNS name, a paused device or a Wake-on-LAN packet, see [What it changes](#what-it-changes) — and only if its user has the write privileges; without them it stays read-only.

> **Experimental.** This plugin was built from the REST API package's documentation and OpenAPI schema, and from the pfSense source code it calls, and tested against answers shaped like that schema — **not on real hardware yet**. Reports from pfSense users are welcome.

## What it reads

| Data | Used for |
|---|---|
| Interfaces: port name (`igc0`), description, status, MAC, IPv4/IPv6, **link speed / media** (e.g. `2500Base-T <full-duplex>`), traffic and error counters | Ports of the firewall on the map, link speed (and RJ45 / SFP), traffic |
| WANs: interfaces with an upstream gateway (and pfSense's default WAN) | WAN nodes on the map |
| Gateways: status, latency, loss (dpinger) | WAN uplinks up / degraded / down |
| ARP table | Which IP and MAC are on which port |
| DHCP leases (ISC or Kea, whichever is in use) and static mappings | Names of devices the network scan only knows by MAC |
| DHCP pool usage: addresses of each enabled server's ranges, against its active leases | A pool running out of addresses |
| Hostname, version, platform (e.g. *Netgate 4200*), serial, CPU, memory, swap, load, temperature, uptime | Firewall health |
| VLANs: tag, description, parent port, subnet | VLANs of the network |
| Services: running or stopped, enabled | A service that stopped |
| VPN peers — OpenVPN (server connections and client instances), WireGuard peers, IPsec tunnels: endpoint, tunnel address, connected, last handshake (WireGuard), traffic | VPN tunnels up/down |
| Firewall state table: current entries and limit | A state table filling up |
| Each VLAN's network: interface, gateway, DHCP range, access read from its firewall rules (needs the *interfaces* GET privilege below) | The networks Omini can change |
| DHCP static mappings | Fixed addresses |
| LAGGs: each member port and its LAGG (`lagg0`) | Cables of a LAG drawn as one link |
| DNS Resolver host overrides (and their aliases), IPv4; the system domain | Local DNS names, and the domain new names get |
| The alias `omini_paused` | Devices whose internet is paused (their IPv4 addresses) |
| NAT port forwards (Firewall → NAT → Port Forward): protocol, external port or range, target address and port, source, interface, description, on or off | The **Exposed to the internet** section (Omini never changes them) |
| NAT port forwards (Firewall → NAT → Port Forward): protocol, external port or range, target address and port, source, interface, description, on or off | The **Exposed to the internet** section (Omini never changes them) |

## Requirements

- **pfSense CE 2.7.2 or later, or pfSense Plus 24.03 or later**, with the **REST API package v2** (`pfSense-pkg-RESTAPI`, version 2.0 or later). Each package release is built for specific pfSense versions; the latest supports CE 2.8.1 / 2.9.0 and Plus 25.11.1 and later, and older v2 releases support CE 2.7.2 and Plus 24.03 / 24.11 (see the [releases page](https://github.com/pfrest/pfSense-pkg-RESTAPI/releases)). There is no v2 build for Plus 23.09 or CE 2.7.0 / 2.7.1.
- Omini 1.0 or later (the SDK with VLANs, services, VPN peers, DHCP pools and firewall states); changing networks needs an Omini whose SDK has networks and configuration changes (1.2 or later); local DNS names, Wake-on-LAN, pausing devices and LAGGs need an Omini that knows them (the release after 1.2).

## Install the REST API package on pfSense

pfSense has no REST API of its own; the [REST API package](https://pfrest.org/INSTALL_AND_CONFIG/) adds one. From the pfSense shell (**Diagnostics → Command Prompt**, or SSH), with the package built for your version:

```sh
# pfSense CE (replace 2.8.1 with your version, from the releases page)
pkg-static add https://github.com/pfrest/pfSense-pkg-RESTAPI/releases/latest/download/pfSense-2.8.1-pkg-RESTAPI.pkg
# pfSense Plus (replace 26.03 with your version)
pkg-static -C /dev/null add https://github.com/pfrest/pfSense-pkg-RESTAPI/releases/latest/download/pfSense-26.03-pkg-RESTAPI.pkg
```

For CE 2.7.2 or Plus 24.03 / 24.11, take the package from an older release (e.g. [v2.4.3](https://github.com/pfrest/pfSense-pkg-RESTAPI/releases/tag/v2.4.3)) instead of `latest`. pfSense removes unofficial packages when it is upgraded: **install the package again after every pfSense upgrade**.

Then, in **System → REST API → Settings**, make sure **API Key** is one of the *Authentication Methods* (Basic is the default; keep it on while you create the key below).

## Create a read-only user and its API key

Use a dedicated user with only the privileges Omini needs. The package creates one privilege per endpoint and method, named `REST API - <endpoint> <METHOD>` ([authorization docs](https://pfrest.org/AUTHENTICATION_AND_AUTHORIZATION/)); an API key has the privileges of the user it was issued to.

1. **System → User Manager → Users → Add**: user `omini`, a long random password. Save, edit it again and, under **Effective Privileges → Add**, pick these (type `REST API - /api/v2/` in the filter):

   | Privilege | Id | For |
   |---|---|---|
   | REST API - /api/v2/status/system GET | `api-v2-status-system-get` | CPU, memory, swap, load, temperature, uptime, platform (**required**) |
   | REST API - /api/v2/system/version GET | `api-v2-system-version-get` | pfSense version |
   | REST API - /api/v2/system/hostname GET | `api-v2-system-hostname-get` | name of the firewall |
   | REST API - /api/v2/status/interfaces GET | `api-v2-status-interfaces-get` | ports, link speed, IPs, counters, WANs |
   | REST API - /api/v2/status/gateways GET | `api-v2-status-gateways-get` | gateway status |
   | REST API - /api/v2/diagnostics/arp_table GET | `api-v2-diagnostics-arp-table-get` | ARP table |
   | REST API - /api/v2/status/dhcp_server/leases GET | `api-v2-status-dhcp-server-leases-get` | DHCP leases |
   | REST API - /api/v2/services/dhcp_servers GET | `api-v2-services-dhcp-servers-get` | DHCP ranges (pool usage) |
   | REST API - /api/v2/interface/vlans GET | `api-v2-interface-vlans-get` | VLANs |
   | REST API - /api/v2/status/services GET | `api-v2-status-services-get` | services |
   | REST API - /api/v2/firewall/states/size GET | `api-v2-firewall-states-size-get` | state table |
   | REST API - /api/v2/status/openvpn/servers GET | `api-v2-status-openvpn-servers-get` | OpenVPN server connections (optional) |
   | REST API - /api/v2/status/openvpn/clients GET | `api-v2-status-openvpn-clients-get` | OpenVPN client instances (optional) |
   | REST API - /api/v2/status/wireguard/tunnels GET | `api-v2-status-wireguard-tunnels-get` | WireGuard peers (optional; needs the WireGuard package) |
   | REST API - /api/v2/status/ipsec/sas GET | `api-v2-status-ipsec-sas-get` | IPsec tunnels (optional) |
   | REST API - /api/v2/interfaces GET | `api-v2-interfaces-get` | each VLAN's network: interface, address (optional) |
   | REST API - /api/v2/firewall/rules GET | `api-v2-firewall-rules-get` | each network's access (optional) |
   | REST API - /api/v2/interface/laggs GET | `api-v2-interface-laggs-get` | LAGG members (optional) |
   | REST API - /api/v2/services/dns_resolver/host_overrides GET | `api-v2-services-dns-resolver-host-overrides-get` | local DNS names (optional) |
   | REST API - /api/v2/firewall/aliases GET | `api-v2-firewall-aliases-get` | paused devices (optional) |
   | REST API - /api/v2/firewall/nat/port_forwards GET | `api-v2-firewall-nat-port-forwards-get` | port forwards (optional) |
   | **User - Config: Deny Config Write** | `user-config-readonly` | **recommended when Omini only reads**: the REST API honours it and refuses any configuration change from this user. Leave it out to apply changes (below) |

   Temporarily add **REST API - /api/v2/auth/key POST** too, for the next step.

2. Create the key **as that user** (keys are always issued to the user who asks for them). From any machine that reaches the firewall:

   ```sh
   curl -k -u omini:'<the password>' -X POST -H 'Content-Type: application/json' \
     -d '{"descr": "Omini"}' https://192.168.1.1/api/v2/auth/key
   ```

   The answer carries the key in `data.key`: copy it (pfSense keeps only its hash). Then remove the *auth/key POST* privilege from the user.
3. In Omini, fill in the firewall address (e.g. `https://192.168.1.1`) and the key, and click **Test connection**: it says which privileges are missing, if any.

Missing optional privileges only leave their data out. Do not give the user *WebCfg - All pages*: it allows everything, including changes.

### Form fields

| Field | Meaning |
|---|---|
| Address | The pfSense web interface, e.g. `https://192.168.1.1` (the REST API lives on the same port) |
| API key | The key from step 2 (stored encrypted, never logged) |
| Verify the TLS certificate | Off by default, since pfSense uses a self-signed certificate; turn it on if yours is trusted |

## How it works

One collection = a few `GET` requests with the key in the `X-API-Key` header, each with a 10 s timeout; answers come in the package's envelope (`{"code", "status", "response_id", "message", "data"}`). Plural endpoints are read with `limit=0` (everything). An endpoint the user may not read (403), that this package version does not have (404) or that needs a package that is not installed (424, e.g. WireGuard) is skipped; only `/api/v2/status/system` is required. Endpoint reference: the package's [API docs](https://pfrest.org/api-docs/) and [OpenAPI schema](https://pfrest.org/api-docs/openapi.json).

| Endpoint | Fields read |
|---|---|
| [`GET /api/v2/status/system`](https://pfrest.org/api-docs/#/STATUS/getStatusSystemEndpoint) | `platform`, `serial`, `uptime`, `cpu_usage`, `cpu_load_avg`, `mem_usage`, `swap_usage`, `temp_c` |
| [`GET /api/v2/system/version`](https://pfrest.org/api-docs/#/SYSTEM/getSystemVersionEndpoint) | `version`, `base`, `patch` |
| [`GET /api/v2/system/hostname`](https://pfrest.org/api-docs/#/SYSTEM/getSystemHostnameEndpoint) | `hostname`, `domain` |
| [`GET /api/v2/status/interfaces`](https://pfrest.org/api-docs/#/STATUS/getStatusInterfacesEndpoint) | `name`, `descr`, `hwif`, `status`, `media`, `macaddr`, `ipaddr`/`subnet`, `ipaddrv6`/`subnetv6`, `inbytes`/`outbytes`, `inerrs`/`outerrs`, `gateway`/`gatewayv6` |
| [`GET /api/v2/status/gateways`](https://pfrest.org/api-docs/#/STATUS/getStatusGatewaysEndpoint) | `name`, `srcip`, `monitorip`, `delay`, `loss`, `status`, `substatus` |
| [`GET /api/v2/diagnostics/arp_table`](https://pfrest.org/api-docs/#/DIAGNOSTICS/getDiagnosticsARPTableEndpoint) | `ip_address`, `mac_address`, `interface`, `permanent` |
| [`GET /api/v2/status/dhcp_server/leases`](https://pfrest.org/api-docs/#/STATUS/getStatusDHCPServerLeasesEndpoint) | `ip`, `mac`, `hostname`, `active_status` |
| [`GET /api/v2/services/dhcp_servers`](https://pfrest.org/api-docs/#/SERVICES/getServicesDHCPServersEndpoint) | `id`/`interface`, `enable`, `range_from`, `range_to`, `pool[]` |
| [`GET /api/v2/interface/vlans`](https://pfrest.org/api-docs/#/INTERFACE/getInterfaceVLANsEndpoint) | `if`, `tag`, `vlanif`, `descr` |
| [`GET /api/v2/status/services`](https://pfrest.org/api-docs/#/STATUS/getStatusServicesEndpoint) | `name`, `description`, `status`, `enabled` |
| [`GET /api/v2/firewall/states/size`](https://pfrest.org/api-docs/#/FIREWALL/getFirewallStatesSizeEndpoint) | `currentstates`, `maximumstates` |
| [`GET /api/v2/status/openvpn/servers`](https://pfrest.org/api-docs/#/STATUS/getStatusOpenVPNServersEndpoint) | `conns[]`: `common_name`, `user_name`, `remote_host`, `virtual_addr`, `bytes_recv`, `bytes_sent` |
| [`GET /api/v2/status/openvpn/clients`](https://pfrest.org/api-docs/#/STATUS/getStatusOpenVPNClientsEndpoint) | `name`, `status`, `state`, `remote_host`, `remote_port`, `virtual_addr` |
| [`GET /api/v2/status/wireguard/tunnels`](https://pfrest.org/api-docs/#/STATUS/getStatusWireGuardTunnelsEndpoint) | `peers[]`: `descr`, `public_key`, `endpoint`, `allowed_ips`, `latest_handshake`, `transfer_rx`, `transfer_tx` |
| [`GET /api/v2/status/ipsec/sas`](https://pfrest.org/api-docs/#/STATUS/getStatusIPsecSAsEndpoint) | `con_id`, `state`, `remote_host`, `remote_port`, `child_sas[]`: `bytes_in`, `bytes_out`, `remote_ts` |
| `GET /api/v2/interfaces` | `id` (lan, opt3), `if`, `descr`, `enable`, `typev4`, `ipaddr`, `subnet`, `gateway` (each VLAN's network) |
| `GET /api/v2/firewall/rules` | `type`, `interface`, `source`, `destination`, `destination_port`, `disabled`, `floating` (each network's access) |
| `GET /api/v2/interface/laggs` | `laggif`, `members[]`, `descr` |
| `GET /api/v2/services/dns_resolver/host_overrides` | `id`, `host`, `domain`, `ip[]`, `aliases[]`: `host`, `domain` |
| `GET /api/v2/firewall/aliases` | `name` (`omini_paused`), `address[]`, `detail[]` |

Mapping details:

- **Ports** are named by `hwif` (`igc0`, `igc1.20`, `pppoe0`), never by pfSense's internal name (`wan`, `opt1`). VLAN interfaces get their parent port and tag from `/interface/vlans` (or from the `parent.tag` name), and the parent's speed.
- **Link speed and connector** come from `media` (`1000baseT` = RJ45; `SR/LR/SX/LX/CR/Twinax…` = SFP); virtual NICs (`vtnet`, `vmx`, `hn`, `xn`) and tunnels get neither.
- **WAN** = an interface with an IPv4/IPv6 upstream gateway, or pfSense's default WAN (`wan`) — pfSense only reports the gateway while the link is up. A gateway's interface is the one whose address is the probes' source (`srcip`), else whose gateway is the monitored IP.
- **Gateway status**: `online` → up, `online` with substatus `delay`/`loss`/`highdelay`/`highloss` → degraded, `down` → down.
- **ARP**: pfSense adds the MAC vendor after the MAC and names assigned interfaces by description (`LAN`); the plugin keeps only the MAC and turns the description into the port name. The firewall's own (permanent) entries are skipped.
- **DHCP leases**: expired / free / backup leases are skipped; static mappings are kept.
- **LAGGs**: pfSense lists only assigned interfaces and a LAGG member can never be assigned, so each member is added as a port with only its name and its LAGG (`lag`); a LAGG that is not assigned is added the same way (type `lag`).
- **DNS names**: every host override's name (`host.domain`) and its aliases' names, for each IPv4 address (IPv6 ones are left out). The domain is the system domain (System → General Setup), which the DHCP server hands out unless a network sets its own.
- **WireGuard**: a peer is *connected* when its last handshake is under 3 minutes old (WireGuard renews sessions every 2 minutes while traffic flows). The answer also carries pre-shared keys: the plugin never reads or keeps them.

## What it changes

Changes are applied only when you confirm one in Omini (Omini's guarded changes), and only with the write privileges below; a missing privilege is named in the error. Everything Omini writes carries **Omini** in its description, so you can tell it apart in the pfSense UI. pfSense saves each change in its configuration as the API makes it; after applying, the plugin reads the configuration again and fails the change unless it reads back as asked (a network it was creating is then removed again).

| Change | What the plugin does on pfSense |
|---|---|
| **network.set** (create) | Adds the VLAN on the port toward the switches (`POST /api/v2/interface/vlan`, on the LAN's port when none is named; never on a bridge or another VLAN), assigns it with the gateway as a static IPv4 address (`POST /api/v2/interface`, then `POST /api/v2/interface/apply`), turns on its DHCP server with the range and the gateway as DNS server (`POST` — or, on older packages, `PATCH` — `/api/v2/services/dhcp_server`, then `…/dhcp_server/apply`) and writes the access rules (below; `POST /api/v2/firewall/rule`, then `POST /api/v2/firewall/apply`) |
| **network.set** (change) | Changes the same things in place with `PATCH` (interface description and address, DHCP range or DHCP off); the rules are replaced only when the access changes to another preset. The LAN is VLAN 1 and is never moved; the address Omini reaches pfSense at is never changed |
| **network.delete** | Removes the network's rules, its DHCP server (`DELETE /api/v2/services/dhcp_server`, or turned off on older packages), the interface assignment (`DELETE /api/v2/interface`) and the VLAN (`DELETE /api/v2/interface/vlan`). Never the LAN, never a WAN |
| **reservation.set** | A static mapping on the DHCP server of the network the address is in (`POST`/`PATCH /api/v2/services/dhcp_server/static_mapping`, then `…/dhcp_server/apply`); a mapping of the same MAC on another network moves |
| **reservation.delete** | Removes the MAC's static mappings |
| **dns.set** | A DNS Resolver host override for the name (`POST /api/v2/services/dns_resolver/host_override` with `host`, `domain`, `ip` and description *Omini*), or the address of the one with that exact name changed (`PATCH`, its description kept; a second override of the same name is removed); then `POST /api/v2/services/dns_resolver/apply`. A name that is an alias of another override is refused (change it in pfSense) |
| **dns.delete** | Removes the host overrides with that name (`DELETE …/host_override`), then applies |
| **wol.send** | `POST /api/v2/services/wake_on_lan/send` with the interface whose network holds the device's address (the LAN without one; never a WAN) and the MAC. Nothing is changed or saved |
| **pause.set** | Puts the device's addresses in the host alias `omini_paused` (`POST`/`PATCH /api/v2/firewall/alias`; each address's description is `Omini <MAC> <name>`, so the alias says which device each one is), replacing the ones the MAC had: the IPv4 addresses Omini sent and the device's IPv6 addresses from the router's NDP table (when the API user may read it, below); the other paused devices' IPv6 entries are refreshed from the NDP table at the same time. Writes the network alias `omini_local` (what a paused device still reaches); makes sure each interface with a private static address (not the WANs, DHCP clients or VPNs) has the block rule (below; `POST /api/v2/firewall/rule`), replacing the IPv4-only rules of 0.2.0; `POST /api/v2/firewall/apply`; then removes the device's open IPv4 connections (`DELETE /api/v2/firewall/states` with `source__startswith=<ip>:` and, for NATed ones, `source__contains=(<ip>:`), best effort. pfSense's own addresses are refused |
| **pause.delete** | Takes the MAC's addresses (IPv4 and IPv6) out of the alias; when it is left empty, removes the block rules and both aliases `omini_paused` and `omini_local` (`DELETE /api/v2/firewall/rule`, `DELETE /api/v2/firewall/alias`); applies. A device paused by 0.2.0 resumes the same way |

**Access** is read from the interface's enabled rules; these exact sets are the presets, anything else is *custom* and is never touched:

| Access | Rules (in order, source: the network) |
|---|---|
| Internet only | pass TCP/UDP 53 to the gateway (`optN:ip`); block to the alias `omini_private` (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, created when missing); pass to any |
| Everything | pass to any (pfSense's default LAN rules, IPv4 and IPv6, read as this) |
| Its own network | pass TCP/UDP 53 to the gateway only |

**Paused devices**: one rule per interface with a private static address (not the WANs, DHCP clients or VPNs), *block, IPv4+IPv6 (`inet46`), source `omini_paused`, destination not `omini_local`*, description *Omini: paused devices, no internet*. `omini_local` holds the private IPv4 ranges (10/8, 172.16/12, 192.168/16), IPv6 link-local `fe80::/10`, ULA `fc00::/7` and multicast `ff00::/8`, and the IPv6 networks of those interfaces as their status shows them (e.g. the ISP's prefix on the LAN), refreshed at every pause. The API adds rules at the end of an interface's list and cannot move them, so they are **floating rules with quick** on that interface (direction in): pfSense evaluates them before every interface rule, so the device keeps reaching its own and the other local networks and loses only the internet, over IPv4 and IPv6. They are not part of a network's *access*, and changing a network's access keeps them. A network created after a device was paused gets its rule at the next pause.

**IPv6 of a paused device**: pfSense's rules cannot match a MAC, so the device's IPv6 addresses (SLAAC, including the temporary/privacy ones that change) must be in the alias. The REST API package has no endpoint for the NDP table, so the plugin reads it with `ndp -an` through `POST /api/v2/diagnostics/command_prompt` — **only if you give the user that privilege**, which lets the key run any shell command on the firewall as root. Without it a paused device is blocked over IPv4 only (and over any IPv6 address already in the alias), and can still reach the internet over IPv6 if the network has it. The addresses are those the router has seen when the pause is applied: a temporary address the device makes later is blocked only from the next `pause.set` (Omini re-sends it when a paused device's IPv4 address changes, not when its IPv6 ones do).

**Discovery between networks (mDNS)** is not supported: pfSense's repeater is the Avahi package, which the REST API does not configure. Turn it on in **Services → Avahi**; asking Omini to turn it on fails with that hint.

### Write privileges

Add these to the Omini user (System → User Manager → the user → *Effective Privileges*), and remove **User - Config: Deny Config Write** from it:

| Privilege | Id |
|---|---|
| REST API - /api/v2/interfaces GET | `api-v2-interfaces-get` |
| REST API - /api/v2/interface POST / PATCH / DELETE | `api-v2-interface-post`, `-patch`, `-delete` |
| REST API - /api/v2/interface/apply POST | `api-v2-interface-apply-post` |
| REST API - /api/v2/interface/vlan POST / DELETE | `api-v2-interface-vlan-post`, `-delete` |
| REST API - /api/v2/services/dhcp_server POST / PATCH / DELETE | `api-v2-services-dhcp-server-post`, `-patch`, `-delete` |
| REST API - /api/v2/services/dhcp_server/apply POST | `api-v2-services-dhcp-server-apply-post` |
| REST API - /api/v2/services/dhcp_server/static_mapping POST / PATCH / DELETE | `api-v2-services-dhcp-server-static-mapping-post`, `-patch`, `-delete` |
| REST API - /api/v2/firewall/rules GET | `api-v2-firewall-rules-get` |
| REST API - /api/v2/firewall/rule POST / DELETE | `api-v2-firewall-rule-post`, `-delete` |
| REST API - /api/v2/firewall/aliases GET | `api-v2-firewall-aliases-get` |
| REST API - /api/v2/firewall/alias POST | `api-v2-firewall-alias-post` |
| REST API - /api/v2/firewall/apply POST | `api-v2-firewall-apply-post` |
| *Local DNS names* | |
| REST API - /api/v2/services/dns_resolver/host_overrides GET | `api-v2-services-dns-resolver-host-overrides-get` |
| REST API - /api/v2/services/dns_resolver/host_override POST / PATCH / DELETE | `api-v2-services-dns-resolver-host-override-post`, `-patch`, `-delete` |
| REST API - /api/v2/services/dns_resolver/apply POST | `api-v2-services-dns-resolver-apply-post` |
| *Wake-on-LAN* | |
| REST API - /api/v2/services/wake_on_lan/send POST | `api-v2-services-wake-on-lan-send-post` |
| *Pausing devices* (with the interfaces, rules and firewall apply ones above) | |
| REST API - /api/v2/firewall/alias PATCH / DELETE | `api-v2-firewall-alias-patch`, `-delete` |
| REST API - /api/v2/firewall/states DELETE | `api-v2-firewall-states-delete` (optional: without it open connections last until they close) |
| REST API - /api/v2/status/interfaces GET | `api-v2-status-interfaces-get` (the LAN-side IPv6 networks a paused device still reaches; already in the read privileges) |
| REST API - /api/v2/diagnostics/command_prompt POST | `api-v2-diagnostics-command-prompt-post` (optional, **runs any shell command**: only to pause over IPv6, see *IPv6 of a paused device*) |

These let the key change interfaces, DHCP and firewall rules anywhere on the firewall; Omini only ever touches what it is asked to (see the table above). Still do not give the user *WebCfg - All pages*.

### Not verified on hardware

The changes, and the reads added since 0.2 (port forwards), follow the package's [OpenAPI schema](https://pfrest.org/api-docs/openapi.json) and were tested against a fake that answers like it, **not against a real pfSense**. Assumed from the schema and not yet seen on a device:

- Ids: an interface's id is its pfSense name (`opt3`) and the `POST /api/v2/interface` answer carries it; a DHCP server's id is its interface's name; VLAN, rule and static-mapping ids are positions in their lists and move down when an earlier one is removed (the plugin removes from the last).
- Fields: VLAN `if`/`tag`/`descr`/`vlanif`; interface `if`/`descr`/`enable`/`typev4: static`/`ipaddr`/`subnet`; DHCP server `interface`/`enable`/`range_from`/`range_to`/`dnsserver`/`staticmap[]`; static mapping `parent_id`/`id`/`mac`/`ipaddr`/`hostname`/`descr`; rule `type`/`interface[]`/`ipprotocol`/`protocol`/`source`/`destination` (`optN:ip` for the interface address)/`destination_port`/`descr`/`disabled`/`floating`; alias `name`/`type`/`address[]`/`detail[]`.
- That rules read back with the same `source`/`destination` values they were written with (`opt3`, `opt3:ip`; `opt3ip` is accepted too), and that an omitted `protocol` means any.
- That a static interface without a DHCP server can get one with `POST /api/v2/services/dhcp_server` (older packages: `PATCH` it), and that pfSense refuses to remove an interface still used by rules or DHCP (the plugin removes those first).
- `/api/v2/interface/apply` applies every pending interface change, including ones made by hand and not applied yet.
- DNS: host override fields `host`/`domain`/`ip[]`/`descr`/`aliases[]` and positional ids; that `…/dns_resolver/apply` makes Unbound answer at once (the plugin reads the overrides back, not the resolver's answers).
- Wake-on-LAN: that `interface` takes pfSense's interface name (`lan`, `opt1`) and `mac_addr` a colon-separated MAC.
- Pausing: alias `address[]`/`detail[]` kept in step and returned as lists; `PATCH` replacing both; rule fields `floating`/`quick`/`direction: in`/`ipprotocol: inet46` with an inverted alias destination (`!omini_local`); that a host alias takes IPv6 addresses and a network alias IPv6 networks next to IPv4 ones; the `output` of `POST /api/v2/diagnostics/command_prompt` and the column layout of FreeBSD's `ndp -an` (address, MAC); `ipaddrv6`/`subnetv6` of `/api/v2/status/interfaces` for a tracked (DHCPv6-PD) LAN; that a floating quick block on an interface is evaluated before that interface's own pass rules (pfSense's documented order); the state-kill filters `source__startswith` and `source__contains` on `DELETE /api/v2/firewall/states`, and the `ip:port` / `wan:port (ip:port)` shape of a state's `source`.
- LAGGs: `GET /api/v2/interface/laggs` with `laggif` and `members[]` as real port names.
- Port forwards: `GET /api/v2/firewall/nat/port_forwards` with `interface` (pfSense's name, `wan`), `protocol`, `source`, `destination_port` (`443`, or a range `27015:27020`), `target`, `local_port`, `disabled`, `nordr` and `descr`.

## Known limitations

- **Only assigned interfaces** are listed (the API reports pfSense's assigned interfaces, not every NIC): an unassigned port is not on the map.
- **Traffic counters** are each interface's bytes in and out (`inbytes`/`outbytes` of `/api/v2/status/interfaces`: all its traffic, not only what the firewall passed), averaged between two collections.
- **CPU usage** is the package's estimate from the 1-minute load average ÷ cores, not a sampled value.
- **Temperature**: a single value, pfSense's system temperature (first CPU core, else the ACPI thermal zone).
- **Disks**: the API reports only the use of `/` as a percentage, with no sizes, so disks are not reported.
- **Updates**: the API has no pending-update status, so only the installed version is reported (Omini never starts an update check).
- **DHCP lease end times** are left out: pfSense formats them in UTC or local time depending on a setting the API does not show.
- **PPPoE / PPP WANs**: the API does not say which port carries the PPP link, so such a WAN has no link speed.
- **Bridges**: their member ports are not in the API, so they are not reported. LAGG members come from the LAGG's own configuration, with no status, speed or counters of their own.
- **No configuration backups**: the REST API has no endpoint that returns `config.xml` (`/diagnostics/config_history/revisions` lists only the time, description and size of each revision), and reading it through `/diagnostics/command_prompt` would need a privilege that runs any shell command. So this plugin does not declare `backup`.
- **Wake-on-LAN** goes out on pfSense's assigned interfaces only.
- **Port forwards**: a forward whose external port is an alias, or for a protocol without ports (ICMP, ESP…), is left out; a target that is an alias has no internal address. UPnP / NAT-PMP mappings (miniupnpd) are not reported: the REST API has no endpoint for them.
- Lease and gateway states are compared with pfSense's English words (`expired`, `online`…); a pfSense GUI set to another language may translate some of them.

## Development

The plugin uses [uv](https://docs.astral.sh/uv/) and expects the Omini repository next to it (the SDK is in `../omini/sdk/python`):

```bash
uv run pytest          # tests, against answers shaped like the REST API's schema (tests/fixtures)
uv run ruff check .    # lint
uv run ruff format .   # format
```

Run it from a local Omini without installing it: `OMINI_PLUGIN_DIRS=../omini-plugin-pfsense make run` in the Omini repository; every collection uses the current code.

## License

MIT
