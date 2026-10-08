# omini-plugin-pfsense

[Omini](https://github.com/riccardoalv/omini) plugin for **pfSense** (CE and Plus), through the [pfSense REST API package](https://pfrest.org/) (v2). Read-only: it only sends `GET` requests and never changes the firewall's configuration.

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

## Requirements

- **pfSense CE 2.7.2 or later, or pfSense Plus 24.03 or later**, with the **REST API package v2** (`pfSense-pkg-RESTAPI`, version 2.0 or later). Each package release is built for specific pfSense versions; the latest supports CE 2.8.1 / 2.9.0 and Plus 25.11.1 and later, and older v2 releases support CE 2.7.2 and Plus 24.03 / 24.11 (see the [releases page](https://github.com/pfrest/pfSense-pkg-RESTAPI/releases)). There is no v2 build for Plus 23.09 or CE 2.7.0 / 2.7.1.
- Omini 0.2 or later (the SDK with VLANs, services, VPN peers, DHCP pools and firewall states).

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
   | **User - Config: Deny Config Write** | `user-config-readonly` | **recommended**: the REST API honours it and refuses any configuration change from this user |

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

Mapping details:

- **Ports** are named by `hwif` (`igc0`, `igc1.20`, `pppoe0`), never by pfSense's internal name (`wan`, `opt1`). VLAN interfaces get their parent port and tag from `/interface/vlans` (or from the `parent.tag` name), and the parent's speed.
- **Link speed and connector** come from `media` (`1000baseT` = RJ45; `SR/LR/SX/LX/CR/Twinax…` = SFP); virtual NICs (`vtnet`, `vmx`, `hn`, `xn`) and tunnels get neither.
- **WAN** = an interface with an IPv4/IPv6 upstream gateway, or pfSense's default WAN (`wan`) — pfSense only reports the gateway while the link is up. A gateway's interface is the one whose address is the probes' source (`srcip`), else whose gateway is the monitored IP.
- **Gateway status**: `online` → up, `online` with substatus `delay`/`loss`/`highdelay`/`highloss` → degraded, `down` → down.
- **ARP**: pfSense adds the MAC vendor after the MAC and names assigned interfaces by description (`LAN`); the plugin keeps only the MAC and turns the description into the port name. The firewall's own (permanent) entries are skipped.
- **DHCP leases**: expired / free / backup leases are skipped; static mappings are kept.
- **WireGuard**: a peer is *connected* when its last handshake is under 3 minutes old (WireGuard renews sessions every 2 minutes while traffic flows). The answer also carries pre-shared keys: the plugin never reads or keeps them.

## Known limitations

- **Only assigned interfaces** are listed (the API reports pfSense's assigned interfaces, not every NIC): an unassigned port is not on the map.
- **Traffic counters** are pfSense's *passed* bytes per interface (pf's 64-bit counters, the same numbers as Status → Interfaces), averaged between two collections.
- **CPU usage** is the package's estimate from the 1-minute load average ÷ cores, not a sampled value.
- **Temperature**: a single value, pfSense's system temperature (first CPU core, else the ACPI thermal zone).
- **Disks**: the API reports only the use of `/` as a percentage, with no sizes, so disks are not reported.
- **Updates**: the API has no pending-update status, so only the installed version is reported (Omini never starts an update check).
- **DHCP lease end times** are left out: pfSense formats them in UTC or local time depending on a setting the API does not show.
- **PPPoE / PPP WANs**: the API does not say which port carries the PPP link, so such a WAN has no link speed.
- **Bridges and LAGGs**: their member ports are not in the API, so they are not reported.
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
