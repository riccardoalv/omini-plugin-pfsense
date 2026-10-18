"""Turns pfSense REST API answers into Omini devices."""

from __future__ import annotations

import ipaddress
import re
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, TypeVar
from urllib.parse import urlparse

from omini_sdk import (
    ArpEntry,
    Config,
    Device,
    DhcpLease,
    DhcpPool,
    FirewallStates,
    Firmware,
    Gateway,
    Interface,
    PluginError,
    Service,
    Temperature,
    Vlan,
    VpnPeer,
    log,
)
from omini_sdk.models import PortForward

from omini_pfsense import manage
from omini_pfsense import networks as nets
from omini_pfsense.client import Client, Forbidden, NotFound

T = TypeVar("T")

MAC = re.compile(r"[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}", re.IGNORECASE)

# Endpoint per piece of data. The REST API package names each privilege after
# its endpoint: "REST API - /api/v2/status/system GET" (id api-v2-status-system-get).
ENDPOINTS = {
    "system": "/api/v2/status/system",
    "version": "/api/v2/system/version",
    "hostname": "/api/v2/system/hostname",
    "interfaces": "/api/v2/status/interfaces",
    "gateways": "/api/v2/status/gateways",
    "arp": "/api/v2/diagnostics/arp_table",
    "dhcp": "/api/v2/status/dhcp_server/leases",
    "services": "/api/v2/status/services",
    "vlans": "/api/v2/interface/vlans",
    "states": "/api/v2/firewall/states/size",
    "dhcp_pools": "/api/v2/services/dhcp_servers",
    "openvpn_servers": "/api/v2/status/openvpn/servers",
    "openvpn_clients": "/api/v2/status/openvpn/clients",
    "wireguard": "/api/v2/status/wireguard/tunnels",
    "ipsec": "/api/v2/status/ipsec/sas",
    "networks": nets.INTERFACES,
    "dns": manage.HOST_OVERRIDES,
    "aliases": nets.ALIASES,
    "laggs": manage.LAGGS,
    "port_forwards": "/api/v2/firewall/nat/port_forwards",
}


def privilege(what: str) -> str:
    return f"REST API - {ENDPOINTS[what]} GET"


def client_from(cfg: Config) -> Client:
    url, key = cfg.str("url"), cfg.str("api_key")
    if not url or not key:
        raise PluginError("the address and the API key are required")
    return Client(url, key, verify_tls=cfg.bool("verify_tls", False))


def rows(c: Client, what: str) -> list[dict[str, Any]]:
    """A plural endpoint, every object (limit=0 means no limit)."""
    data = c.get(ENDPOINTS[what], params={"limit": 0})
    return [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []


def one(c: Client, what: str) -> dict[str, Any]:
    data = c.get(ENDPOINTS[what])
    return data if isinstance(data, dict) else {}


def optional(what: str, missing: list[str], fn: Callable[[], T], default: T) -> T:
    """Optional data: a missing privilege or package never fails the collection."""
    try:
        return fn()
    except Forbidden:
        log.warning("no privilege for %s (%s)", what, privilege(what))
        missing.append(privilege(what))
    except NotFound:
        log.info("%s not available on this pfSense", what)
    except PluginError:
        raise
    except Exception:
        log.exception("could not read %s", what)
    return default


# --- parsing helpers -------------------------------------------------------


def mac(value: Any) -> str | None:
    """The first MAC in a value. pfSense's ARP table may add the vendor after
    it ("aa:bb:… <small>(Apple, Inc.)</small>") or say "(Incomplete)"."""
    if not isinstance(value, str):
        return None
    m = MAC.search(value)
    if not m:
        return None
    v = m.group().lower().replace("-", ":")
    return None if v == "00:00:00:00:00:00" else v


def number(value: Any) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str):
        m = re.search(r"-?\d+(\.\d+)?", value)
        if m:
            return float(m.group())
    return None


def counter(value: Any) -> int | None:
    n = number(value)
    return int(n) if n is not None and n >= 0 else None


def pct(value: Any) -> float | None:
    n = number(value)
    return round(n, 1) if n is not None and 0 <= n <= 100 else None


def text(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def uptime_seconds(value: Any) -> int | None:
    """pfSense's get_uptime(): '3 Days 04 Hours 12 Minutes 09 Seconds',
    '1 Day 00 Hour 05 Minutes 01 Second' or '04 Hours 12 Minutes 09 Seconds'
    (the words may be translated, so only the numbers are used)."""
    if not isinstance(value, str):
        return None
    parts = [int(n) for n in re.findall(r"\d+", value)]
    if len(parts) == 3:
        parts.insert(0, 0)
    if len(parts) != 4:
        return None
    days, h, mi, s = parts
    return ((days * 24 + h) * 60 + mi) * 60 + s


def load_avg(value: Any) -> list[float] | None:
    if isinstance(value, str):
        value = re.split(r"[,\s]+", value.strip())
    if not isinstance(value, list):
        return None
    values = [number(v) for v in value]
    values = [v for v in values if v is not None and v >= 0]
    return values[:3] or None


def speed_from_media(media: str) -> int | None:
    """'1000baseT <full-duplex>' → 1000, '2500Base-T' → 2500, '10Gbase-SR' → 10000."""
    m = re.search(r"(\d+(?:\.\d+)?)\s*(G)?base", media, re.IGNORECASE)
    if not m:
        return None
    value = float(m.group(1))
    return int(value * 1000) if m.group(2) else int(value)


# NICs of a hypervisor (pfSense running as a VM): no physical jack, made-up speed.
VIRTUAL_NIC = re.compile(r"^(vtnet|xn|hn|vmx)\d")
COPPER = re.compile(r"base-?T", re.IGNORECASE)  # 1000baseT, 2500Base-T, 10Gbase-T, 100baseTX
FIBER_OR_DAC = re.compile(
    r"base-?(SR|LR|ER|ZR|LRM|SX|LX|ZX|BX|CX|CR|KR|Twinax|AOC|SFI)", re.IGNORECASE
)
TUNNEL = (
    "ovpn",
    "tun",
    "tap",
    "wg",
    "gif",
    "gre",
    "ipsec",
    "enc",
    "ppp",
    "pppoe",
    "pptp",
    "l2tp",
    "tailscale",
    "zt",
)
VLAN_NAME = re.compile(r"^(?P<parent>[a-z][\w]*?\d+)\.(?P<tag>\d+)$")


def interface_type(hwif: str) -> str:
    if VLAN_NAME.match(hwif) or hwif.startswith("vlan"):
        return "vlan"
    if hwif.startswith(("lagg", "lag")):
        return "lag"
    if hwif.startswith("bridge"):
        return "bridge"
    if hwif.startswith(TUNNEL):
        return "tunnel"
    if hwif.startswith("lo"):
        return "loopback"
    if "_wlan" in hwif or hwif.startswith(("ath", "iwm", "iwn", "wlan")):
        return "wireless"
    if VIRTUAL_NIC.match(hwif):
        return "other"
    return "ethernet"


def connector(media: str, speed: int | None) -> str | None:
    """RJ45 or SFP from the current media (pfSense only reports it while the
    link is up)."""
    copper = bool(COPPER.search(media)) and not FIBER_OR_DAC.search(media)
    fiber = bool(FIBER_OR_DAC.search(media))
    if copper == fiber:
        return None
    if copper:
        return "rj45"
    return "qsfp" if speed and speed >= 40_000 else "sfp"


def with_prefix(ip: Any, prefix: Any) -> str | None:
    ip = text(ip)
    if not ip:
        return None
    p = text(str(prefix)) if prefix not in (None, "") else None
    return f"{ip}/{p}" if p and p.isdigit() else ip


def network(ip: Any, prefix: Any) -> str | None:
    """'192.168.20.1', '24' → '192.168.20.0/24'."""
    address = with_prefix(ip, prefix)
    if not address or "/" not in address:
        return None
    try:
        return str(ipaddress.ip_interface(address).network)
    except ValueError:
        return None


def ip_or_none(value: Any) -> str | None:
    """An IPv4 or IPv6 address, normalized; None for anything else (an alias)."""
    try:
        return str(ipaddress.ip_address(text(value) or ""))
    except ValueError:
        return None


def address_key(ip: str) -> tuple[int, int]:
    """Sorts IPv4 before IPv6, each in numeric order."""
    a = ipaddress.ip_address(ip)
    return a.version, int(a)


# --- readers ---------------------------------------------------------------


def system_status(c: Client) -> dict[str, Any]:
    try:
        return one(c, "system")
    except Forbidden as e:
        raise PluginError(
            "connected, but the API user cannot read the system status: "
            f"give it the privilege {privilege('system')}"
        ) from e
    except NotFound as e:
        raise PluginError(
            f"{c.base} has no REST API v2 (/api/v2/status/system): "
            "install the pfSense REST API package"
        ) from e


def os_version(version: dict[str, Any]) -> str | None:
    """'2.7.2-RELEASE' → 'pfSense CE 2.7.2'; '24.03-RELEASE' + patch 1 →
    'pfSense Plus 24.03-p1'. Plus versions are year.month."""
    base = text(version.get("base")) or (text(version.get("version")) or "").split("-")[0]
    if not base:
        return None
    major = number(base.split(".")[0]) or 0
    edition = "Plus" if major >= 21 else "CE"
    patch = (text(str(version.get("patch") or "")) or "").lstrip("p")
    suffix = f"-p{patch}" if patch.isdigit() and int(patch) > 0 else ""
    return f"pfSense {edition} {base}{suffix}"


def interfaces(
    c: Client, vlans: list[dict[str, Any]]
) -> tuple[list[Interface], dict[str, dict[str, Any]]]:
    """Assigned interfaces (pfSense's API lists only those). Also returns the
    raw rows by pfSense name (wan, lan, opt1) for the readers that need them."""
    data = rows(c, "interfaces")
    vlan_of = {v.get("vlanif"): v for v in vlans if v.get("vlanif")}
    out: list[Interface] = []
    by_name: dict[str, dict[str, Any]] = {}
    speeds: dict[str, int] = {}
    for row in data:
        hwif = text(row.get("hwif"))
        if not hwif:
            continue
        by_name[str(row.get("name") or hwif)] = row
        media = text(row.get("media")) or ""
        speed = speed_from_media(media)
        if speed:
            speeds[hwif] = speed
    for row in data:
        hwif = text(row.get("hwif"))
        if not hwif:
            continue
        kind = interface_type(hwif)
        media = text(row.get("media")) or ""
        status = str(row.get("status") or "").lower()
        up = status in ("up", "associated")
        speed = speed_from_media(media) if kind not in ("other", "tunnel") else None
        parent, tag = None, None
        if kind == "vlan":
            v = vlan_of.get(hwif) or {}
            m = VLAN_NAME.match(hwif)
            parent = text(v.get("if")) or (m.group("parent") if m else None)
            tag = nets.vlan_tag(v.get("tag"))
            if tag is None and m:
                tag = int(m.group("tag"))
            if not speed and parent:
                speed = speeds.get(parent)
        wan = is_wan(row)
        duplex = "full" if "full-duplex" in media else "half" if "half-duplex" in media else None
        ips = [
            ip
            for ip in (
                with_prefix(row.get("ipaddr"), row.get("subnet")),
                with_prefix(row.get("ipaddrv6"), row.get("subnetv6")),
            )
            if ip and not ip.lower().startswith("fe80")
        ]
        out.append(
            Interface(
                name=hwif,
                description=text(row.get("descr")),
                type=kind,
                connector=connector(media, speed) if kind in ("ethernet", "lag") else None,
                mac=mac(row.get("macaddr")),
                up=up,
                enabled=row.get("enable") if isinstance(row.get("enable"), bool) else None,
                speed_mbps=speed if up and speed else None,
                duplex=duplex if kind in ("ethernet", "lag") else None,
                media=media or None,
                ips=ips or None,
                wan=True if wan else None,
                parent=parent,
                vlan=tag if tag and 1 <= tag <= 4094 else None,
                rx_bytes=counter(row.get("inbytes")),
                tx_bytes=counter(row.get("outbytes")),
                rx_errors=counter(row.get("inerrs")),
                tx_errors=counter(row.get("outerrs")),
            )
        )
    return out, by_name


def is_wan(row: dict[str, Any]) -> bool:
    """pfSense marks an internet uplink by giving the interface an upstream
    gateway. The API only reports it while the interface is up, so the
    default WAN (pfSense name "wan") counts even when it is down."""
    return bool(text(row.get("gateway")) or text(row.get("gatewayv6"))) or row.get("name") == "wan"


def gateways(c: Client, by_name: dict[str, dict[str, Any]]) -> list[Gateway]:
    """Gateway status (dpinger). The interface is the one whose address is the
    probes' source (srcip), else the one whose gateway is the monitored IP."""
    out = []
    for g in rows(c, "gateways"):
        name = text(g.get("name"))
        if not name:
            continue
        srcip, monitor = text(g.get("srcip")), text(g.get("monitorip"))
        row = next(
            (
                r
                for r in by_name.values()
                if srcip and srcip in (r.get("ipaddr"), r.get("ipaddrv6"))
            ),
            None,
        ) or next(
            (
                r
                for r in by_name.values()
                if monitor and monitor in (r.get("gateway"), r.get("gatewayv6"))
            ),
            None,
        )
        address = None
        if row:
            v6 = ":" in (srcip or monitor or "")
            address = text(row.get("gatewayv6" if v6 else "gateway"))
        status = gateway_status(g)
        delay, loss = number(g.get("delay")), number(g.get("loss"))
        out.append(
            Gateway(
                name=name,
                interface=text(row.get("hwif")) if row else None,
                address=address,
                status=status,
                rtt_ms=delay if delay is not None and delay >= 0 and status != "down" else None,
                loss_pct=loss if loss is not None and 0 <= loss <= 100 else None,
            )
        )
    return out


def gateway_status(g: dict[str, Any]) -> str:
    """status is "online" or "down"; substatus says why: none, delay, loss,
    highdelay, highloss (still online when the gateway's action is disabled),
    force_down or down."""
    status = str(g.get("status") or "").lower()
    sub = str(g.get("substatus") or "").lower()
    if status in ("down", "force_down"):
        return "down"
    if status in ("online", "up", "none"):
        return "degraded" if sub in ("delay", "loss", "highdelay", "highloss") else "up"
    return "unknown"


def arp(c: Client, by_name: dict[str, dict[str, Any]]) -> list[ArpEntry]:
    """pfSense's ARP table names an assigned interface by its description
    ("LAN"); others by their real name. Both become the port name (igb1)."""
    port = {}
    for name, row in by_name.items():
        hwif = text(row.get("hwif"))
        if hwif:
            port[name] = hwif
            port[hwif] = hwif
            if text(row.get("descr")):
                port[row["descr"]] = hwif
    out = []
    for row in rows(c, "arp"):
        m, ip = mac(row.get("mac_address")), text(row.get("ip_address"))
        if not m or not ip or row.get("permanent") is True:
            continue
        intf = text(row.get("interface"))
        out.append(ArpEntry(ip=ip, mac=m, interface=port.get(intf or "", intf)))
    return out


# Lease states that are not in use (pfSense translates them; English here).
GONE = {"expired", "free", "reserved", "backup"}


def leases(c: Client) -> list[DhcpLease]:
    """Leases of the DHCP server in use (ISC or Kea) and static mappings.
    The end time is left out: pfSense formats it in UTC or local time
    depending on a setting the API does not show."""
    found: dict[tuple[str, str], DhcpLease] = {}
    for r in rows(c, "dhcp"):
        # IPv6 leases are kept too, when the package reports one with a MAC.
        m, ip = mac(r.get("mac")), ip_or_none(r.get("ip"))
        if not m or not ip:
            continue
        if str(r.get("active_status") or "").strip().lower() in GONE:
            continue
        found[(ip, m)] = DhcpLease(ip=ip, mac=m, hostname=text(r.get("hostname")))
    return sorted(found.values(), key=lambda lease: address_key(lease.ip))


def services(c: Client) -> list[Service]:
    out = []
    for s in rows(c, "services"):
        name = text(s.get("name"))
        if not name:
            continue
        out.append(
            Service(
                name=name,
                description=text(s.get("description")),
                running=s.get("status") if isinstance(s.get("status"), bool) else None,
                enabled=s.get("enabled") if isinstance(s.get("enabled"), bool) else None,
            )
        )
    return out


def vlans(vlan_rows: list[dict[str, Any]], by_name: dict[str, dict[str, Any]]) -> list[Vlan]:
    subnet = {
        r.get("hwif"): network(r.get("ipaddr"), r.get("subnet"))
        for r in by_name.values()
        if r.get("hwif")
    }
    out = []
    for v in vlan_rows:
        tag = nets.vlan_tag(v.get("tag"))
        if tag is None or not 1 <= tag <= 4094:
            continue
        vlanif = text(v.get("vlanif")) or (f"{v['if']}.{tag}" if text(v.get("if")) else None)
        out.append(
            Vlan(
                id=tag,
                name=text(v.get("descr")),
                interface=vlanif,
                subnet=subnet.get(vlanif),
            )
        )
    return out


def firewall_states(c: Client) -> FirewallStates | None:
    data = one(c, "states")
    current, limit = counter(data.get("currentstates")), counter(data.get("maximumstates"))
    if current is None and limit is None:
        return None
    return FirewallStates(current=current, limit=limit)


def dhcp_pools(
    c: Client, by_name: dict[str, dict[str, Any]], active: list[DhcpLease]
) -> list[DhcpPool]:
    """Usage of each enabled DHCP server: the addresses of its main range and
    extra pools, and the active leases in them."""
    leased = [ipaddress.ip_address(lease.ip) for lease in active if "." in lease.ip]
    out = []
    for server in rows(c, "dhcp_pools"):
        if server.get("enable") is False:
            continue
        ranges = []
        for r in [server, *[p for p in server.get("pool") or [] if isinstance(p, dict)]]:
            try:
                a = ipaddress.IPv4Address(str(r.get("range_from") or "").strip())
                b = ipaddress.IPv4Address(str(r.get("range_to") or "").strip())
            except ValueError:
                continue
            if a <= b:
                ranges.append((a, b))
        if not ranges:
            continue
        iface = str(server.get("interface") or server.get("id") or "")
        row = by_name.get(iface) or {}
        network = text(row.get("descr")) or network_of(row) or iface or f"{ranges[0][0]}"
        out.append(
            DhcpPool(
                network=network,
                total=sum(int(b) - int(a) + 1 for a, b in ranges),
                used=sum(1 for ip in leased if any(a <= ip <= b for a, b in ranges)),
            )
        )
    return sorted(out, key=lambda p: p.network)


def network_of(row: dict[str, Any]) -> str | None:
    return network(row.get("ipaddr"), row.get("subnet")) if row else None


def endpoint(host: Any, port: Any) -> str | None:
    host = text(host)
    if not host or host.lower() in ("(none)", "none"):
        return None
    port = text(str(port)) if port not in (None, "") else None
    if port and not host.endswith(f":{port}"):
        return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    return host


def when(unix: Any) -> datetime | None:
    n = number(unix)
    return datetime.fromtimestamp(n, timezone.utc) if n and n > 0 else None


def openvpn_servers(c: Client) -> list[VpnPeer]:
    """Clients connected to each OpenVPN server."""
    out = []
    for server in rows(c, "openvpn_servers"):
        for conn in server.get("conns") or []:
            name = text(conn.get("common_name")) or text(conn.get("user_name"))
            if not name:
                continue
            out.append(
                VpnPeer(
                    name=name,
                    protocol="openvpn",
                    endpoint=text(conn.get("remote_host")),
                    address=text(conn.get("virtual_addr")) or text(conn.get("virtual_addr6")),
                    connected=True,
                    rx_bytes=counter(conn.get("bytes_recv")),
                    tx_bytes=counter(conn.get("bytes_sent")),
                )
            )
    return out


def openvpn_clients(c: Client) -> list[VpnPeer]:
    """OpenVPN client instances of the firewall (tunnels to remote servers)."""
    out = []
    for client in rows(c, "openvpn_clients"):
        name = text(client.get("name"))
        if not name:
            continue
        status = str(client.get("status") or "").lower()
        state = str(client.get("state") or "").upper()
        out.append(
            VpnPeer(
                name=name,
                protocol="openvpn",
                endpoint=endpoint(client.get("remote_host"), client.get("remote_port")),
                address=text(client.get("virtual_addr")) or text(client.get("virtual_addr6")),
                connected=status == "up" or state == "CONNECTED",
            )
        )
    return out


# WireGuard renews a session every 2 minutes while traffic flows; a peer with no
# handshake for longer than this has no live session.
HANDSHAKE_S = 180


def wireguard(c: Client, now: float | None = None) -> list[VpnPeer]:
    """Peers of every WireGuard tunnel (the answer also carries pre-shared
    keys: they are never read)."""
    now = now if now is not None else time.time()
    out = []
    for tunnel in rows(c, "wireguard"):
        for peer in tunnel.get("peers") or []:
            key = text(peer.get("public_key"))
            name = text(peer.get("descr")) or (f"{key[:8]}…" if key else None)
            if not name:
                continue
            handshake = when(peer.get("latest_handshake"))
            allowed = peer.get("allowed_ips")
            if isinstance(allowed, list):
                allowed = ", ".join(str(a) for a in allowed if a)
            out.append(
                VpnPeer(
                    name=name,
                    protocol="wireguard",
                    endpoint=endpoint(peer.get("endpoint"), None),
                    address=text(allowed),
                    connected=bool(handshake and now - handshake.timestamp() <= HANDSHAKE_S),
                    last_handshake=handshake,
                    rx_bytes=counter(peer.get("transfer_rx")),
                    tx_bytes=counter(peer.get("transfer_tx")),
                )
            )
    return out


def ipsec(c: Client) -> list[VpnPeer]:
    """IKE security associations (one per IPsec tunnel that is up or
    connecting); traffic is the sum of its child SAs."""
    out = []
    for sa in rows(c, "ipsec"):
        name = text(sa.get("con_id")) or text(sa.get("remote_id")) or text(sa.get("remote_host"))
        if not name:
            continue
        children = [ch for ch in sa.get("child_sas") or [] if isinstance(ch, dict)]
        selectors = sorted({str(ts) for ch in children for ts in ch.get("remote_ts") or []})
        rx = [counter(ch.get("bytes_in")) for ch in children]
        tx = [counter(ch.get("bytes_out")) for ch in children]
        out.append(
            VpnPeer(
                name=name,
                protocol="ipsec",
                endpoint=endpoint(sa.get("remote_host"), sa.get("remote_port")),
                address=", ".join(selectors) or None,
                connected=str(sa.get("state") or "").upper() == "ESTABLISHED",
                rx_bytes=sum(v for v in rx if v is not None)
                if any(v is not None for v in rx)
                else None,
                tx_bytes=sum(v for v in tx if v is not None)
                if any(v is not None for v in tx)
                else None,
            )
        )
    return out


def vpn_peers(c: Client, missing: list[str]) -> list[VpnPeer]:
    out: list[VpnPeer] = []
    for what, fn in (
        ("openvpn_servers", openvpn_servers),
        ("openvpn_clients", openvpn_clients),
        ("wireguard", wireguard),
        ("ipsec", ipsec),
    ):
        out += optional(what, missing, lambda fn=fn: fn(c), [])
    return out


def temperatures(status: dict[str, Any]) -> list[Temperature] | None:
    """pfSense's system temperature: the first CPU core's sensor
    (dev.cpu.0.temperature), else the ACPI thermal zone."""
    celsius = number(status.get("temp_c"))
    if celsius is None:
        return None
    return [Temperature(sensor="CPU", kind="cpu", celsius=celsius)]


def wan_devices(ifaces: list[Interface]) -> set[str]:
    """The WANs and what they ride on (igc0.2000 → igc0)."""
    by_name = {i.name: i for i in ifaces}
    out: set[str] = set()
    for i in ifaces:
        cur = i if i.wan else None
        while cur is not None and cur.name not in out:
            out.add(cur.name)
            cur = by_name.get(cur.parent or "")
    return out


def add_laggs(ifaces: list[Interface], lagg_rows: list[dict[str, Any]]) -> list[Interface]:
    """Each LAGG member port gets its LAGG's name. pfSense lists only assigned
    interfaces, and a member can never be assigned: members (and an
    unassigned LAGG) are added with what the LAGG says of them, and the LAGG
    gets its members."""
    if "lag" not in Interface.model_fields:
        return ifaces
    out = list(ifaces)
    by_name = {i.name: i for i in out}
    for r in lagg_rows:
        lagg = text(r.get("laggif"))
        if not lagg:
            continue
        if lagg not in by_name:
            by_name[lagg] = Interface(name=lagg, type="lag", description=text(r.get("descr")))
            out.append(by_name[lagg])
        members = []
        for m in r.get("members") or []:
            m = text(m)
            if not m or m == lagg:
                continue
            if m not in by_name:
                by_name[m] = Interface(name=m, type=interface_type(m))
                out.append(by_name[m])
            by_name[m].lag = lagg
            members.append(m)
        by_name[lagg].members = members or None
    return out


def router_names(
    c: Client, names: dict[str, Any], ifaces: list[Interface], missing: list[str]
) -> dict[str, Any]:
    """Local DNS names (host overrides), the domain and the paused devices
    (left out with an Omini whose SDK does not know them yet)."""
    if "dns_records" not in Device.model_fields:
        return {}
    records = optional("dns", missing, lambda: manage.dns_records(manage.overrides(c)), [])
    aliases = optional("aliases", missing, lambda: nets.rows(c, nets.ALIASES), [])
    return {
        "dns_records": records or None,
        "dns_domain": text(names.get("domain")),
        "paused": manage.paused(manage.paused_alias(aliases)) or None,
    }


def router_networks(c: Client, ifaces: list[Interface], missing: list[str]) -> dict[str, Any]:
    """Each VLAN's network and the DHCP server's fixed addresses (left out
    with an Omini whose SDK does not know them yet)."""
    if "networks" not in Device.model_fields:
        return {}
    st = optional("networks", missing, lambda: nets.read_state(c, wan_devices(ifaces)), None)
    if not st:
        return {}
    return {
        "networks": nets.networks(st) or None,
        "dhcp_reservations": nets.reservations(st) or None,
    }


PORT_RANGE = re.compile(r"^(\d{1,5})(?:\s*[:-]\s*(\d{1,5}))?$")


def port_range(value: Any) -> tuple[int | None, int | None]:
    """'443' → (443, None); '27015:27020' or '27015-27020' → (27015, 27020).
    An alias name, or nothing, gives (None, None): the port is unknown."""
    m = PORT_RANGE.match(text(str(value)) or "") if value not in (None, "") else None
    if not m:
        return None, None
    lo, hi = int(m.group(1)), int(m.group(2)) if m.group(2) else None
    if not 1 <= lo <= 65535 or (hi is not None and not lo <= hi <= 65535):
        return None, None
    return lo, hi if hi != lo else None


def port_forwards(c: Client, by_name: dict[str, dict[str, Any]]) -> list[PortForward]:
    """NAT port forwards (Firewall → NAT → Port Forward). A "no redirect" rule
    forwards nothing; one whose external port is an alias, or for a protocol
    without ports (ICMP, ESP...), is left out: its port is unknown. A target
    that is an alias leaves the internal address empty."""
    out = []
    for r in rows(c, "port_forwards"):
        protocol = str(r.get("protocol") or "").lower()
        if protocol not in ("tcp", "udp", "tcp/udp") or r.get("nordr") is True:
            continue
        ext, ext_end = port_range(r.get("destination_port"))
        if ext is None:
            log.info("port forward %r: unknown external port", r.get("descr"))
            continue
        local, _ = port_range(r.get("local_port"))
        source = text(r.get("source"))
        iface = r.get("interface")
        if isinstance(iface, list):
            iface = next((i for i in iface if text(i)), None)
        iface = text(iface)
        row = by_name.get(iface or "") or {}
        out.append(
            PortForward(
                protocol=protocol,
                external_port=ext,
                external_port_end=ext_end,
                internal_ip=ip_or_none(r.get("target")),
                internal_port=local,
                source=None if not source or source.lower() == "any" else source,
                interface=text(row.get("hwif")) or iface,
                description=text(r.get("descr")),
                enabled=not r["disabled"] if isinstance(r.get("disabled"), bool) else None,
                upnp=False,
            )
        )
    return out


def exposure(c: Client, by_name: dict[str, dict[str, Any]], missing: list[str]) -> dict[str, Any]:
    """Port forwards (left out with an Omini whose SDK does not know them yet)."""
    if "port_forwards" not in Device.model_fields:
        return {}
    found = optional("port_forwards", missing, lambda: port_forwards(c, by_name), [])
    return {"port_forwards": found or None}


# --- plugin entry points -------------------------------------------------------


def collect(cfg: Config) -> list[Device]:
    c = client_from(cfg)
    try:
        status = system_status(c)
        missing: list[str] = []
        version = optional("version", missing, lambda: one(c, "version"), {})
        names = optional("hostname", missing, lambda: one(c, "hostname"), {})
        vlan_rows = optional("vlans", missing, lambda: rows(c, "vlans"), [])
        ifaces, by_name = optional(
            "interfaces", missing, lambda: interfaces(c, vlan_rows), ([], {})
        )
        ifaces = add_laggs(ifaces, optional("laggs", missing, lambda: rows(c, "laggs"), []))
        host = urlparse(c.base).hostname or c.base
        lan = by_name.get("lan") or {}
        macs = sorted({i.mac for i in ifaces if i.mac})
        ips = sorted(
            {ip.split("/")[0] for i in ifaces for ip in (i.ips or [])},
            key=address_key,
        )
        hostname = text(names.get("hostname"))
        domain = text(names.get("domain"))
        current = os_version(version)
        platform = text(status.get("platform"))
        dhcp = optional("dhcp", missing, lambda: leases(c), [])
        device = Device(
            key=mac(lan.get("macaddr")) or (macs[0] if macs else host),
            name=(f"{hostname}.{domain}" if hostname and domain else hostname) or host,
            host=host,
            role="firewall",
            vendor="pfSense",
            model=platform if platform and platform.lower() != "pfsense" else None,
            os_version=current,
            serial=text(status.get("serial")),
            uptime_s=uptime_seconds(status.get("uptime")),
            cpu_count=counter(status.get("cpu_count")) or None,
            cpu_pct=pct(status.get("cpu_usage")),
            mem_pct=pct(status.get("mem_usage")),
            swap_pct=pct(status.get("swap_usage")),
            load_avg=load_avg(status.get("cpu_load_avg")),
            temperatures=temperatures(status),
            # Only the installed version: the API has no update status.
            firmware=Firmware(current=current) if current else None,
            macs=macs or None,
            ips=ips or None,
            interfaces=ifaces or None,
            arp=optional("arp", missing, lambda: arp(c, by_name), []) or None,
            dhcp_leases=dhcp or None,
            dhcp_pools=optional("dhcp_pools", missing, lambda: dhcp_pools(c, by_name, dhcp), [])
            or None,
            gateways=optional("gateways", missing, lambda: gateways(c, by_name), []) or None,
            vlans=vlans(vlan_rows, by_name) or None,
            services=optional("services", missing, lambda: services(c), []) or None,
            vpn_peers=vpn_peers(c, missing) or None,
            firewall_states=optional("states", missing, lambda: firewall_states(c), None),
            **router_networks(c, ifaces, missing),
            **router_names(c, names, ifaces, missing),
            **exposure(c, by_name, missing),
        )
        if missing:
            log.warning("missing privileges: %s", ", ".join(sorted(set(missing))))
        return [device]
    finally:
        c.close()


CHANGES = (
    "network.set",
    "network.delete",
    "reservation.set",
    "reservation.delete",
    "dns.set",
    "dns.delete",
    "wol.send",
    "pause.set",
    "pause.delete",
)


def apply(cfg: Config, change: Any) -> list[Device]:
    """network.set: a VLAN's network (its VLAN on the port toward the switches,
    the interface and gateway, the DHCP range, the access rules); network.delete
    removes it; reservation.set and reservation.delete fix or free an address;
    dns.set and dns.delete a DNS Resolver host override; wol.send a magic
    packet; pause.set and pause.delete a device's addresses in the alias of
    paused devices (with its block rules). pfSense saves what the API changes;
    the plugin then reads the router again until it serves what was asked (and
    removes a network it created that does not come out as asked)."""
    if change.kind not in CHANGES:
        raise PluginError(f"this plugin cannot apply {change.kind}")
    value = change.value if isinstance(change.value, dict) else dict(change.value)
    c = client_from(cfg)
    try:
        system_status(c)
        missing: list[str] = []
        vlan_rows = optional("vlans", missing, lambda: rows(c, "vlans"), [])
        ifaces, by_name = optional(
            "interfaces", missing, lambda: interfaces(c, vlan_rows), ([], {})
        )
        if change.kind == "wol.send" and privilege("interfaces") in missing:
            # Without them there is no network to send the magic packet on.
            raise PluginError(f"give the API user the privilege {privilege('interfaces')}")
        wan = wan_devices(ifaces)
        if change.kind in ("dns.set", "dns.delete", "wol.send", "pause.set", "pause.delete"):
            reads(apply_other, c, change.kind, value, by_name, wan)
        else:
            reads(apply_network, c, change.kind, value, wan)
    finally:
        c.close()
    return collect(cfg)


def reads(fn: Callable[..., None], *args: Any) -> None:
    """A change: a read it needs that the API user may not make, or an
    endpoint the package does not have, names itself."""
    try:
        fn(*args)
    except Forbidden as e:
        raise PluginError(f"give the API user the privilege {e.privilege}") from e
    except NotFound as e:
        raise PluginError(f"this REST API package has no {e} endpoint: update the package") from e


def apply_network(c: Client, kind: str, value: dict[str, Any], wan: set[str]) -> None:
    def state() -> nets.State:
        return nets.read_state(c, wan) or nets.State()

    st = nets.read_state(c, wan)
    if st is None:
        raise PluginError(
            "changing networks needs the REST API package v2 and these privileges: "
            + "; ".join(nets.WRITE_PRIVILEGES)
        )
    if kind == "reservation.set":
        mac = nets.norm_mac(value.get("mac"))
        nets.reserve(c, st, value)
        nets.wait_for(
            lambda: any(
                r["mac"] == mac and r["ip"] == value["ip"] for r in nets.reservations(state())
            ),
            "the reservation",
        )
    elif kind == "reservation.delete":
        mac = nets.norm_mac(value.get("mac"))
        nets.unreserve(c, st, mac)
        nets.wait_for(
            lambda: not any(r["mac"] == mac for r in nets.reservations(state())),
            "the removal of the reservation",
        )
    elif kind == "network.set":
        nets.check_mdns(value)
        vid = int(value["vlan"])
        new = nets.find(st, vid) is None
        had_vlan = any(v["tag"] == vid for v in st.vlans.values())
        try:
            nets.apply_set(c, st, value)
            nets.wait_for(lambda: nets.matches(nets.read_state(c, wan), value), "the network")
        except (PluginError, Forbidden, NotFound):
            if new and vid != 1:
                undo(c, wan, vid, had_vlan)
            raise
    else:
        vid = int(value["vlan"])
        nets.apply_delete(c, st, vid)
        nets.wait_for(lambda: nets.find(state(), vid) is None, "the removal")


def apply_other(
    c: Client, kind: str, value: dict[str, Any], by_name: dict[str, dict[str, Any]], wan: set[str]
) -> None:
    if kind == "dns.set":
        manage.dns_set(c, value)
    elif kind == "dns.delete":
        manage.dns_delete(c, value)
    elif kind == "wol.send":
        manage.wake(c, by_name, wan, value)
    elif kind == "pause.set":
        manage.pause_set(c, wan, value)
    else:
        manage.pause_delete(c, wan, value)


def undo(c: Client, wan: set[str], vid: int, keep_vlan: bool) -> None:
    """Removes what a network.set that failed had created (the VLAN only when
    it was not there before)."""
    try:
        nets.remove(c, nets.read_state(c, wan) or nets.State(), vid, keep_vlan)
    except Exception:
        log.exception("could not remove what was created for VLAN %s", vid)


def test(cfg: Config) -> str:
    c = client_from(cfg)
    try:
        system_status(c)
        missing: list[str] = []
        version = optional("version", missing, lambda: one(c, "version"), {})
        names = optional("hostname", missing, lambda: one(c, "hostname"), {})
        for what in ("interfaces", "gateways", "arp", "dhcp"):
            optional(what, missing, lambda what=what: rows(c, what), None)
        name = text(names.get("hostname")) or c.base
        msg = f"Connected to {name} ({os_version(version) or 'pfSense'})"
        if missing:
            msg += ". Missing privileges: " + "; ".join(sorted(set(missing)))
        return msg
    finally:
        c.close()
