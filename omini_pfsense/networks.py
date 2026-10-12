"""A VLAN's network on pfSense: its VLAN, interface, gateway, DHCP range and
access rules, and the DHCP server's fixed addresses. Read for every round,
and changed by network.set, network.delete, reservation.set and
reservation.delete through the REST API package v2.

Endpoints and fields come from the package's OpenAPI schema
(https://pfrest.org/api-docs/openapi.json); none of it was tried on a real
pfSense yet. Things the schema says that the code relies on:

- VLANs (``/api/v2/interface/vlan``) apply immediately; interfaces, DHCP
  servers and firewall rules wait for their ``…/apply`` endpoint.
- An interface's id is pfSense's name for it (``lan``, ``opt3``); a DHCP
  server's id is its interface's; a VLAN's, a rule's and a static mapping's
  id is its position in its list, so ids after a removed one move down:
  several are always removed from the last to the first.
"""

from __future__ import annotations

import contextlib
import ipaddress
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from omini_sdk import PluginError

from omini_pfsense.client import Client, Forbidden, NotFound

INTERFACES = "/api/v2/interfaces"  # the assigned interfaces' configuration
INTERFACE = "/api/v2/interface"
INTERFACE_APPLY = "/api/v2/interface/apply"
VLANS = "/api/v2/interface/vlans"
VLAN = "/api/v2/interface/vlan"
DHCP_SERVERS = "/api/v2/services/dhcp_servers"
DHCP_SERVER = "/api/v2/services/dhcp_server"
DHCP_APPLY = "/api/v2/services/dhcp_server/apply"
STATIC_MAPPING = "/api/v2/services/dhcp_server/static_mapping"
RULES = "/api/v2/firewall/rules"
RULE = "/api/v2/firewall/rule"
ALIASES = "/api/v2/firewall/aliases"
ALIAS = "/api/v2/firewall/alias"
FIREWALL_APPLY = "/api/v2/firewall/apply"

# The privileges a change needs, as the package names them ("REST API -
# <endpoint> <METHOD>"), for the README and the error that lists them.
WRITE_PRIVILEGES = [
    f"REST API - {path} {method}"
    for path, method in (
        (INTERFACES, "GET"),
        (VLAN, "POST"),
        (VLAN, "DELETE"),
        (INTERFACE, "POST"),
        (INTERFACE, "PATCH"),
        (INTERFACE, "DELETE"),
        (INTERFACE_APPLY, "POST"),
        (DHCP_SERVER, "POST"),
        (DHCP_SERVER, "PATCH"),
        (DHCP_SERVER, "DELETE"),
        (DHCP_APPLY, "POST"),
        (STATIC_MAPPING, "POST"),
        (STATIC_MAPPING, "PATCH"),
        (STATIC_MAPPING, "DELETE"),
        (RULES, "GET"),
        (RULE, "POST"),
        (RULE, "DELETE"),
        (ALIASES, "GET"),
        (ALIAS, "POST"),
        (FIREWALL_APPLY, "POST"),
    )
]

# The private ranges, an alias the "Internet only" rules block.
PRIVATE_ALIAS = "omini_private"
PRIVATE_RANGES = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
# What Omini writes starts with this, so a person reading it knows.
PREFIX = "Omini: "


def rows(c: Client, path: str) -> list[dict[str, Any]]:
    data = c.get(path, params={"limit": 0})
    return [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []


def text(value: Any) -> str:
    return "" if value is None else str(value).strip()


@dataclass
class Assigned:
    """An assigned interface: lan, opt3..."""

    ifname: str
    device: str  # igc1, igc1.30
    descr: str
    gateway: str  # "192.168.30.1/24", "" when not statically addressed
    enabled: bool
    wan: bool  # has an upstream gateway


@dataclass
class State:
    """What the router has, read once per change or round."""

    assigned: list[Assigned] = field(default_factory=list)
    vlans: dict[str, dict[str, Any]] = field(default_factory=dict)  # device → {id, tag, parent}
    wan: set[str] = field(default_factory=set)  # devices that are WANs or carry one
    dhcp: dict[str, dict[str, Any]] | None = None  # ifname → server; None: cannot read
    rules: list[dict[str, Any]] | None = None  # None: cannot read


def read_state(c: Client, wan_devices: set[str]) -> State | None:
    """The router's networks as the API shows them; None without the
    interfaces' configuration (an older package, or no privilege)."""
    try:
        assigned_rows = rows(c, INTERFACES)
    except (NotFound, Forbidden):
        return None
    st = State(wan=set(wan_devices))
    for r in assigned_rows:
        ifname, device = text(r.get("id")), text(r.get("if"))
        if not ifname or not device:
            continue
        ip, prefix = text(r.get("ipaddr")), text(r.get("subnet"))
        static = text(r.get("typev4")) == "static" and ip and prefix.isdigit()
        st.assigned.append(
            Assigned(
                ifname=ifname,
                device=device,
                descr=text(r.get("descr")),
                gateway=f"{ip}/{prefix}" if static else "",
                enabled=r.get("enable") is not False,
                wan=bool(text(r.get("gateway"))) or ifname == "wan",
            )
        )
    with contextlib.suppress(NotFound, Forbidden):
        for r in rows(c, VLANS):
            tag, parent = r.get("tag"), text(r.get("if"))
            if not isinstance(tag, int) or not parent:
                continue
            device = text(r.get("vlanif")) or f"{parent}.{tag}"
            st.vlans[device] = {"id": r.get("id"), "tag": tag, "parent": parent}
    with contextlib.suppress(NotFound, Forbidden):
        st.dhcp = {
            text(r.get("interface") or r.get("id")): r
            for r in rows(c, DHCP_SERVERS)
            if text(r.get("interface") or r.get("id"))
        }
    with contextlib.suppress(NotFound, Forbidden):
        st.rules = rows(c, RULES)
    return st


def vlan_of(st: State, a: Assigned) -> int | None:
    """The VLAN an interface serves: its VLAN device's tag; the LAN is VLAN 1."""
    if a.device in st.vlans:
        return st.vlans[a.device]["tag"] or None
    return 1 if a.ifname == "lan" else None


def dhcp_of(st: State, ifname: str) -> dict[str, Any] | None:
    if st.dhcp is None:
        return None
    server = st.dhcp.get(ifname)
    if not server or server.get("enable") is not True:
        return {"enabled": False}
    lo, hi = text(server.get("range_from")), text(server.get("range_to"))
    if not lo or not hi:
        return {"enabled": False}
    return {"enabled": True, "from": lo, "to": hi}


def interfaces_of(r: dict[str, Any]) -> list[str]:
    value = r.get("interface")
    if isinstance(value, str):
        value = value.split(",")
    return [text(v) for v in value or [] if text(v)]


def rules_on(st: State, ifname: str) -> list[dict[str, Any]]:
    """The enabled rules that match traffic coming in on the interface."""
    return [
        r for r in st.rules or [] if ifname in interfaces_of(r) and r.get("disabled") is not True
    ]


def rule_shape(r: dict[str, Any], ifname: str) -> str:
    """A rule as one of the presets' pieces: dns, block_private, pass_any or other."""
    kind = text(r.get("type")).lower()
    src = text(r.get("source")).lower()
    dst = text(r.get("destination")).lower()
    port = text(r.get("destination_port")).lower()
    if interfaces_of(r) != [ifname] or r.get("floating") is True:
        return "other"
    if src != ifname.lower():
        return "other"
    if kind == "pass" and dst == "any" and not port:
        return "pass_any"
    if kind in ("block", "reject") and dst == PRIVATE_ALIAS and not port:
        return "block_private"
    if kind == "pass" and dst in (f"{ifname}:ip", f"{ifname}ip", "(self)") and port == "53":
        return "dns"
    return "other"


def access_of(st: State, ifname: str) -> str | None:
    """Which of the three choices the interface's rules are, else custom.
    pfSense's default LAN rules (allow to any, IPv4 and IPv6) count as all."""
    if st.rules is None:
        return None
    shapes = [rule_shape(r, ifname) for r in rules_on(st, ifname)]
    if not shapes or "other" in shapes:
        return "custom"
    core: list[str] = []
    for s in shapes:
        if s != "dns" and (not core or core[-1] != s):
            core.append(s)
    if core == ["pass_any"]:
        return "all"
    if core == ["block_private", "pass_any"]:
        return "internet"
    if not core:
        return "local"
    return "custom"


def private(gateway: str) -> bool:
    try:
        return ipaddress.ip_interface(gateway).ip.is_private
    except ValueError:
        return False


def networks(st: State) -> list[dict[str, Any]]:
    """Each VLAN's network: the statically addressed interfaces, but WANs."""
    out = []
    for a in st.assigned:
        vid = vlan_of(st, a)
        if not vid or not a.gateway or a.wan or a.device in st.wan or not private(a.gateway):
            continue
        out.append(
            {
                "vlan": vid,
                "name": a.descr or None,
                "interface": a.ifname,
                "device": a.device,
                "parent": (st.vlans.get(a.device) or {}).get("parent") or None,
                "gateway": a.gateway,
                "dhcp": dhcp_of(st, a.ifname),
                "access": access_of(st, a.ifname),
                # Avahi (pfSense's mDNS repeater) is not in the REST API.
                "mdns": None,
            }
        )
    return sorted(out, key=lambda n: n["vlan"])


def find(st: State, vid: int) -> dict[str, Any] | None:
    return next((n for n in networks(st) if n["vlan"] == vid), None)


# --- changes ------------------------------------------------------------------


def write(fn, *args: Any) -> Any:
    """A change: a missing privilege names itself."""
    try:
        return fn(*args)
    except Forbidden as e:
        raise PluginError(
            f"the API user may not change this: give it the privilege {e.privilege} "
            "(and remove 'User - Config: Deny Config Write' if it has it)"
        ) from e


def descr_for(name: str, vid: int) -> str:
    """An interface description pfSense accepts: letters, digits and _ only,
    not starting with a digit."""
    out = re.sub(r"[^A-Za-z0-9_]+", "_", name).strip("_")[:22]
    if not out or out[0].isdigit():
        out = f"VLAN{vid}" + (f"_{out}" if out else "")
    return out


def lan_port(st: State) -> str:
    lan = next((a for a in st.assigned if a.ifname == "lan"), None)
    return lan.device if lan else ""


def check_parent(parent: str, vid: int) -> None:
    if not parent:
        raise PluginError(
            f"no port to put VLAN {vid} on: name the router's port toward the switches"
        )
    if parent.startswith("bridge") or "." in parent:
        raise PluginError(
            f"VLAN {vid} cannot ride on {parent}: name the router's physical port "
            "toward the switches"
        )


def ensure_vlan(c: Client, st: State, vid: int, parent: str, name: str) -> str:
    """The VLAN device on parent (igc1.30), created when missing."""
    for device, v in st.vlans.items():
        if v["tag"] == vid and v["parent"] == parent:
            return device
    check_parent(parent, vid)
    write(c.post, VLAN, {"if": parent, "tag": vid, "descr": f"{PREFIX}{name or f'VLAN {vid}'}"})
    for r in rows(c, VLANS):
        if r.get("tag") == vid and text(r.get("if")) == parent:
            device = text(r.get("vlanif")) or f"{parent}.{vid}"
            st.vlans[device] = {"id": r.get("id"), "tag": vid, "parent": parent}
            return device
    raise PluginError(f"pfSense did not create VLAN {vid} on {parent}")


def management_ip(c: Client) -> str:
    return urlparse(c.base).hostname or ""


def ensure_assigned(c: Client, st: State, device: str, name: str, vid: int, gateway: str) -> str:
    """The interface on the device with the gateway address; its name (opt3)."""
    ip, _, prefix = gateway.partition("/")
    current = next((a for a in st.assigned if a.device == device), None)
    body: dict[str, Any] = {"enable": True, "typev4": "static", "ipaddr": ip, "subnet": int(prefix)}
    if current is None:
        body = {"if": device, "descr": descr_for(name, vid), **body}
        created = write(c.post, INTERFACE, body)
        ifname = text(created.get("id")) if isinstance(created, dict) else ""
    else:
        ifname = current.ifname
        old_ip = current.gateway.partition("/")[0]
        if old_ip and old_ip != ip and old_ip == management_ip(c):
            raise PluginError(
                f"{old_ip} is the address Omini reaches pfSense at: change it in pfSense itself"
            )
        descr = descr_for(name, vid) if name else current.descr
        if (current.descr, current.gateway, current.enabled) == (descr, gateway, True):
            return ifname
        write(c.patch, INTERFACE, {"id": ifname, "descr": descr, **body})
    write(c.post, INTERFACE_APPLY)
    if ifname:
        return ifname
    for r in rows(c, INTERFACES):
        if text(r.get("if")) == device:
            return text(r.get("id"))
    raise PluginError(f"pfSense did not assign {device}")


def set_dhcp(
    c: Client, st: State, ifname: str, gateway: str, dhcp: dict[str, Any] | None, new: bool
) -> None:
    """The DHCP server of the interface: on with the range, or off. A network
    Omini creates hands out its gateway as router and DNS server."""
    if st.dhcp is None:
        st.dhcp = {}
    server = st.dhcp.get(ifname)
    on = bool(dhcp and dhcp.get("enabled"))
    if on:
        lo, hi = str(dhcp["from"]), str(dhcp["to"])
        if server and (
            server.get("enable"),
            text(server.get("range_from")),
            text(server.get("range_to")),
        ) == (
            True,
            lo,
            hi,
        ):
            return
        body: dict[str, Any] = {"enable": True, "range_from": lo, "range_to": hi}
        if new:
            body["dnsserver"] = [gateway.partition("/")[0]]
        if server is None:
            try:
                write(c.post, DHCP_SERVER, {"interface": ifname, **body})
            except NotFound:
                # Packages before DHCP servers could be created: every static
                # interface already has one to change.
                write(c.patch, DHCP_SERVER, {"id": ifname, **body})
        else:
            write(c.patch, DHCP_SERVER, {"id": ifname, **body})
    elif server and server.get("enable") is True:
        write(c.patch, DHCP_SERVER, {"id": ifname, "enable": False})
    else:
        return
    write(c.post, DHCP_APPLY)


def ensure_private_alias(c: Client) -> None:
    if any(text(a.get("name")) == PRIVATE_ALIAS for a in rows(c, ALIASES)):
        return
    write(
        c.post,
        ALIAS,
        {
            "name": PRIVATE_ALIAS,
            "type": "network",
            "descr": f"{PREFIX}private networks",
            "address": PRIVATE_RANGES,
            "detail": ["Omini"] * len(PRIVATE_RANGES),
        },
    )


def preset_rules(access: str, ifname: str, name: str) -> list[dict[str, Any]]:
    def rule(kind: str, dst: str, what: str, **extra: Any) -> dict[str, Any]:
        return {
            "type": kind,
            "interface": [ifname],
            "ipprotocol": "inet",
            "source": ifname,
            "destination": dst,
            "descr": f"{PREFIX}{name or ifname} {what}",
            **extra,
        }

    dns = rule("pass", f"{ifname}:ip", "DNS", protocol="tcp/udp", destination_port="53")
    if access == "all":
        return [rule("pass", "any", "to everything")]
    if access == "internet":
        return [
            dns,
            rule("block", PRIVATE_ALIAS, "not to other networks"),
            rule("pass", "any", "to the internet"),
        ]
    return [dns]  # local: its own network only


def delete_rules(c: Client, st: State, ifname: str) -> bool:
    """Removes the interface's rules, the last first (ids are positions)."""
    found = sorted(
        (r for r in st.rules or [] if ifname in interfaces_of(r) and isinstance(r.get("id"), int)),
        key=lambda r: r["id"],
        reverse=True,
    )
    for r in found:
        write(c.delete, RULE, {"id": r["id"]})
    return bool(found)


def set_access(c: Client, st: State, ifname: str, access: str | None, name: str) -> None:
    """Replaces the interface's rules with the chosen access; custom (or none)
    leaves them as they are."""
    if access not in ("internet", "all", "local"):
        return
    if st.rules is None:
        raise PluginError(
            "the API user cannot read the firewall rules: give it the privilege "
            f"REST API - {RULES} GET"
        )
    if access_of(st, ifname) == access:
        return
    if access == "internet":
        ensure_private_alias(c)
    delete_rules(c, st, ifname)
    for r in preset_rules(access, ifname, name):
        write(c.post, RULE, r)
    write(c.post, FIREWALL_APPLY)


def apply_set(c: Client, st: State, want: dict[str, Any]) -> None:
    vid = int(want["vlan"])
    name = str(want.get("name") or "")
    gateway = str(want["gateway"])
    existing = find(st, vid)
    if existing:
        device = existing["device"]
    elif vid == 1:
        raise PluginError("the router has no LAN to change")
    else:
        parent = str(want.get("parent") or "") or lan_port(st)
        device = ensure_vlan(c, st, vid, parent, name)
    ifname = ensure_assigned(c, st, device, name, vid, gateway)
    set_dhcp(c, st, ifname, gateway, want.get("dhcp"), existing is None)
    set_access(c, st, ifname, want.get("access"), name or ifname)


def check_mdns(want: dict[str, Any]) -> None:
    if want.get("mdns"):
        raise PluginError(
            "pfSense's REST API cannot drive the Avahi package (its mDNS repeater): "
            "turn on discovery between networks in Services → Avahi on pfSense"
        )


def remove(c: Client, st: State, vid: int, keep_vlan: bool = False) -> None:
    """Removes what pfSense has of the network on vid: rules, DHCP server,
    interface and VLAN, whichever exist (also what a failed change left)."""
    if vid == 1:
        raise PluginError("the LAN cannot be removed from Omini")
    device = next((d for d, v in st.vlans.items() if v["tag"] == vid), None)
    a = next((a for a in st.assigned if device and a.device == device), None)
    if a is not None:
        if a.wan or a.device in st.wan:
            raise PluginError(f"VLAN {vid} carries a WAN: Omini does not remove it")
        if delete_rules(c, st, a.ifname):
            write(c.post, FIREWALL_APPLY)
        if st.dhcp is not None and a.ifname in st.dhcp:
            try:
                write(c.delete, DHCP_SERVER, {"id": a.ifname})
            except NotFound:
                write(c.patch, DHCP_SERVER, {"id": a.ifname, "enable": False})
            write(c.post, DHCP_APPLY)
        write(c.delete, INTERFACE, {"id": a.ifname, "apply": True})
    if device is not None and not keep_vlan and isinstance(st.vlans[device].get("id"), int):
        write(c.delete, VLAN, {"id": st.vlans[device]["id"]})


def apply_delete(c: Client, st: State, vid: int) -> None:
    if vid != 1 and find(st, vid) is None:
        raise PluginError(f"the router serves no network on VLAN {vid}")
    remove(c, st, vid)


def wait_for(check, what: str, tries: int = 5, pause: float = 1.0) -> None:
    """The API answers once pfSense saved a change; reads again a few times
    in case an interface takes a moment to come up."""
    for i in range(tries):
        if check():
            return
        if i < tries - 1:
            time.sleep(pause)
    raise PluginError(f"pfSense did not apply {what}")


def matches(st: State | None, want: dict[str, Any]) -> bool:
    """Whether the router serves want as asked."""
    if st is None:
        return False
    have = find(st, int(want["vlan"]))
    if have is None or have["gateway"] != want.get("gateway"):
        return False
    d, h = want.get("dhcp") or {"enabled": False}, have.get("dhcp") or {"enabled": False}
    if bool(d.get("enabled")) != bool(h.get("enabled")):
        return False
    if d.get("enabled") and (d.get("from"), d.get("to")) != (h.get("from"), h.get("to")):
        return False
    access = want.get("access")
    return access not in ("internet", "all", "local") or have["access"] == access


# --- reservations (a fixed address for a MAC) -----------------------------------


def norm_mac(value: Any) -> str:
    raw = re.sub(r"[^0-9a-f]", "", text(value).lower())
    return ":".join(raw[i : i + 2] for i in range(0, 12, 2)) if len(raw) == 12 else ""


def hostname(name: str) -> str:
    """A name DHCP can hand out: letters, digits and dashes."""
    out = re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-")
    return out[:63] or "device"


def mappings(st: State) -> list[tuple[str, dict[str, Any]]]:
    """Every static mapping with its DHCP server's interface."""
    return [
        (ifname, m)
        for ifname, server in (st.dhcp or {}).items()
        for m in server.get("staticmap") or []
        if isinstance(m, dict)
    ]


def reservations(st: State) -> list[dict[str, Any]]:
    out = []
    for _, m in mappings(st):
        mac, ip = norm_mac(m.get("mac")), text(m.get("ipaddr"))
        if mac and ip:
            out.append({"mac": mac, "ip": ip, "name": text(m.get("hostname")) or None})
    return out


def reserve(c: Client, st: State, want: dict[str, Any]) -> None:
    mac, ip = norm_mac(want.get("mac")), str(want.get("ip") or "")
    if not mac:
        raise PluginError(f"{want.get('mac')!r} is not a MAC address")
    addr = ipaddress.IPv4Address(ip)
    ifname = next(
        (
            a.ifname
            for a in st.assigned
            if a.gateway and addr in ipaddress.ip_interface(a.gateway).network
        ),
        None,
    )
    if ifname is None or (dhcp_of(st, ifname) or {}).get("enabled") is not True:
        raise PluginError(f"no DHCP server hands out {ip}: turn DHCP on in that network first")
    body = {"mac": mac, "ipaddr": ip, "hostname": hostname(str(want.get("name") or ""))}
    current = [(i, m) for i, m in mappings(st) if norm_mac(m.get("mac")) == mac]
    same = next((m for i, m in current if i == ifname), None)
    for i, m in sorted(
        ((i, m) for i, m in current if i != ifname), key=lambda x: x[1]["id"], reverse=True
    ):
        write(c.delete, STATIC_MAPPING, {"parent_id": i, "id": m["id"]})
    if same is not None:
        write(c.patch, STATIC_MAPPING, {"parent_id": ifname, "id": same["id"], **body})
    else:
        write(c.post, STATIC_MAPPING, {"parent_id": ifname, **body, "descr": "Omini"})
    write(c.post, DHCP_APPLY)


def unreserve(c: Client, st: State, mac_value: Any) -> None:
    mac = norm_mac(mac_value)
    found = sorted(
        ((i, m) for i, m in mappings(st) if norm_mac(m.get("mac")) == mac),
        key=lambda x: (x[0], x[1]["id"]),
        reverse=True,
    )
    for i, m in found:
        write(c.delete, STATIC_MAPPING, {"parent_id": i, "id": m["id"]})
    if found:
        write(c.post, DHCP_APPLY)
