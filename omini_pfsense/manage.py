"""Local DNS names, Wake-on-LAN, paused devices and LAGGs on pfSense, through
the REST API package v2.

Endpoints and fields come from the package's OpenAPI schema
(https://pfrest.org/api-docs/openapi.json); none of it was tried on a real
pfSense yet. What the code relies on:

- DNS names are the DNS Resolver's (Unbound) host overrides: ``host`` and
  ``domain`` make the name, ``ip`` is a list, ``aliases`` more names for the
  same addresses. They wait for ``/services/dns_resolver/apply``. Ids are
  positions in the list, so several are removed from the last to the first.
- Wake-on-LAN takes pfSense's name of the interface (``lan``, ``opt1``) and
  the MAC; it changes nothing.
- A paused device's addresses are entries of the host alias ``omini_paused``,
  each entry's ``detail`` "Omini <mac> <name>" (pfSense keeps a description
  per address), so the alias alone says which MAC owns which address: the
  IPv4 ones Omini sent and the IPv6 ones the NDP table knows (``ndp -an``
  through the command prompt, the only way the package offers, when the API
  user may). The block rules (IPv4+IPv6) let the device reach ``omini_local``:
  private IPv4, IPv6 link-local, ULA, multicast and the LAN-side IPv6 networks. Rules
  are added at the end of the interface's list (the API has no placement),
  so the block rules are floating and quick: pfSense evaluates them before
  any interface rule, whatever comes after.
"""

from __future__ import annotations

import contextlib
import ipaddress
import re
from typing import Any

from omini_sdk import PluginError, log

from omini_pfsense import networks as nets
from omini_pfsense.client import Client, Forbidden, NotFound

HOST_OVERRIDES = "/api/v2/services/dns_resolver/host_overrides"
HOST_OVERRIDE = "/api/v2/services/dns_resolver/host_override"
DNS_APPLY = "/api/v2/services/dns_resolver/apply"
WOL = "/api/v2/services/wake_on_lan/send"
STATES = "/api/v2/firewall/states"
LAGGS = "/api/v2/interface/laggs"

PAUSED_ALIAS = nets.PAUSED_ALIAS
TAG = "Omini"


def privileges(*pairs: tuple[str, str]) -> list[str]:
    return [f"REST API - {path} {method}" for path, method in pairs]


DNS_PRIVILEGES = privileges(
    (HOST_OVERRIDES, "GET"),
    (HOST_OVERRIDE, "POST"),
    (HOST_OVERRIDE, "PATCH"),
    (HOST_OVERRIDE, "DELETE"),
    (DNS_APPLY, "POST"),
)
WOL_PRIVILEGES = privileges((WOL, "POST"))
PAUSE_PRIVILEGES = privileges(
    (nets.INTERFACES, "GET"),
    (nets.ALIASES, "GET"),
    (nets.ALIAS, "POST"),
    (nets.ALIAS, "PATCH"),
    (nets.ALIAS, "DELETE"),
    (nets.RULES, "GET"),
    (nets.RULE, "POST"),
    (nets.RULE, "DELETE"),
    (nets.FIREWALL_APPLY, "POST"),
    (STATES, "DELETE"),
)

text = nets.text


def ipv4(value: Any) -> str | None:
    try:
        return str(ipaddress.IPv4Address(text(value)))
    except ValueError:
        return None


def addresses(value: Any) -> list[str]:
    """A host override's ``ip``: a list (or a comma separated string)."""
    if isinstance(value, str):
        value = value.split(",")
    return [text(v) for v in value or [] if text(v)]


# --- local DNS names ------------------------------------------------------------


def fqdn(host: Any, domain: Any) -> str:
    return ".".join(p for p in (text(host).strip("."), text(domain).strip(".")) if p).lower()


def alias_names(r: dict[str, Any]) -> list[str]:
    return [
        fqdn(a.get("host"), a.get("domain"))
        for a in r.get("aliases") or []
        if isinstance(a, dict) and fqdn(a.get("host"), a.get("domain"))
    ]


def overrides(c: Client) -> list[dict[str, Any]]:
    return nets.rows(c, HOST_OVERRIDES)


def dns_records(rows: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Every name the host overrides answer (theirs and their aliases'), IPv4 only."""
    found: set[tuple[str, str]] = set()
    for r in rows:
        ips = [ip for ip in (ipv4(a) for a in addresses(r.get("ip"))) if ip]
        names = [n for n in (fqdn(r.get("host"), r.get("domain")), *alias_names(r)) if n]
        found |= {(n, ip) for n in names for ip in ips}
    return [
        {"name": n, "ip": ip}
        for n, ip in sorted(found, key=lambda x: (x[0], ipaddress.IPv4Address(x[1])))
    ]


def dns_name(value: Any) -> str:
    name = text(value).strip(".").lower()
    if not re.fullmatch(
        r"[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+", name
    ):
        raise PluginError(f"{value!r} is not a fully qualified DNS name")
    return name


def answers(c: Client, name: str) -> set[str]:
    return {r["ip"] for r in dns_records(overrides(c)) if r["name"] == name}


def check_not_alias(rows: list[dict[str, Any]], name: str) -> None:
    owner = next((r for r in rows if name in alias_names(r)), None)
    if owner is not None:
        raise PluginError(
            f"{name} is an alias of the host override "
            f"{fqdn(owner.get('host'), owner.get('domain'))} in pfSense: change it there"
        )


def dns_set(c: Client, value: dict[str, Any]) -> None:
    """Creates the host override, or points the one with that exact name to
    the address (it keeps its own description)."""
    name, ip = dns_name(value.get("name")), ipv4(value.get("ip"))
    if ip is None:
        raise PluginError(f"{value.get('ip')!r} is not an IPv4 address")
    rows = overrides(c)
    mine = sorted(
        (r for r in rows if fqdn(r.get("host"), r.get("domain")) == name),
        key=lambda r: r.get("id", 0),
    )
    if not mine:
        check_not_alias(rows, name)
        host, _, domain = name.partition(".")
        nets.write(
            c.post, HOST_OVERRIDE, {"host": host, "domain": domain, "ip": [ip], "descr": TAG}
        )
    else:
        first, rest = mine[0], mine[1:]
        for r in reversed(rest):  # the same name twice: one is enough
            nets.write(c.delete, HOST_OVERRIDE, {"id": r["id"]})
        if addresses(first.get("ip")) != [ip]:
            nets.write(c.patch, HOST_OVERRIDE, {"id": first["id"], "ip": [ip]})
        elif not rest:
            return
    nets.write(c.post, DNS_APPLY)
    nets.wait_for(lambda: answers(c, name) == {ip}, f"the DNS name {name}")


def dns_delete(c: Client, value: dict[str, Any]) -> None:
    name = dns_name(value.get("name"))
    rows = overrides(c)
    mine = [r for r in rows if fqdn(r.get("host"), r.get("domain")) == name]
    if not mine:
        check_not_alias(rows, name)
        return
    for r in sorted(mine, key=lambda r: r.get("id", 0), reverse=True):
        nets.write(c.delete, HOST_OVERRIDE, {"id": r["id"]})
    nets.write(c.post, DNS_APPLY)
    nets.wait_for(lambda: not answers(c, name), f"the removal of {name}")


# --- Wake-on-LAN ----------------------------------------------------------------


def wake_interface(by_name: dict[str, dict[str, Any]], wan: set[str], ip: Any) -> str:
    """pfSense's name of the interface whose network holds ip (the LAN without one)."""
    if not text(ip):
        if "lan" not in by_name:
            raise PluginError("pfSense has no LAN to send the magic packet on")
        return "lan"
    addr = ipv4(ip)
    if addr is None:
        raise PluginError(f"{ip!r} is not an IPv4 address")
    for name, row in by_name.items():
        if text(row.get("hwif")) in wan:
            continue
        mine, prefix = text(row.get("ipaddr")), text(row.get("subnet"))
        if not mine or not prefix.isdigit():
            continue
        with contextlib.suppress(ValueError):
            if ipaddress.IPv4Address(addr) in ipaddress.ip_interface(f"{mine}/{prefix}").network:
                return name
    raise PluginError(f"no network of pfSense holds {addr}")


def wake(
    c: Client, by_name: dict[str, dict[str, Any]], wan: set[str], value: dict[str, Any]
) -> None:
    mac = nets.norm_mac(value.get("mac"))
    if not mac:
        raise PluginError(f"{value.get('mac')!r} is not a MAC address")
    ifname = wake_interface(by_name, wan, value.get("ip"))
    nets.write(c.post, WOL, {"interface": ifname, "mac_addr": mac})


# --- paused devices ---------------------------------------------------------------

DETAIL = re.compile(r"^Omini ([0-9a-f]{2}(?::[0-9a-f]{2}){5})(?: (.*))?$")

# What a paused device still reaches: its own networks, IPv4 and IPv6.
LOCAL_ALIAS = "omini_local"
LOCAL_IPV6 = ["fe80::/10", "fc00::/7", "ff00::/8"]  # link-local, ULA, multicast
STATUS_INTERFACES = "/api/v2/status/interfaces"
# The package has no endpoint for the NDP table: it is read through the
# command prompt, only when the API user was given that privilege.
COMMAND_PROMPT = "/api/v2/diagnostics/command_prompt"
NDP = "/usr/sbin/ndp -an"


def paused_alias(aliases: list[dict[str, Any]]) -> dict[str, Any] | None:
    return next((a for a in aliases if text(a.get("name")) == PAUSED_ALIAS), None)


def local_alias(aliases: list[dict[str, Any]]) -> dict[str, Any] | None:
    return next((a for a in aliases if text(a.get("name")) == LOCAL_ALIAS), None)


def entries(alias: dict[str, Any] | None) -> list[tuple[str, str]]:
    """The alias's (address, detail) pairs."""
    if not alias:
        return []
    address = addresses(alias.get("address"))
    detail = alias.get("detail") or []
    if isinstance(detail, str):
        detail = detail.split("||")
    return [(a, text(detail[i]) if i < len(detail) else "") for i, a in enumerate(address)]


def owner(detail: str) -> tuple[str, str | None] | None:
    m = DETAIL.match(detail)
    return (m.group(1), text(m.group(2)) or None) if m else None


def mac_of(detail: str) -> str:
    return (owner(detail) or ("", None))[0]


def paused(alias: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Each paused MAC with its IPv4 addresses (the ones Omini sent), in the
    alias's order; its IPv6 entries come from the NDP table and are not reported."""
    out: dict[str, dict[str, Any]] = {}
    for address, detail in entries(alias):
        who = owner(detail)
        if who is None:
            continue
        mac, name = who
        d = out.setdefault(mac, {"mac": mac, "ips": [], "name": name})
        if ipv4(address) and address not in d["ips"]:
            d["ips"].append(address)
    return list(out.values())


def detail_for(mac: str, name: Any) -> str:
    """pfSense separates details with "||" and keeps them on one line."""
    clean = re.sub(r"[|\r\n]+", " ", text(name)).strip()[:60]
    return f"{TAG} {mac} {clean}" if clean else f"{TAG} {mac}"


def ipv6(value: Any) -> str | None:
    """A device's IPv6 address worth blocking: not link-local."""
    try:
        a = ipaddress.IPv6Address(text(value).split("%")[0])
    except ValueError:
        return None
    return None if a.is_link_local or a.is_multicast else str(a)


def neighbours(c: Client) -> dict[str, list[str]] | None:
    """MAC → IPv6 addresses, from the router's NDP table; None when it cannot
    be read (the API user may not use the command prompt)."""
    try:
        out = c.post(COMMAND_PROMPT, {"command": NDP})
    except (Forbidden, NotFound, PluginError) as e:
        log.info("could not read the NDP table: %s", e)
        return None
    table: dict[str, list[str]] = {}
    for line in text((out or {}).get("output") if isinstance(out, dict) else "").splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        ip, mac = ipv6(parts[0]), nets.norm_mac(parts[1])
        if ip and mac and ip not in table.setdefault(mac, []):
            table[mac].append(ip)
    return table


is_pause_rule = nets.is_pause_rule


def lan_side(st: nets.State) -> list[str]:
    """The interfaces a paused device may be behind: every enabled one but the WANs."""
    return [a.ifname for a in st.assigned if a.enabled and not a.wan and a.device not in st.wan]


def lan_ipv6(c: Client, st: nets.State) -> list[str]:
    """The LAN-side interfaces' IPv6 networks (e.g. the ISP's prefix on the
    LAN), as their status shows them; none when it cannot be read."""
    lan = set(lan_side(st))
    out = []
    with contextlib.suppress(Forbidden, NotFound, PluginError):
        for r in nets.rows(c, STATUS_INTERFACES):
            if text(r.get("name")) not in lan:
                continue
            with contextlib.suppress(ValueError):
                net = ipaddress.IPv6Interface(
                    f"{text(r.get('ipaddrv6'))}/{text(r.get('subnetv6'))}"
                ).network
                if not net.is_link_local and str(net) not in out:
                    out.append(str(net))
    return out


def local_networks(lan_v6: list[str]) -> list[str]:
    return list(dict.fromkeys([*nets.PRIVATE_RANGES, *LOCAL_IPV6, *lan_v6]))


def pause_rule(ifname: str) -> dict[str, Any]:
    return {
        "type": "block",
        "interface": [ifname],
        "ipprotocol": "inet46",
        "source": PAUSED_ALIAS,
        "destination": f"!{LOCAL_ALIAS}",
        "floating": True,
        "quick": True,
        "direction": "in",
        "descr": f"{nets.PREFIX}paused devices, no internet",
    }


def good(r: dict[str, Any]) -> bool:
    """A block rule as this version writes it: IPv4 and IPv6, to the local alias.
    Older ones (IPv4 only, to omini_private) are replaced at the next pause."""
    return (
        is_pause_rule(r)
        and text(r.get("ipprotocol")) == "inet46"
        and text(r.get("destination")) == f"!{LOCAL_ALIAS}"
        and r.get("disabled") is not True
    )


def ruled(st: nets.State) -> set[str]:
    """The interfaces that have the block rule."""
    return {i for r in st.rules or [] if good(r) for i in nets.interfaces_of(r)}


def read(c: Client, wan: set[str]) -> tuple[nets.State, list[dict[str, Any]]]:
    st = nets.read_state(c, wan)
    if st is None or st.rules is None:
        raise PluginError("pausing a device needs these privileges: " + "; ".join(PAUSE_PRIVILEGES))
    try:
        aliases = nets.rows(c, nets.ALIASES)
    except Forbidden as e:
        raise PluginError(f"give the API user the privilege {e.privilege}") from e
    return st, aliases


def own_addresses(c: Client, st: nets.State) -> set[str]:
    out = {a.gateway.partition("/")[0] for a in st.assigned if a.gateway}
    return out | {nets.management_ip(c)}


def write_alias(c: Client, alias: dict[str, Any] | None, pairs: list[tuple[str, str]]) -> None:
    body = {"address": [a for a, _ in pairs], "detail": [d for _, d in pairs]}
    if alias is None:
        nets.write(
            c.post,
            nets.ALIAS,
            {"name": PAUSED_ALIAS, "type": "host", "descr": f"{nets.PREFIX}paused devices", **body},
        )
    else:
        nets.write(c.patch, nets.ALIAS, {"id": alias["id"], **body})


def write_local_alias(c: Client, alias: dict[str, Any] | None, networks: list[str]) -> bool:
    """The networks a paused device still reaches; whether it changed."""
    if alias is not None and addresses(alias.get("address")) == networks:
        return False
    body = {"address": networks, "detail": ["Omini"] * len(networks)}
    if alias is None:
        nets.write(
            c.post,
            nets.ALIAS,
            {
                "name": LOCAL_ALIAS,
                "type": "network",
                "descr": f"{nets.PREFIX}local networks, IPv4 and IPv6",
                **body,
            },
        )
    else:
        nets.write(c.patch, nets.ALIAS, {"id": alias["id"], **body})
    return True


def delete_rules(c: Client, rules: list[dict[str, Any]]) -> None:
    """Ids are positions: the last first."""
    for r in sorted(
        (r for r in rules if isinstance(r.get("id"), int)), key=lambda r: r["id"], reverse=True
    ):
        nets.write(c.delete, nets.RULE, {"id": r["id"]})


def pause_set(c: Client, wan: set[str], value: dict[str, Any]) -> None:
    """Puts the MAC's addresses in the alias (replacing the ones it had): the
    IPv4 ones Omini sent and the IPv6 ones the NDP table knows for the MAC;
    the other paused devices' IPv6 entries are refreshed too. Makes sure every
    LAN-side interface has the block rule (IPv4 and IPv6)."""
    mac = nets.norm_mac(value.get("mac"))
    if not mac:
        raise PluginError(f"{value.get('mac')!r} is not a MAC address")
    given = [text(i) for i in value.get("ips") or []]
    ips = list(dict.fromkeys(ip for ip in (ipv4(i) for i in given) if ip))
    if not ips:
        raise PluginError("no IPv4 address to pause: the device has none known")
    st, aliases = read(c, wan)
    mine = own_addresses(c, st) & set(ips)
    if mine:
        raise PluginError(
            f"{', '.join(sorted(mine))} is pfSense's own address: it cannot be paused"
        )
    alias = paused_alias(aliases)
    detail = detail_for(mac, value.get("name"))
    ndp = neighbours(c)
    v6 = [ip for ip in (ipv6(i) for i in given) if ip]
    v6 = list(dict.fromkeys([*v6, *(ndp or {}).get(mac, [])]))
    keep: list[tuple[str, str]] = []
    others: dict[str, str] = {}  # the other paused devices: MAC → detail
    for a, d in entries(alias):
        if a in ips or a in v6 or mac_of(d) == mac:
            continue  # this device's (or an address that moved to it)
        if mac_of(d):
            others.setdefault(mac_of(d), d)
            if ndp is not None and ipv6(a):
                continue  # replaced by what the NDP table knows now
        keep.append((a, d))
    if ndp is not None:
        for other, d in others.items():
            keep += [(ip, d) for ip in ndp.get(other, []) if ip not in v6]
    pairs = list(dict.fromkeys(keep + [(ip, detail) for ip in ips + v6]))
    changed = alias is None or pairs != entries(alias)
    if changed:
        write_alias(c, alias, pairs)
    changed |= write_local_alias(c, local_alias(aliases), local_networks(lan_ipv6(c, st)))
    old = [r for r in st.rules or [] if is_pause_rule(r) and not good(r)]
    delete_rules(c, old)
    have = ruled(st)
    missing = [i for i in lan_side(st) if i not in have]
    for ifname in missing:
        nets.write(c.post, nets.RULE, pause_rule(ifname))
    if changed or missing or old:
        nets.write(c.post, nets.FIREWALL_APPLY)
    cut(c, ips)

    def done() -> bool:
        st2, aliases2 = read(c, wan)
        now = next((p for p in paused(paused_alias(aliases2)) if p["mac"] == mac), None)
        return (
            bool(now)
            and set(now["ips"]) == set(ips)
            and local_alias(aliases2) is not None
            and set(lan_side(st2)) <= ruled(st2)
        )

    nets.wait_for(done, "the pause")


def cut(c: Client, ips: list[str]) -> None:
    """Best effort: removes the open connections of the addresses (their
    states on the LAN side, "ip:port", and the NATed ones on the WAN,
    "wan:port (ip:port)"), so the block applies at once."""
    for ip in ips:
        for query in ({"source__startswith": f"{ip}:"}, {"source__contains": f"({ip}:"}):
            try:
                c.delete(STATES, {**query, "limit": 0})
            except (Forbidden, NotFound, PluginError) as e:
                log.info("could not cut the connections of %s: %s", ip, e)


def pause_delete(c: Client, wan: set[str], value: dict[str, Any]) -> None:
    """Takes the MAC's addresses (IPv4 and IPv6) out of the alias; with no
    entry left, the block rules (of any version) and both aliases go too."""
    mac = nets.norm_mac(value.get("mac"))
    if not mac:
        raise PluginError(f"{value.get('mac')!r} is not a MAC address")
    st, aliases = read(c, wan)
    alias = paused_alias(aliases)
    pairs = [(a, d) for a, d in entries(alias) if mac_of(d) != mac]
    if alias is None or pairs == entries(alias):
        return
    if pairs:
        write_alias(c, alias, pairs)
    else:
        delete_rules(c, [r for r in st.rules or [] if is_pause_rule(r)])
        nets.write(c.delete, nets.ALIAS, {"id": alias["id"]})
        # Ids are positions: read again for the local alias's.
        local = local_alias(nets.rows(c, nets.ALIASES))
        if local is not None:
            nets.write(c.delete, nets.ALIAS, {"id": local["id"]})
    nets.write(c.post, nets.FIREWALL_APPLY)

    def done() -> bool:
        st2, aliases2 = read(c, wan)
        alias2 = paused_alias(aliases2)
        gone = all(p["mac"] != mac for p in paused(alias2))
        return gone and (
            bool(entries(alias2)) or not any(is_pause_rule(r) for r in st2.rules or [])
        )

    nets.wait_for(done, "the end of the pause")


# --- LAGGs -----------------------------------------------------------------------


def laggs(c: Client) -> list[dict[str, Any]]:
    return nets.rows(c, LAGGS)
