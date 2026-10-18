"""DNS names, Wake-on-LAN, paused devices and LAGGs against a stateful fake of
the REST API package v2 (the networks' Router, plus host overrides, WoL,
alias changes, state kills and LAGGs)."""

import copy

import httpx
import pytest
from omini_sdk import PluginError

import omini_pfsense.collect as collect_module
import omini_pfsense.networks as networks_module
from tests.conftest import error
from tests.test_networks import Router, change, networks, ok

PAUSE_RULE = "/api/v2/firewall/rule"


class Box(Router):
    def __init__(self):
        super().__init__()
        self.overrides = [
            {
                "host": "nas",
                "domain": "home.arpa",
                "ip": ["192.168.1.20"],
                "descr": "by hand",
                "aliases": [{"host": "files", "domain": "home.arpa", "descr": ""}],
            },
            {
                "host": "v6only",
                "domain": "home.arpa",
                "ip": ["fd00::5"],
                "descr": "",
                "aliases": [],
            },
        ]
        self.woken = []
        self.killed = []
        self.laggs = [
            {
                "laggif": "lagg0",
                "members": ["igc2", "igc3"],
                "proto": "lacp",
                "descr": "to the core switch",
            }
        ]
        self.dns_applied = 0
        # `ndp -an` through the command prompt; None: the package answers 404.
        self.ndp = None
        self.commands = []
        self.status_interfaces = None  # None: the fixture's
        self.dns_lag = 0  # reads that still show the old host overrides after a change
        self._stale = None

    def get(self, path):
        if path == "/api/v2/services/dns_resolver/host_overrides":
            rows = self._stale if self._stale is not None and self.dns_lag > 0 else self.overrides
            if self.dns_lag > 0:
                self.dns_lag -= 1
            return ok([{"id": i, **copy.deepcopy(o)} for i, o in enumerate(rows)])
        if path == "/api/v2/status/interfaces" and self.status_interfaces is not None:
            return ok(self.status_interfaces)
        if path == "/api/v2/interface/laggs":
            return ok([{"id": i, **lg} for i, lg in enumerate(self.laggs)])
        return super().get(path)

    def write(self, method, path, q, body):
        if path == "/api/v2/services/dns_resolver/host_override":
            self._stale = copy.deepcopy(self.overrides)
            if method == "POST":
                self.overrides.append({"aliases": [], **body})
                return ok({"id": len(self.overrides) - 1, **body})
            if method == "PATCH":
                self.overrides[body["id"]].update({k: v for k, v in body.items() if k != "id"})
                return ok(body)
            return ok(self.overrides.pop(int(q["id"])))
        if path == "/api/v2/services/dns_resolver/apply":
            self.dns_applied += 1
            return ok({"applied": True})
        if (method, path) == ("POST", "/api/v2/services/wake_on_lan/send"):
            if body.get("interface") not in self.interfaces:
                return error(400, "bad request", "FIELD_INVALID_CHOICE", "Invalid interface")
            self.woken.append(body)
            return ok(body)
        if (method, path) == ("PATCH", "/api/v2/firewall/alias"):
            self.aliases[body["id"]].update({k: v for k, v in body.items() if k != "id"})
            return ok(body)
        if (method, path) == ("DELETE", "/api/v2/firewall/alias"):
            name = self.aliases[int(q["id"])]["name"]
            if any(name in (r.get("source"), r.get("destination")) for r in self.rules):
                return error(409, "conflict", "ALIAS_IN_USE", "Alias is in use")
            return ok(self.aliases.pop(int(q["id"])))
        if (method, path) == ("POST", "/api/v2/diagnostics/command_prompt"):
            self.commands.append(body["command"])
            if self.ndp is None:
                return error(404, "not found", "ENDPOINT_NOT_FOUND", "Endpoint not found")
            return ok({"output": self.ndp, "result_code": 0})
        if (method, path) == ("DELETE", "/api/v2/firewall/states"):
            self.killed.append(q)
            return ok([])
        return super().write(method, path, q, body)

    def pause_rules(self):
        return [r for r in self.rules if r.get("source") == "omini_paused"]

    def paused(self):
        a = self.alias("omini_paused")
        return None if a is None else list(zip(a["address"], a["detail"], strict=True))

    def alias(self, name):
        return next((a for a in self.aliases if a["name"] == name), None)


@pytest.fixture
def box(pfsense, monkeypatch):
    b = Box()
    fallback = pfsense.handler

    def handler(request):
        if request.headers.get("x-api-key") != pfsense.key:
            return fallback(request)
        return b.handle(request) or fallback(request)

    collect_module.Client.keywords["transport"] = httpx.MockTransport(handler)
    monkeypatch.setattr(networks_module.time, "sleep", lambda _s: None)
    return b


def records(devices):
    return [(r.name, r.ip) for r in devices[0].dns_records or []]


# --- reads -----------------------------------------------------------------------


def test_reads_names_domain_and_laggs(box, cfg):
    [fw] = collect_module.collect(cfg)
    assert records([fw]) == [("files.home.arpa", "192.168.1.20"), ("nas.home.arpa", "192.168.1.20")]
    assert fw.dns_domain == "home.arpa"
    assert fw.paused is None
    ifaces = {i.name: i for i in fw.interfaces}
    assert ifaces["lagg0"].type == "lag" and ifaces["lagg0"].description == "to the core switch"
    assert (ifaces["igc2"].lag, ifaces["igc3"].lag) == ("lagg0", "lagg0")
    assert ifaces["lagg0"].members == ["igc2", "igc3"]
    assert ifaces["igc2"].type == "ethernet" and ifaces["igc2"].up is None  # nothing invented
    assert ifaces["igc1"].lag is None
    assert box.writes == []


def test_an_assigned_lagg_keeps_its_data(box, pfsense, cfg):
    rows = pfsense.routes["/api/v2/status/interfaces"]["data"]
    rows.append({**rows[1], "name": "opt9", "hwif": "lagg0", "descr": "CORE"})
    [fw] = collect_module.collect(cfg)
    lagg = [i for i in fw.interfaces if i.name == "lagg0"]
    assert len(lagg) == 1 and lagg[0].description == "CORE" and lagg[0].type == "lag"
    assert lagg[0].members == ["igc2", "igc3"]


def test_without_the_new_privileges_the_round_goes_on(box, cfg):
    box.forbidden |= {
        ("GET", "/api/v2/services/dns_resolver/host_overrides"),
        ("GET", "/api/v2/firewall/aliases"),
        ("GET", "/api/v2/interface/laggs"),
    }
    [fw] = collect_module.collect(cfg)
    assert fw.dns_records is None and fw.paused is None
    assert fw.dns_domain == "home.arpa"
    assert not any(i.lag for i in fw.interfaces)


# --- DNS names --------------------------------------------------------------------


def test_creates_a_dns_name(box, cfg):
    devices = collect_module.apply(
        cfg, change("dns.set", {"name": "Printer.home.arpa.", "ip": "192.168.1.30"})
    )
    assert box.overrides[-1] == {
        "aliases": [],
        "host": "printer",
        "domain": "home.arpa",
        "ip": ["192.168.1.30"],
        "descr": "Omini",
    }
    assert box.dns_applied == 1
    assert ("printer.home.arpa", "192.168.1.30") in records(devices)


def test_changes_the_address_of_a_name_set_by_hand(box, cfg):
    devices = collect_module.apply(
        cfg, change("dns.set", {"name": "nas.home.arpa", "ip": "192.168.1.21"})
    )
    assert box.overrides[0]["ip"] == ["192.168.1.21"]
    assert box.overrides[0]["descr"] == "by hand"  # its own description stays
    assert ("nas.home.arpa", "192.168.1.21") in records(devices)
    assert ("files.home.arpa", "192.168.1.21") in records(devices)  # its alias follows


def test_setting_the_same_name_again_changes_nothing(box, cfg):
    collect_module.apply(cfg, change("dns.set", {"name": "nas.home.arpa", "ip": "192.168.1.20"}))
    assert box.writes == []


def test_a_duplicate_name_is_left_once(box, cfg):
    box.overrides.append(
        {"host": "nas", "domain": "home.arpa", "ip": ["192.168.1.99"], "descr": "", "aliases": []}
    )
    devices = collect_module.apply(
        cfg, change("dns.set", {"name": "nas.home.arpa", "ip": "192.168.1.20"})
    )
    assert [o["host"] for o in box.overrides].count("nas") == 1
    assert [ip for n, ip in records(devices) if n == "nas.home.arpa"] == ["192.168.1.20"]


def test_waits_for_the_resolver(box, cfg):
    box.dns_lag = 2
    collect_module.apply(cfg, change("dns.set", {"name": "tv.home.arpa", "ip": "192.168.1.31"}))
    assert box.overrides[-1]["host"] == "tv"


def test_a_name_that_never_shows_fails(box, cfg):
    box.dns_lag = 100
    with pytest.raises(PluginError, match=r"tv\.home\.arpa"):
        collect_module.apply(cfg, change("dns.set", {"name": "tv.home.arpa", "ip": "192.168.1.31"}))


def test_removes_a_dns_name(box, cfg):
    devices = collect_module.apply(cfg, change("dns.delete", {"name": "nas.home.arpa"}))
    assert [o["host"] for o in box.overrides] == ["v6only"]
    assert records(devices) == []
    assert box.dns_applied == 1


def test_removing_a_name_that_is_not_there_changes_nothing(box, cfg):
    collect_module.apply(cfg, change("dns.delete", {"name": "ghost.home.arpa"}))
    assert box.writes == []


def test_an_alias_is_changed_in_pfsense(box, cfg):
    for c in (
        change("dns.set", {"name": "files.home.arpa", "ip": "192.168.1.40"}),
        change("dns.delete", {"name": "files.home.arpa"}),
    ):
        with pytest.raises(PluginError, match=r"alias of the host override nas\.home\.arpa"):
            collect_module.apply(cfg, c)
    assert box.writes == []


@pytest.mark.parametrize(
    "value",
    [
        {"name": "printer", "ip": "192.168.1.30"},
        {"name": "bad name.home.arpa", "ip": "192.168.1.30"},
        {"name": "printer.home.arpa", "ip": "fd00::1"},
        {"name": "printer.home.arpa", "ip": "nope"},
    ],
)
def test_refuses_a_bad_name_or_address(box, cfg, value):
    with pytest.raises(PluginError, match="not a"):
        collect_module.apply(cfg, change("dns.set", value))
    assert box.writes == []


def test_a_missing_dns_privilege_is_named(box, cfg):
    box.forbidden.add(("POST", "/api/v2/services/dns_resolver/host_override"))
    with pytest.raises(PluginError, match="dns_resolver/host_override POST"):
        collect_module.apply(cfg, change("dns.set", {"name": "tv.home.arpa", "ip": "192.168.1.31"}))


# --- Wake-on-LAN ------------------------------------------------------------------


def test_wakes_on_the_network_that_holds_the_address(box, cfg):
    collect_module.apply(cfg, change("wol.send", {"mac": "AA-BB-CC-00-00-07", "ip": "10.0.20.33"}))
    assert box.woken == [{"interface": "opt1", "mac_addr": "aa:bb:cc:00:00:07"}]


def test_wakes_on_the_lan_without_an_address(box, cfg):
    collect_module.apply(cfg, change("wol.send", {"mac": "aa:bb:cc:00:00:07"}))
    assert box.woken == [{"interface": "lan", "mac_addr": "aa:bb:cc:00:00:07"}]


@pytest.mark.parametrize(
    ("value", "msg"),
    [
        ({"mac": "aa:bb:cc:00:00:07", "ip": "10.99.0.5"}, "no network"),
        ({"mac": "aa:bb:cc:00:00:07", "ip": "203.0.113.50"}, "no network"),  # the WAN
        ({"mac": "nope", "ip": "192.168.1.5"}, "not a MAC"),
    ],
)
def test_refuses_to_wake(box, cfg, value, msg):
    with pytest.raises(PluginError, match=msg):
        collect_module.apply(cfg, change("wol.send", value))
    assert box.woken == []


# --- paused devices -----------------------------------------------------------------


def pause(mac="aa:bb:cc:00:00:50", ips=("192.168.1.50",), name="Kid's tablet"):
    return change("pause.set", {"mac": mac, "ips": list(ips), "name": name})


def test_pauses_a_device(box, cfg):
    devices = collect_module.apply(cfg, pause())
    assert box.paused() == [("192.168.1.50", "Omini aa:bb:cc:00:00:50 Kid's tablet")]
    alias = next(a for a in box.aliases if a["name"] == "omini_paused")
    assert alias["type"] == "host"
    # What the device still reaches: private IPv4, IPv6 link-local, ULA,
    # multicast and the LAN's IPv6 network (from the interfaces' status).
    local = box.alias("omini_local")
    assert (local["type"], local["address"]) == (
        "network",
        [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "fe80::/10",
            "fc00::/7",
            "ff00::/8",
            "fd00::/64",
        ],
    )
    rules = box.pause_rules()
    assert sorted(r["interface"][0] for r in rules) == ["lan", "opt1", "opt2"]  # never the WAN
    for r in rules:
        assert (
            r["type"],
            r["ipprotocol"],
            r["destination"],
            r["floating"],
            r["quick"],
            r["direction"],
        ) == ("block", "inet46", "!omini_local", True, True, "in")
        assert r["descr"].startswith("Omini")
    assert "/api/v2/firewall/apply" in box.applied
    assert box.killed == [
        {"source__startswith": "192.168.1.50:", "limit": "0"},
        {"source__contains": "(192.168.1.50:", "limit": "0"},
    ]
    [p] = devices[0].paused
    assert (p.mac, p.ips, p.name) == ("aa:bb:cc:00:00:50", ["192.168.1.50"], "Kid's tablet")
    nets = networks(devices)
    assert nets[1].access == "all"  # the block is no access preset


def test_pausing_again_replaces_the_addresses(box, cfg):
    collect_module.apply(cfg, pause(mac="aa:bb:cc:00:00:60", ips=["192.168.1.60"], name="TV"))
    collect_module.apply(cfg, pause())
    rules = len(box.pause_rules())
    devices = collect_module.apply(cfg, pause(ips=["192.168.1.51", "10.0.20.51", "fd00::51"]))
    assert box.paused() == [
        ("192.168.1.60", "Omini aa:bb:cc:00:00:60 TV"),
        ("192.168.1.51", "Omini aa:bb:cc:00:00:50 Kid's tablet"),
        ("10.0.20.51", "Omini aa:bb:cc:00:00:50 Kid's tablet"),
        ("fd00::51", "Omini aa:bb:cc:00:00:50 Kid's tablet"),  # blocked, not reported
    ]
    assert len(box.pause_rules()) == rules  # one rule per interface, not per device
    assert [(p.mac, p.ips) for p in devices[0].paused] == [
        ("aa:bb:cc:00:00:60", ["192.168.1.60"]),
        ("aa:bb:cc:00:00:50", ["192.168.1.51", "10.0.20.51"]),
    ]


def test_an_address_that_moved_to_another_device(box, cfg):
    collect_module.apply(cfg, pause(mac="aa:bb:cc:00:00:60", ips=["192.168.1.60"], name="TV"))
    collect_module.apply(cfg, pause(ips=["192.168.1.60"]))
    assert box.paused() == [("192.168.1.60", "Omini aa:bb:cc:00:00:50 Kid's tablet")]


def test_a_network_added_later_gets_the_rule(box, cfg):
    collect_module.apply(cfg, pause())
    collect_module.apply(
        cfg,
        change(
            "network.set",
            {
                "vlan": 40,
                "name": "CAMERAS",
                "gateway": "10.0.40.1/24",
                "dhcp": {"enabled": True, "from": "10.0.40.100", "to": "10.0.40.200"},
                "access": "internet",
            },
        ),
    )
    assert "opt3" not in {r["interface"][0] for r in box.pause_rules()}
    devices = collect_module.apply(cfg, pause())
    assert "opt3" in {r["interface"][0] for r in box.pause_rules()}
    assert networks(devices)[40].access == "internet"


def test_changing_a_networks_access_keeps_the_block(box, cfg):
    collect_module.apply(cfg, pause())
    devices = collect_module.apply(
        cfg,
        change(
            "network.set",
            {
                "vlan": 20,
                "name": "IOT",
                "gateway": "10.0.20.1/24",
                "dhcp": {"enabled": True, "from": "10.0.20.2", "to": "10.0.20.50"},
                "access": "local",
            },
        ),
    )
    assert "opt1" in {r["interface"][0] for r in box.pause_rules()}
    assert networks(devices)[20].access == "local"


def test_resumes_a_device(box, cfg):
    collect_module.apply(cfg, pause(mac="aa:bb:cc:00:00:60", ips=["192.168.1.60"], name="TV"))
    collect_module.apply(cfg, pause())
    devices = collect_module.apply(cfg, change("pause.delete", {"mac": "aa:bb:cc:00:00:60"}))
    assert box.paused() == [("192.168.1.50", "Omini aa:bb:cc:00:00:50 Kid's tablet")]
    assert len(box.pause_rules()) == 3
    assert [p.mac for p in devices[0].paused] == ["aa:bb:cc:00:00:50"]

    devices = collect_module.apply(cfg, change("pause.delete", {"mac": "aa:bb:cc:00:00:50"}))
    assert box.paused() is None  # the aliases go with the last device
    assert box.alias("omini_local") is None
    assert box.pause_rules() == []
    assert devices[0].paused is None
    assert networks(devices)[1].access == "all"


NDP = """Neighbor                             Linklayer Address  Netif Expire    1s 5s
fe80::1:2%igc1                       aa:bb:cc:00:00:50   igc1 23h59m58s S
2804:1128:bd7c:8800:1c2b:3d4e:5f60:7181 aa:bb:cc:00:00:50 igc1 23h59m58s S
2804:1128:bd7c:8800::60              aa:bb:cc:00:00:60   igc1 23h59m50s S
2804:1128:bd7c:8800::1               90:ec:77:aa:bb:02   igc1 permanent R
fd00::99                             (incomplete)        igc1 expired   N
"""


def test_the_ndp_table_adds_the_devices_ipv6_addresses(box, cfg):
    """A phone with a temporary IPv6 address: the NDP table says it is the
    MAC's, so it goes in the alias with the IPv4 address Omini sent."""
    box.ndp = NDP
    collect_module.apply(cfg, pause(mac="aa:bb:cc:00:00:60", ips=["192.168.1.60"], name="TV"))
    devices = collect_module.apply(cfg, pause())
    assert box.commands[-1] == "/usr/sbin/ndp -an"
    assert box.paused() == [
        ("192.168.1.60", "Omini aa:bb:cc:00:00:60 TV"),
        ("2804:1128:bd7c:8800::60", "Omini aa:bb:cc:00:00:60 TV"),
        ("192.168.1.50", "Omini aa:bb:cc:00:00:50 Kid's tablet"),
        ("2804:1128:bd7c:8800:1c2b:3d4e:5f60:7181", "Omini aa:bb:cc:00:00:50 Kid's tablet"),
    ]
    # Reported as Omini sent it: the IPv4 address only.
    assert [(p.mac, p.ips) for p in devices[0].paused] == [
        ("aa:bb:cc:00:00:60", ["192.168.1.60"]),
        ("aa:bb:cc:00:00:50", ["192.168.1.50"]),
    ]
    # A new temporary address: the next pause.set (any device's) refreshes them all.
    box.ndp = NDP.replace("::60 ", "::61 ").replace("7181", "7182")
    collect_module.apply(cfg, pause())
    assert [a for a, _ in box.paused()] == [
        "192.168.1.60",
        "2804:1128:bd7c:8800::61",
        "192.168.1.50",
        "2804:1128:bd7c:8800:1c2b:3d4e:5f60:7182",
    ]
    # The router's own IPv6 network stays reachable: it is in omini_local.
    status = [{"name": "lan", "ipaddrv6": "2804:1128:bd7c:8800::1", "subnetv6": "64"}]
    box.status_interfaces = status
    collect_module.apply(cfg, pause())
    assert "2804:1128:bd7c:8800::/64" in box.alias("omini_local")["address"]
    # Resuming takes the IPv6 entries out with the IPv4 one.
    collect_module.apply(cfg, change("pause.delete", {"mac": "aa:bb:cc:00:00:50"}))
    assert {d for _, d in box.paused()} == {"Omini aa:bb:cc:00:00:60 TV"}


def test_without_the_ndp_table_the_ipv6_entries_stay(box, cfg):
    """No command prompt privilege: IPv4 is paused; IPv6 entries already in
    the alias are kept, since nothing says they changed."""
    box.ndp = NDP
    collect_module.apply(cfg, pause(mac="aa:bb:cc:00:00:60", ips=["192.168.1.60"], name="TV"))
    box.ndp = None
    box.forbidden.add(("POST", "/api/v2/diagnostics/command_prompt"))
    devices = collect_module.apply(cfg, pause())
    assert box.paused() == [
        ("192.168.1.60", "Omini aa:bb:cc:00:00:60 TV"),
        ("2804:1128:bd7c:8800::60", "Omini aa:bb:cc:00:00:60 TV"),
        ("192.168.1.50", "Omini aa:bb:cc:00:00:50 Kid's tablet"),
    ]
    assert [p.mac for p in devices[0].paused] == ["aa:bb:cc:00:00:60", "aa:bb:cc:00:00:50"]


def old_pause(box):
    """A pause made by 0.2.0: IPv4 rules to anything not omini_private."""
    box.aliases.append(
        {
            "name": "omini_private",
            "type": "network",
            "address": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
            "detail": ["Omini"] * 3,
        }
    )
    box.aliases.append(
        {
            "name": "omini_paused",
            "type": "host",
            "address": ["192.168.1.60"],
            "detail": ["Omini aa:bb:cc:00:00:60 TV"],
        }
    )
    for ifname in ("lan", "opt1", "opt2"):
        box.rules.append(
            {
                "type": "block",
                "interface": [ifname],
                "ipprotocol": "inet",
                "source": "omini_paused",
                "destination": "!omini_private",
                "floating": True,
                "quick": True,
                "direction": "in",
            }
        )


def test_an_older_pause_moves_to_ipv4_and_ipv6_rules(box, cfg):
    old_pause(box)
    devices = collect_module.apply(cfg, pause())
    rules = box.pause_rules()
    assert sorted(r["interface"][0] for r in rules) == ["lan", "opt1", "opt2"]
    assert {(r["ipprotocol"], r["destination"]) for r in rules} == {("inet46", "!omini_local")}
    assert {p.mac for p in devices[0].paused} == {"aa:bb:cc:00:00:60", "aa:bb:cc:00:00:50"}


def test_an_older_pause_still_resumes(box, cfg):
    old_pause(box)
    devices = collect_module.apply(cfg, change("pause.delete", {"mac": "aa:bb:cc:00:00:60"}))
    assert devices[0].paused is None
    assert box.pause_rules() == [] and box.paused() is None
    assert box.alias("omini_private") is not None  # the networks' access uses it


def test_resuming_a_device_that_is_not_paused_changes_nothing(box, cfg):
    collect_module.apply(cfg, change("pause.delete", {"mac": "aa:bb:cc:00:00:99"}))
    assert box.writes == []


def test_entries_added_by_hand_are_kept(box, cfg):
    collect_module.apply(cfg, pause())
    alias = next(a for a in box.aliases if a["name"] == "omini_paused")
    alias["address"].append("192.168.1.77")
    alias["detail"].append("added by hand")
    devices = collect_module.apply(cfg, change("pause.delete", {"mac": "aa:bb:cc:00:00:50"}))
    assert box.paused() == [("192.168.1.77", "added by hand")]
    assert len(box.pause_rules()) == 3  # the list is not empty
    assert devices[0].paused is None  # no MAC of Omini's


@pytest.mark.parametrize(
    ("value", "msg"),
    [
        ({"mac": "aa:bb:cc:00:00:50", "ips": ["192.168.1.1"]}, "pfSense's own address"),
        ({"mac": "aa:bb:cc:00:00:50", "ips": []}, "no IPv4 address"),
        ({"mac": "aa:bb:cc:00:00:50", "ips": ["fd00::50"]}, "no IPv4 address"),
        ({"mac": "x", "ips": ["192.168.1.50"]}, "not a MAC"),
    ],
)
def test_refuses_to_pause(box, cfg, value, msg):
    with pytest.raises(PluginError, match=msg):
        collect_module.apply(cfg, change("pause.set", value))
    assert box.writes == []


def test_pausing_needs_the_rules(box, cfg):
    box.forbidden.add(("GET", "/api/v2/firewall/rules"))
    with pytest.raises(PluginError, match=r"firewall/rules GET"):
        collect_module.apply(cfg, pause())
    assert box.writes == []


def test_cutting_connections_is_best_effort(box, cfg):
    box.forbidden.add(("DELETE", "/api/v2/firewall/states"))
    devices = collect_module.apply(cfg, pause())
    assert [p.mac for p in devices[0].paused] == ["aa:bb:cc:00:00:50"]


def test_a_pause_that_does_not_take_fails(box, cfg):
    box.drop_rules = True
    with pytest.raises(PluginError, match="the pause"):
        collect_module.apply(cfg, pause())


def test_removing_a_network_removes_its_block(box, cfg):
    collect_module.apply(cfg, pause())
    collect_module.apply(cfg, change("network.delete", {"vlan": 20}))
    assert "opt1" not in box.interfaces
    assert {r["interface"][0] for r in box.pause_rules()} == {"lan", "opt2"}


def test_waking_without_the_interfaces_privilege_names_it(box, pfsense, cfg):
    pfsense.forbidden.add("/api/v2/status/interfaces")
    with pytest.raises(PluginError, match=r"REST API - /api/v2/status/interfaces GET"):
        collect_module.apply(cfg, change("wol.send", {"mac": "aa:bb:cc:00:00:07"}))
    assert box.woken == []
