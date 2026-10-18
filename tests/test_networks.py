import copy
import json

import httpx
import pytest
from omini_sdk import Change, PluginError

import omini_pfsense.collect as collect_module
import omini_pfsense.networks as networks_module
from tests.conftest import error


def ok(data):
    return httpx.Response(
        200,
        json={"code": 200, "status": "ok", "response_id": "SUCCESS", "message": "", "data": data},
    )


class Router:
    """The parts of pfSense's configuration that hold a network, with their
    state, answered like the REST API package v2: interfaces, VLANs, DHCP
    servers with their static mappings, firewall rules and aliases. Ids of
    VLANs, rules and mappings are positions in their lists, as in the package."""

    def __init__(self):
        self.interfaces = {
            "wan": {
                "if": "igc0",
                "descr": "WAN",
                "enable": True,
                "typev4": "static",
                "ipaddr": "203.0.113.10",
                "subnet": 24,
                "gateway": "WANGW",
            },
            "lan": {
                "if": "igc1",
                "descr": "LAN",
                "enable": True,
                "typev4": "static",
                "ipaddr": "192.168.1.1",
                "subnet": 24,
            },
            "opt1": {
                "if": "igc1.20",
                "descr": "IOT",
                "enable": True,
                "typev4": "static",
                "ipaddr": "10.0.20.1",
                "subnet": 24,
            },
            "opt2": {
                "if": "ix0",
                "descr": "DMZ",
                "enable": True,
                "typev4": "static",
                "ipaddr": "172.16.0.1",
                "subnet": 24,
            },
        }
        self.vlans = [
            {"if": "igc1", "tag": 20, "vlanif": "igc1.20", "descr": "IoT devices"},
            {"if": "igc1", "tag": 30, "vlanif": "igc1.30", "descr": ""},
        ]
        self.dhcp = {
            "lan": {
                "enable": True,
                "range_from": "192.168.1.100",
                "range_to": "192.168.1.199",
                "dnsserver": [],
                "staticmap": [
                    {"mac": "aa:bb:cc:dd:ee:12", "ipaddr": "192.168.1.20", "hostname": "nas"}
                ],
            },
            "opt1": {
                "enable": True,
                "range_from": "10.0.20.2",
                "range_to": "10.0.20.50",
                "dnsserver": [],
                "staticmap": [],
            },
        }
        self.rules = [
            {
                "type": "pass",
                "interface": ["lan"],
                "ipprotocol": "inet",
                "source": "lan",
                "destination": "any",
                "descr": "Default allow LAN to any rule",
            },
            {
                "type": "pass",
                "interface": ["lan"],
                "ipprotocol": "inet6",
                "source": "lan",
                "destination": "any",
                "descr": "Default allow LAN IPv6 to any rule",
            },
            {
                "type": "pass",
                "interface": ["opt1"],
                "ipprotocol": "inet",
                "source": "opt1",
                "destination": "192.168.1.20",
                "descr": "IoT to the NAS",
            },
        ]
        self.aliases = []
        self.writes = []  # (method, path)
        self.applied = []
        self.forbidden = set()  # (method, path)
        self.refuse = {}  # (method, path) → message (400)
        self.drop_rules = False  # accepts new rules but keeps none of them
        self.interfaces_api = True

    # -- answers --
    def handle(self, request):
        method, path = request.method, request.url.path
        q = dict(request.url.params)
        body = json.loads(request.content) if request.content else {}
        if path == "/api/v2/interfaces" and not self.interfaces_api:
            return error(404, "not found", "ENDPOINT_NOT_FOUND", "Endpoint not found")
        if (method, path) in self.forbidden:
            return error(403, "forbidden", "AUTH_INSUFFICIENT_PRIVILEGES", "Not authorized")
        if (method, path) in self.refuse:
            return error(400, "bad request", "FIELD_INVALID", self.refuse[(method, path)])
        if method == "GET":
            return self.get(path)
        self.writes.append((method, path))
        return self.write(method, path, q, body)

    def get(self, path):
        if path == "/api/v2/interfaces":
            return ok([{"id": k, **copy.deepcopy(v)} for k, v in self.interfaces.items()])
        if path == "/api/v2/interface/vlans":
            return ok([{"id": i, **v} for i, v in enumerate(self.vlans)])
        if path == "/api/v2/services/dhcp_servers":
            return ok([self.server(k) for k in self.dhcp])
        if path == "/api/v2/firewall/rules":
            return ok([{"id": i, **copy.deepcopy(r)} for i, r in enumerate(self.rules)])
        if path == "/api/v2/firewall/aliases":
            return ok([{"id": i, **a} for i, a in enumerate(self.aliases)])
        return None

    def server(self, ifname):
        s = copy.deepcopy(self.dhcp[ifname])
        s["staticmap"] = [{"parent_id": ifname, "id": i, **m} for i, m in enumerate(s["staticmap"])]
        return {"id": ifname, "interface": ifname, **s}

    def write(self, method, path, q, body):
        if path.endswith("/apply"):
            self.applied.append(path)
            return ok({"applied": True})
        if (method, path) == ("POST", "/api/v2/interface/vlan"):
            if any(v["if"] == body["if"] and v["tag"] == body["tag"] for v in self.vlans):
                return error(400, "bad request", "VLAN_TAG_EXISTS", "Field `tag` must be unique")
            self.vlans.append({**body, "vlanif": f"{body['if']}.{body['tag']}"})
            return ok({"id": len(self.vlans) - 1, **self.vlans[-1]})
        if (method, path) == ("DELETE", "/api/v2/interface/vlan"):
            v = self.vlans[int(q["id"])]
            if any(i["if"] == v["vlanif"] for i in self.interfaces.values()):
                return error(409, "conflict", "VLAN_IN_USE", "VLAN is in use by an interface")
            del self.vlans[int(q["id"])]
            return ok(v)
        if (method, path) == ("POST", "/api/v2/interface"):
            n = 1 + max(int(k[3:]) for k in self.interfaces if k.startswith("opt"))
            self.interfaces[f"opt{n}"] = body
            return ok({"id": f"opt{n}", **body})
        if (method, path) == ("PATCH", "/api/v2/interface"):
            self.interfaces[body["id"]].update({k: v for k, v in body.items() if k != "id"})
            return ok(body)
        if (method, path) == ("DELETE", "/api/v2/interface"):
            name = q["id"]
            if self.dhcp.get(name, {}).get("enable") or any(
                name in r["interface"] for r in self.rules
            ):
                return error(409, "conflict", "INTERFACE_IN_USE", "Interface is in use")
            return ok(self.interfaces.pop(name))
        if (method, path) == ("POST", "/api/v2/services/dhcp_server"):
            name = body.pop("interface")
            self.dhcp[name] = {"dnsserver": [], "staticmap": [], **body}
            return ok(self.server(name))
        if (method, path) == ("PATCH", "/api/v2/services/dhcp_server"):
            self.dhcp[body["id"]].update({k: v for k, v in body.items() if k != "id"})
            return ok(self.server(body["id"]))
        if (method, path) == ("DELETE", "/api/v2/services/dhcp_server"):
            return ok(self.dhcp.pop(q["id"]))
        if path == "/api/v2/services/dhcp_server/static_mapping":
            maps = self.dhcp[str(body.get("parent_id") or q.get("parent_id"))]["staticmap"]
            if method == "POST":
                maps.append({k: v for k, v in body.items() if k != "parent_id"})
            elif method == "PATCH":
                maps[body["id"]].update(
                    {k: v for k, v in body.items() if k not in ("parent_id", "id")}
                )
            else:
                del maps[int(q["id"])]
            return ok({})
        if (method, path) == ("POST", "/api/v2/firewall/rule"):
            if not self.drop_rules:
                self.rules.append(body)
            return ok(body)
        if (method, path) == ("DELETE", "/api/v2/firewall/rule"):
            return ok(self.rules.pop(int(q["id"])))
        if (method, path) == ("POST", "/api/v2/firewall/alias"):
            self.aliases.append(body)
            return ok(body)
        return error(404, "not found", "ENDPOINT_NOT_FOUND", "Endpoint not found")

    def on(self, ifname):
        return [r for r in self.rules if ifname in r["interface"]]


@pytest.fixture
def router(pfsense, monkeypatch):
    r = Router()
    fallback = pfsense.handler

    def handler(request):
        if request.headers.get("x-api-key") != pfsense.key:
            return fallback(request)
        return r.handle(request) or fallback(request)

    collect_module.Client.keywords["transport"] = httpx.MockTransport(handler)
    monkeypatch.setattr(networks_module.time, "sleep", lambda _s: None)
    return r


def change(kind, value):
    return Change(device="x", kind=kind, value=value)


def networks(devices):
    return {n.vlan: n for n in devices[0].networks or []}


def cameras(**extra):
    return {
        "vlan": 40,
        "name": "CAMERAS",
        "gateway": "10.0.40.1/24",
        "dhcp": {"enabled": True, "from": "10.0.40.100", "to": "10.0.40.200"},
        "access": "internet",
        **extra,
    }


def test_reads_the_networks(router, cfg):
    [fw] = collect_module.collect(cfg)
    nets = networks([fw])
    assert sorted(nets) == [1, 20]  # the DMZ is no VLAN; the WAN is never one
    lan, iot = nets[1], nets[20]
    assert (lan.interface, lan.device, lan.gateway, lan.access) == (
        "lan",
        "igc1",
        "192.168.1.1/24",
        "all",  # pfSense's default rules, IPv4 and IPv6
    )
    assert (lan.dhcp.enabled, lan.dhcp.from_, lan.dhcp.to) == (
        True,
        "192.168.1.100",
        "192.168.1.199",
    )
    assert lan.dhcp.reserve_in_range is False  # pfSense keeps static mappings out of it
    assert (iot.interface, iot.device, iot.parent, iot.name) == ("opt1", "igc1.20", "igc1", "IOT")
    assert iot.access == "custom"  # a rule Omini does not know: left as it is
    assert lan.mdns is None  # Avahi is not in the API
    assert [(r.mac, r.ip, r.name) for r in fw.dhcp_reservations] == [
        ("aa:bb:cc:dd:ee:12", "192.168.1.20", "nas")
    ]
    assert {m for m, _ in router.writes} == set()  # a round only reads


def test_creates_a_network(router, cfg):
    devices = collect_module.apply(cfg, change("network.set", cameras()))
    assert router.vlans[-1] == {
        "if": "igc1",
        "tag": 40,
        "descr": "Omini: CAMERAS",
        "vlanif": "igc1.40",
    }
    assigned = router.interfaces["opt3"]
    assert (assigned["if"], assigned["ipaddr"], assigned["subnet"], assigned["typev4"]) == (
        "igc1.40",
        "10.0.40.1",
        24,
        "static",
    )
    assert assigned["descr"] == "CAMERAS" and assigned["enable"] is True
    server = router.dhcp["opt3"]
    assert (server["enable"], server["range_from"], server["range_to"]) == (
        True,
        "10.0.40.100",
        "10.0.40.200",
    )
    assert server["dnsserver"] == ["10.0.40.1"]  # its gateway answers DNS
    shapes = [(r["type"], r["destination"], r.get("destination_port")) for r in router.on("opt3")]
    assert shapes == [
        ("pass", "opt3:ip", "53"),
        ("block", "omini_private", None),
        ("pass", "any", None),
    ]
    assert all(r["descr"].startswith("Omini: CAMERAS") for r in router.on("opt3"))
    [alias] = router.aliases
    assert alias["name"] == "omini_private"
    assert alias["address"] == ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    assert router.applied == [
        "/api/v2/interface/apply",
        "/api/v2/services/dhcp_server/apply",
        "/api/v2/firewall/apply",
    ]
    got = networks(devices)[40]
    assert (got.interface, got.gateway, got.access, got.dhcp.from_) == (
        "opt3",
        "10.0.40.1/24",
        "internet",
        "10.0.40.100",
    )


def test_uses_a_vlan_that_is_already_there(router, cfg):
    collect_module.apply(
        cfg,
        change("network.set", cameras(vlan=30, gateway="10.0.30.1/24", dhcp={"enabled": False})),
    )
    assert ("POST", "/api/v2/interface/vlan") not in router.writes
    assert router.interfaces["opt3"]["if"] == "igc1.30"
    assert "opt3" not in router.dhcp


def test_changes_a_network_in_place(router, cfg):
    collect_module.apply(cfg, change("network.set", cameras()))
    router.writes.clear()
    devices = collect_module.apply(
        cfg,
        change(
            "network.set",
            cameras(access="all", dhcp={"enabled": True, "from": "10.0.40.50", "to": "10.0.40.99"}),
        ),
    )
    assert [r["destination"] for r in router.on("opt3")] == ["any"]
    assert (router.dhcp["opt3"]["range_from"], router.dhcp["opt3"]["range_to"]) == (
        "10.0.40.50",
        "10.0.40.99",
    )
    assert ("POST", "/api/v2/interface/vlan") not in router.writes
    assert ("POST", "/api/v2/interface") not in router.writes
    assert ("PATCH", "/api/v2/services/dhcp_server") in router.writes
    assert networks(devices)[40].access == "all"
    # DHCP off: the server stays, turned off.
    collect_module.apply(cfg, change("network.set", cameras(access="all", dhcp={"enabled": False})))
    assert router.dhcp["opt3"]["enable"] is False


def test_custom_access_keeps_the_rules(router, cfg):
    value = {"vlan": 20, "gateway": "10.0.20.1/24", "dhcp": {"enabled": False}, "access": "custom"}
    collect_module.apply(cfg, change("network.set", value))
    assert [r["destination"] for r in router.on("opt1")] == ["192.168.1.20"]
    assert router.dhcp["opt1"]["enable"] is False


def test_the_lan_already_as_asked_is_not_touched(router, cfg):
    lan = {
        "vlan": 1,
        "name": "LAN",
        "gateway": "192.168.1.1/24",
        "dhcp": {"enabled": True, "from": "192.168.1.100", "to": "192.168.1.199"},
        "access": "all",
    }
    collect_module.apply(cfg, change("network.set", lan))
    assert router.writes == []


def test_never_moves_the_address_omini_reaches_pfsense_at(router, cfg):
    lan = {"vlan": 1, "gateway": "192.168.2.1/24", "dhcp": {"enabled": False}, "access": "all"}
    with pytest.raises(PluginError, match=r"192\.168\.1\.1 is the address Omini reaches"):
        collect_module.apply(cfg, change("network.set", lan))
    assert router.writes == []


def test_deletes_a_network(router, cfg):
    collect_module.apply(cfg, change("network.set", cameras()))
    devices = collect_module.apply(cfg, change("network.delete", {"vlan": 40}))
    assert 40 not in networks(devices)
    assert "opt3" not in router.interfaces and "opt3" not in router.dhcp
    assert not router.on("opt3")
    assert not any(v["tag"] == 40 for v in router.vlans)
    # The other rules and VLANs are still there.
    assert len(router.rules) == 3 and [v["tag"] for v in router.vlans] == [20, 30]
    with pytest.raises(PluginError, match="LAN"):
        collect_module.apply(cfg, change("network.delete", {"vlan": 1}))
    with pytest.raises(PluginError, match="no network on VLAN 99"):
        collect_module.apply(cfg, change("network.delete", {"vlan": 99}))


def test_removes_rules_from_the_last(router, cfg):
    collect_module.apply(cfg, change("network.set", cameras()))
    router.rules.insert(
        0, {"type": "pass", "interface": ["opt3"], "source": "opt3", "destination": "1.1.1.1"}
    )
    collect_module.apply(cfg, change("network.set", cameras(access="local")))
    assert [(r["destination"]) for r in router.on("opt3")] == ["opt3:ip"]
    assert len(router.on("lan")) == 2 and len(router.on("opt1")) == 1


def test_a_network_that_does_not_come_out_as_asked_is_removed(router, cfg):
    router.drop_rules = True
    with pytest.raises(PluginError, match="did not apply the network"):
        collect_module.apply(cfg, change("network.set", cameras()))
    assert "opt3" not in router.interfaces and "opt3" not in router.dhcp
    assert [v["tag"] for v in router.vlans] == [20, 30]
    # A VLAN that was there before is kept.
    with pytest.raises(PluginError):
        collect_module.apply(cfg, change("network.set", cameras(vlan=30, gateway="10.0.30.1/24")))
    assert [v["tag"] for v in router.vlans] == [20, 30]
    assert "opt3" not in router.interfaces


def test_refusals_are_shown(router, cfg):
    router.refuse[("POST", "/api/v2/interface")] = "Field `ipaddr` overlaps with interface `lan`."
    with pytest.raises(PluginError, match="overlaps with interface `lan`"):
        collect_module.apply(cfg, change("network.set", cameras()))
    assert [v["tag"] for v in router.vlans] == [20, 30]  # the new VLAN was removed again


def test_missing_write_privilege_is_named(router, cfg):
    router.forbidden.add(("POST", "/api/v2/interface/vlan"))
    with pytest.raises(PluginError, match=r"REST API - /api/v2/interface/vlan POST"):
        collect_module.apply(cfg, change("network.set", cameras()))


def test_needs_the_interfaces_endpoint(router, cfg):
    router.interfaces_api = False
    [fw] = collect_module.collect(cfg)
    assert not fw.networks and not fw.dhcp_reservations
    with pytest.raises(PluginError, match=r"REST API - /api/v2/interfaces GET"):
        collect_module.apply(cfg, change("network.set", cameras()))


def test_a_vlan_rides_on_a_port(router, cfg):
    with pytest.raises(PluginError, match="physical port"):
        collect_module.apply(cfg, change("network.set", cameras(parent="bridge0")))
    assert router.writes == []


def test_discovery_between_networks_is_refused(router, cfg):
    with pytest.raises(PluginError, match="Avahi"):
        collect_module.apply(cfg, change("network.set", cameras(mdns=True)))
    assert router.writes == []
    collect_module.apply(cfg, change("network.set", cameras(mdns=False)))  # off: nothing to do
    assert "opt3" in router.interfaces


def test_other_changes_are_refused(router, cfg):
    with pytest.raises(PluginError, match=r"cannot apply port\.vlans"):
        collect_module.apply(
            cfg, Change(device="x", kind="port.vlans", port="igc1", value={"untagged": 1})
        )


def test_fixes_and_frees_an_address(router, cfg):
    value = {"mac": "AA-BB-CC-00-00-01", "ip": "192.168.1.50", "name": "Living room TV"}
    devices = collect_module.apply(cfg, change("reservation.set", value))
    assert router.dhcp["lan"]["staticmap"][-1] == {
        "mac": "aa:bb:cc:00:00:01",
        "ipaddr": "192.168.1.50",
        "hostname": "living-room-tv",
        "descr": "Omini",
    }
    assert ("aa:bb:cc:00:00:01", "192.168.1.50") in [
        (r.mac, r.ip) for r in devices[0].dhcp_reservations
    ]
    # Again with an address in another network: moves to that network's server.
    collect_module.apply(cfg, change("reservation.set", {**value, "ip": "10.0.20.60"}))
    assert [m["mac"] for m in router.dhcp["lan"]["staticmap"]] == ["aa:bb:cc:dd:ee:12"]
    assert [m["ipaddr"] for m in router.dhcp["opt1"]["staticmap"]] == ["10.0.20.60"]
    # And within it: the same mapping changes.
    collect_module.apply(cfg, change("reservation.set", {**value, "ip": "10.0.20.61"}))
    assert [m["ipaddr"] for m in router.dhcp["opt1"]["staticmap"]] == ["10.0.20.61"]
    devices = collect_module.apply(cfg, change("reservation.delete", {"mac": "aa:bb:cc:00:00:01"}))
    assert not router.dhcp["opt1"]["staticmap"]
    assert [r.mac for r in devices[0].dhcp_reservations] == ["aa:bb:cc:dd:ee:12"]


def test_a_reservation_stays_out_of_the_dhcp_range(router, cfg):
    with pytest.raises(PluginError, match="outside it"):
        collect_module.apply(
            cfg, change("reservation.set", {"mac": "aa:bb:cc:00:00:01", "ip": "192.168.1.150"})
        )
    assert router.writes == []


def test_a_reservation_needs_dhcp_in_its_network(router, cfg):
    with pytest.raises(PluginError, match="DHCP"):
        collect_module.apply(
            cfg, change("reservation.set", {"mac": "aa:bb:cc:00:00:01", "ip": "172.16.0.50"})
        )
    assert router.writes == []


def test_a_read_the_change_needs_names_its_privilege(router, cfg):
    router.forbidden.add(("GET", "/api/v2/firewall/aliases"))
    with pytest.raises(PluginError, match=r"REST API - /api/v2/firewall/aliases GET"):
        collect_module.apply(cfg, change("network.set", cameras()))
    assert "opt3" not in router.interfaces  # what it created is removed again
    router.forbidden = {("GET", "/api/v2/interface/vlans")}
    with pytest.raises(PluginError, match=r"REST API - /api/v2/interface/vlans GET"):
        collect_module.apply(cfg, change("network.set", cameras(access="all")))


SHARED = [
    {"type": "pass", "interface": ["opt1", "lan"], "source": "any", "destination": "1.1.1.1"},
    {
        "type": "pass",
        "interface": ["opt1"],
        "floating": True,
        "source": "any",
        "destination": "any",
    },
]
IOT = {"vlan": 20, "gateway": "10.0.20.1/24", "dhcp": {"enabled": False}}


def test_rules_shared_with_other_interfaces_are_never_removed(router, cfg):
    router.rules += copy.deepcopy(SHARED)
    with pytest.raises(PluginError, match="change them in pfSense first"):
        collect_module.apply(cfg, change("network.set", {**IOT, "access": "all"}))
    assert ("DELETE", "/api/v2/firewall/rule") not in router.writes
    # Removing the network leaves them (pfSense then refuses to drop the interface).
    with pytest.raises(PluginError, match="in use"):
        collect_module.apply(cfg, change("network.delete", {"vlan": 20}))
    assert all(r in router.rules for r in SHARED)
    assert not [r for r in router.rules if r["interface"] == ["opt1"] and not r.get("floating")]


def test_a_new_access_keeps_the_disabled_rules(router, cfg):
    off = {"type": "block", "interface": ["opt1"], "source": "opt1", "destination": "any"}
    router.rules.append({**off, "disabled": True})
    collect_module.apply(cfg, change("network.set", {**IOT, "access": "all"}))
    assert {**off, "disabled": True} in router.rules
    assert [r["destination"] for r in router.on("opt1") if not r.get("disabled")] == ["any"]


def test_a_vlan_tag_given_as_a_string_counts(router, cfg):
    for v in router.vlans:
        v["tag"] = str(v["tag"])
    [fw] = collect_module.collect(cfg)
    assert 20 in networks([fw])
    assert 20 in [v.id for v in fw.vlans]
    collect_module.apply(cfg, change("network.set", cameras(vlan=30, gateway="10.0.30.1/24")))
    assert [v["tag"] for v in router.vlans] == ["20", "30"]  # the VLAN there is used
    collect_module.apply(cfg, change("network.set", cameras()))
