import httpx
import pytest
from omini_sdk import Config, PluginError

from omini_pfsense.collect import (
    collect,
    mac,
    os_version,
    speed_from_media,
    uptime_seconds,
)
from omini_pfsense.collect import test as connection_test


def test_reads_the_firewall(pfsense, cfg):
    [fw] = collect(cfg)
    assert fw.name == "pfsense.home.arpa"
    assert fw.key == "90:ec:77:aa:bb:02"  # LAN MAC
    assert (fw.role, fw.vendor, fw.model) == ("firewall", "pfSense", "Netgate 4200")
    assert fw.os_version == "pfSense Plus 24.03-p1"
    assert fw.firmware.current == "pfSense Plus 24.03-p1"
    assert fw.firmware.update_available is None  # the API does not expose it: never guessed
    assert fw.host == "192.168.1.1" and fw.serial == "2213220123"
    assert fw.uptime_s == ((3 * 24 + 4) * 60 + 12) * 60 + 9
    assert (fw.cpu_pct, fw.mem_pct, fw.swap_pct) == (5.2, 23, 0)
    assert fw.cpu_count == 4
    assert fw.load_avg == [0.21, 0.18, 0.15]
    assert [(t.sensor, t.kind, t.celsius) for t in fw.temperatures] == [("CPU", "cpu", 48.5)]
    assert fw.storage is None  # only a percentage is reported, no sizes
    assert fw.ips == ["10.0.20.1", "10.6.0.1", "172.16.0.1", "192.168.1.1", "203.0.113.10"]
    assert (fw.firewall_states.current, fw.firewall_states.limit) == (1234, 1622000)


def test_ports_with_speed_connector_and_traffic(pfsense, cfg):
    [fw] = collect(cfg)
    ports = {i.name: i for i in fw.interfaces}
    assert list(ports) == ["igc0", "igc1", "igc1.20", "ix0", "ix1", "tun_wg0"]
    wan = ports["igc0"]
    assert (wan.description, wan.up, wan.speed_mbps, wan.duplex, wan.connector) == (
        "WAN",
        True,
        1000,
        "full",
        "rj45",
    )
    assert wan.wan is True and wan.rx_bytes == 98765432100 and wan.tx_bytes == 12345678900
    assert wan.ips == ["203.0.113.10/24"]
    lan = ports["igc1"]
    assert lan.speed_mbps == 2500 and lan.rx_errors == 2 and lan.wan is None
    assert lan.ips == ["192.168.1.1/24", "fd00::1/64"]
    iot = ports["igc1.20"]
    assert (iot.type, iot.parent, iot.vlan, iot.speed_mbps) == ("vlan", "igc1", 20, 2500)
    assert iot.connector is None and iot.tx_errors == 1
    dmz = ports["ix0"]
    assert (dmz.speed_mbps, dmz.connector) == (10000, "sfp")
    down = ports["ix1"]
    assert (down.up, down.speed_mbps, down.connector, down.wan) == (False, None, None, None)
    assert wan.enabled is True
    wg = ports["tun_wg0"]
    assert (wg.type, wg.mac, wg.speed_mbps) == ("tunnel", None, None)


def test_default_wan_counts_even_when_down(pfsense, cfg):
    wan = pfsense.routes["/api/v2/status/interfaces"]["data"][0]
    wan.update(status="no carrier", media="", gateway=None, ipaddr="")
    [fw] = collect(cfg)
    port = next(i for i in fw.interfaces if i.name == "igc0")
    assert port.wan is True and port.up is False and port.speed_mbps is None


def test_gateways(pfsense, cfg):
    [fw] = collect(cfg)
    gw = {g.name: g for g in fw.gateways}
    wan = gw["WAN_DHCP"]
    assert (wan.status, wan.rtt_ms, wan.loss_pct) == ("up", 1.234, 0)
    assert (wan.interface, wan.address) == ("igc0", "203.0.113.1")
    down = gw["WAN2_DHCP"]
    assert (down.status, down.interface, down.rtt_ms, down.loss_pct) == ("down", None, None, 100)
    lan = gw["LAN_ROUTER"]
    assert (lan.status, lan.interface, lan.address) == ("degraded", "igc1", None)


def test_arp_and_leases(pfsense, cfg):
    [fw] = collect(cfg)
    # vendor suffix stripped, MAC lowercased, firewall's own (permanent) and incomplete left out,
    # interface descriptions turned into port names
    assert [(a.ip, a.mac, a.interface) for a in fw.arp] == [
        ("192.168.1.50", "aa:bb:cc:dd:ee:01", "igc1"),
        ("10.0.20.7", "aa:bb:cc:dd:ee:07", "igc1.20"),
    ]
    assert [(lease.ip, lease.mac, lease.hostname) for lease in fw.dhcp_leases] == [
        ("10.0.20.7", "aa:bb:cc:dd:ee:07", None),
        ("192.168.1.20", "aa:bb:cc:dd:ee:12", "nas"),  # static mapping
        ("192.168.1.100", "aa:bb:cc:dd:ee:10", "laptop"),  # the expired lease is left out
    ]
    assert all(lease.expires_at is None for lease in fw.dhcp_leases)


def test_dhcp_pools(pfsense, cfg):
    [fw] = collect(cfg)
    assert [(p.network, p.total, p.used) for p in fw.dhcp_pools] == [
        ("IOT", 49, 1),
        ("LAN", 110, 1),  # main range + extra pool; the static mapping is outside them
    ]  # the disabled DMZ server is left out


def test_vlans_and_services(pfsense, cfg):
    [fw] = collect(cfg)
    assert [(v.id, v.name, v.interface, v.subnet) for v in fw.vlans] == [
        (20, "IoT devices", "igc1.20", "10.0.20.0/24"),
        (30, None, "igc1.30", None),  # not assigned to an interface
    ]
    services = {s.name: s for s in fw.services}
    assert (services["dhcpd"].running, services["dhcpd"].enabled) == (True, True)
    assert services["ntpd"].running is False and services["ntpd"].description == "NTP clock sync"


def test_vpn_peers(pfsense, cfg):
    [fw] = collect(cfg)
    peers = {(p.protocol, p.name): p for p in fw.vpn_peers}
    alice = peers[("openvpn", "alice-laptop")]
    assert (alice.endpoint, alice.address, alice.connected) == (
        "198.51.100.7:51234",
        "10.8.0.2",
        True,
    )
    assert (alice.rx_bytes, alice.tx_bytes) == (123456, 654321)
    office = peers[("openvpn", "Office UDP4:1194")]
    assert (office.endpoint, office.connected) == ("192.0.2.50:1194", True)
    phone = peers[("wireguard", "phone")]
    assert (phone.connected, phone.endpoint, phone.address) == (
        True,
        "198.51.100.9:40000",
        "10.6.0.2/32",
    )
    assert phone.last_handshake.timestamp() == 1791374340 and phone.rx_bytes == 4096
    laptop = peers[("wireguard", "peerLapt…")]  # no description: start of its public key
    assert (laptop.connected, laptop.endpoint, laptop.last_handshake) == (False, None, None)
    assert laptop.address == "10.6.0.3/32, fd06::3/128"
    tunnel = peers[("ipsec", "con1")]
    assert (tunnel.endpoint, tunnel.connected) == ("192.0.2.99:500", True)
    assert tunnel.address == "10.50.0.0/16, 10.60.0.0/16"
    assert (tunnel.rx_bytes, tunnel.tx_bytes) == (1500, 2250)
    assert "preshared" not in fw.model_dump_json()


def test_only_reads(pfsense, cfg):
    collect(cfg)
    connection_test(cfg)
    assert {method for method, _ in pfsense.calls} == {"GET"}


def test_connection_test(pfsense, cfg):
    assert connection_test(cfg) == "Connected to pfsense (pfSense Plus 24.03-p1)"


def test_missing_privileges_skip_data_and_are_reported(pfsense, cfg):
    pfsense.forbidden = {"/api/v2/status/gateways", "/api/v2/diagnostics/arp_table"}
    [fw] = collect(cfg)
    assert fw.gateways is None and fw.arp is None
    assert fw.interfaces and fw.dhcp_leases  # the rest still works
    msg = connection_test(cfg)
    assert msg.startswith("Connected to pfsense (pfSense Plus 24.03-p1). Missing privileges:")
    assert "REST API - /api/v2/status/gateways GET" in msg
    assert "REST API - /api/v2/diagnostics/arp_table GET" in msg


def test_optional_endpoints_missing_do_not_fail(pfsense, cfg):
    # An older package without these endpoints, and no WireGuard package (424).
    for path in (
        "/api/v2/status/ipsec/sas",
        "/api/v2/firewall/states/size",
        "/api/v2/system/hostname",
        "/api/v2/status/services",
    ):
        del pfsense.routes[path]
    pfsense.missing_package = {"/api/v2/status/wireguard"}
    [fw] = collect(cfg)
    assert fw.name == "192.168.1.1"  # no hostname: the address
    assert fw.firewall_states is None and fw.services is None
    assert {p.protocol for p in fw.vpn_peers} == {"openvpn"}
    assert fw.interfaces and fw.gateways


def test_wrong_key(pfsense, cfg):
    pfsense.key = "another"
    with pytest.raises(PluginError, match="rejected the API key"):
        collect(cfg)
    with pytest.raises(PluginError, match="rejected the API key"):
        connection_test(cfg)


def test_errors_the_user_can_act_on(pfsense, cfg):
    pfsense.forbidden = {"/api/v2/status/system"}
    with pytest.raises(PluginError, match=r"REST API - /api/v2/status/system GET"):
        collect(cfg)
    pfsense.forbidden = set()
    del pfsense.routes["/api/v2/status/system"]
    with pytest.raises(PluginError, match="install the pfSense REST API package"):
        collect(cfg)
    with pytest.raises(PluginError, match="required"):
        collect(Config({"url": "https://192.168.1.1"}))


def test_not_pfsense(monkeypatch, cfg):
    import omini_pfsense.collect as collect_module
    from omini_pfsense.client import Client

    def login_page(request):
        return httpx.Response(200, text="<html>Login</html>")

    monkeypatch.setattr(
        collect_module,
        "Client",
        lambda *a, **kw: Client(*a, **kw, transport=httpx.MockTransport(login_page)),
    )
    with pytest.raises(PluginError, match="REST API package"):
        collect(cfg)


def test_unreachable(monkeypatch, cfg):
    import omini_pfsense.collect as collect_module
    from omini_pfsense.client import Client

    def refuse(request):
        raise httpx.ConnectError("connection refused", request=request)

    monkeypatch.setattr(
        collect_module,
        "Client",
        lambda *a, **kw: Client(*a, **kw, transport=httpx.MockTransport(refuse)),
    )
    with pytest.raises(PluginError, match="cannot connect"):
        collect(cfg)


def test_key_never_in_errors(pfsense, cfg):
    pfsense.key = "another"
    with pytest.raises(PluginError) as e:
        collect(cfg)
    assert cfg.str("api_key") not in str(e.value)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"),
        ("aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff"),
        ("00:11:22:33:44:55 <small>(Some Vendor)</small>", "00:11:22:33:44:55"),
        ("(Incomplete)", None),
        ("00:00:00:00:00:00", None),
        (None, None),
    ],
)
def test_mac_normalization(value, expected):
    assert mac(value) == expected


@pytest.mark.parametrize(
    ("text", "seconds"),
    [
        ("3 Days 04 Hours 12 Minutes 09 Seconds", ((3 * 24 + 4) * 60 + 12) * 60 + 9),
        ("1 Day 00 Hour 01 Minute 01 Second", 86400 + 61),
        ("04 Hours 12 Minutes 09 Seconds", (4 * 60 + 12) * 60 + 9),
        ("", None),
        (None, None),
    ],
)
def test_uptime(text, seconds):
    assert uptime_seconds(text) == seconds


def test_speed_and_version():
    assert speed_from_media("1000baseT <full-duplex>") == 1000
    assert speed_from_media("2500Base-T <full-duplex>") == 2500
    assert speed_from_media("10Gbase-Twinax <full-duplex>") == 10000
    assert speed_from_media("autoselect") is None
    assert os_version({"version": "2.7.2-RELEASE", "base": "2.7.2", "patch": "0"}) == (
        "pfSense CE 2.7.2"
    )
    assert os_version({"version": "24.11-RELEASE", "base": "24.11", "patch": "0"}) == (
        "pfSense Plus 24.11"
    )
    assert os_version({}) is None


def test_a_disabled_interface(pfsense, cfg):
    rows = pfsense.routes["/api/v2/status/interfaces"]["data"]
    rows[-1]["enable"] = False
    del rows[0]["enable"]
    [fw] = collect(cfg)
    assert [i.enabled for i in fw.interfaces][:1] == [None]
    assert fw.interfaces[len(rows) - 1].enabled is False


def test_port_forwards(pfsense, cfg):
    [fw] = collect(cfg)
    got = [f.model_dump(exclude_none=True) for f in fw.port_forwards]
    assert got == [
        {
            "protocol": "tcp",
            "external_port": 443,
            "internal_ip": "192.168.1.20",
            "internal_port": 8443,
            "interface": "igc0",
            "description": "NAS web",
            "enabled": True,
            "upnp": False,
        },
        {
            "protocol": "udp",
            "external_port": 27015,
            "external_port_end": 27020,
            "internal_ip": "192.168.1.30",
            "internal_port": 27015,
            "source": "198.51.100.0/24",
            "interface": "igc0",
            "description": "Game server",
            "enabled": False,
            "upnp": False,
        },
        # "no redirect", ICMP and an alias port are left out: nothing invented
    ]


def test_port_forwards_are_optional(pfsense, cfg, caplog):
    pfsense.forbidden = {"/api/v2/firewall/nat/port_forwards"}
    [fw] = collect(cfg)
    assert fw.port_forwards is None and fw.interfaces
    assert "REST API - /api/v2/firewall/nat/port_forwards GET" in caplog.text
    pfsense.forbidden = set()
    del pfsense.routes["/api/v2/firewall/nat/port_forwards"]  # an older package: 404
    [fw] = collect(cfg)
    assert fw.port_forwards is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("443", (443, None)),
        ("27015:27020", (27015, 27020)),
        ("8000-8010", (8000, 8010)),
        ("80:80", (80, None)),
        ("web_ports", (None, None)),
        (None, (None, None)),
        ("0", (None, None)),
        ("90:80", (None, None)),
    ],
)
def test_port_range(value, expected):
    from omini_pfsense.collect import port_range

    assert port_range(value) == expected
