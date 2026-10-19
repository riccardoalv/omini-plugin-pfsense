"""port.enabled: an assigned interface turned on or off, against the stateful
fake of the REST API package v2."""

import pytest
from omini_sdk import Change, PluginError

import omini_pfsense.collect as collect_module
from tests.test_networks import router  # noqa: F401 (fixture)


def port(name, enabled):
    return Change(device="x", kind="port.enabled", port=name, value=enabled)


def test_turns_an_interface_off_and_reads_it_back(router, cfg):  # noqa: F811
    devices = collect_module.apply(cfg, port("ix0", False))
    assert router.interfaces["opt2"]["enable"] is False
    assert router.writes == [("PATCH", "/api/v2/interface"), ("POST", "/api/v2/interface/apply")]
    assert devices[0].key == "90:ec:77:aa:bb:02"


def test_turns_it_back_on(router, cfg):  # noqa: F811
    router.interfaces["opt2"]["enable"] = False
    collect_module.apply(cfg, port("ix0", True))
    assert router.interfaces["opt2"]["enable"] is True


def test_already_as_asked_changes_nothing(router, cfg):  # noqa: F811
    collect_module.apply(cfg, port("igc1.20", True))
    assert router.writes == []


def test_never_turns_off_the_interface_omini_reaches_pfsense_through(router, cfg):  # noqa: F811
    with pytest.raises(PluginError, match=r"192\.168\.1\.1, the address Omini reaches"):
        collect_module.apply(cfg, port("igc1", False))
    assert router.writes == []


def test_the_address_on_dhcp_comes_from_the_status(router, pfsense, cfg):  # noqa: F811
    router.interfaces["lan"].update(typev4="dhcp", ipaddr="dhcp")
    with pytest.raises(PluginError, match="the address Omini reaches"):
        collect_module.apply(cfg, port("igc1", False))
    assert router.writes == []


def test_without_the_status_an_address_on_dhcp_is_not_guessed(router, pfsense, cfg):  # noqa: F811
    router.interfaces["opt2"].update(typev4="dhcp", ipaddr="dhcp")
    pfsense.forbidden = {"/api/v2/status/interfaces"}
    with pytest.raises(PluginError, match=r"status/interfaces GET"):
        collect_module.apply(cfg, port("ix0", False))
    assert router.writes == []


def test_turning_on_the_management_interface_is_allowed(router, cfg):  # noqa: F811
    router.interfaces["lan"]["enable"] = False
    collect_module.apply(cfg, port("igc1", True))
    assert router.interfaces["lan"]["enable"] is True


def test_an_unassigned_port_is_refused(router, cfg):  # noqa: F811
    with pytest.raises(PluginError, match="igc5 is not an assigned interface"):
        collect_module.apply(cfg, port("igc5", False))


def test_a_value_that_is_not_a_boolean_is_refused(router, cfg):  # noqa: F811
    with pytest.raises(PluginError, match="true or false"):
        collect_module.apply(cfg, Change(device="x", kind="port.enabled", port="ix0", value="no"))


def test_a_change_that_does_not_read_back_is_undone(router, cfg, monkeypatch):  # noqa: F811
    original = router.write

    def stuck(method, path, q, body):
        if (method, path) == ("PATCH", "/api/v2/interface") and body.get("enable") is False:
            return original(method, path, q, {"id": body["id"]})  # accepted, not kept
        return original(method, path, q, body)

    monkeypatch.setattr(router, "write", stuck)
    with pytest.raises(PluginError, match=r"did not apply turning ix0 off: .* \(undone\)$"):
        collect_module.apply(cfg, port("ix0", False))
    assert router.interfaces["opt2"]["enable"] is True
    assert router.writes[-2:] == [
        ("PATCH", "/api/v2/interface"),
        ("POST", "/api/v2/interface/apply"),
    ]


def test_a_missing_privilege_is_named(router, cfg):  # noqa: F811
    router.forbidden = {("PATCH", "/api/v2/interface")}
    with pytest.raises(PluginError, match=r"REST API - /api/v2/interface PATCH"):
        collect_module.apply(cfg, port("ix0", False))


def test_reports_whether_each_interface_is_enabled(router, pfsense, cfg):  # noqa: F811
    pfsense.routes["/api/v2/status/interfaces"]["data"][3]["enable"] = False
    [fw] = collect_module.collect(cfg)
    assert [i.enabled for i in fw.interfaces if i.name == "ix0"] == [False]
