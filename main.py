"""Omini plugin for pfSense (entrypoint run by the Omini core)."""

from omini_sdk import plugin

from omini_pfsense.collect import collect, test

plugin.collect(collect)
plugin.test(test)

if __name__ == "__main__":
    plugin.run()
