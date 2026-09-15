"""Tests for plugin system."""

import tempfile
from pathlib import Path

from voidfreq.core.plugins import Plugin, PluginManager, PluginManifest


class TestPluginManifest:
    def test_defaults(self):
        m = PluginManifest(name="test")
        assert m.version == "0.1.0"
        assert m.commands == []
        assert m.hooks == []
        assert m.entry_point == "plugin.py"

    def test_custom_values(self):
        m = PluginManifest(
            name="custom",
            version="1.0.0",
            commands=["scan", "attack"],
            hooks=["pre_operation"],
        )
        assert m.name == "custom"
        assert len(m.commands) == 2


class TestPluginDiscovery:
    def test_no_plugins_dir(self):
        mgr = PluginManager(plugin_dir=Path("/nonexistent/path/plugins"))
        assert mgr.discover() == []

    def test_discover_valid_plugin(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_dir = Path(tmpdir) / "plugins"
            plugin_dir.mkdir()

            my_plugin = plugin_dir / "my_plugin"
            my_plugin.mkdir()

            manifest = my_plugin / "manifest.yaml"
            manifest.write_text(
                "name: my_plugin\n"
                "version: '1.0.0'\n"
                "description: Test plugin\n"
                "commands:\n  - hello\n"
                "hooks:\n  - pre_operation\n"
            )

            entry = my_plugin / "plugin.py"
            entry.write_text(
                "def pre_operation(**kwargs):\n"
                "    pass\n\n"
                "def cmd_hello(args):\n"
                "    print('Hello from plugin!')\n"
            )

            mgr = PluginManager(plugin_dir=plugin_dir)
            manifests = mgr.discover()
            assert len(manifests) == 1
            assert manifests[0].name == "my_plugin"
            assert manifests[0].version == "1.0.0"

    def test_discover_invalid_manifest(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_dir = Path(tmpdir) / "plugins"
            plugin_dir.mkdir()

            bad = plugin_dir / "bad_plugin"
            bad.mkdir()

            manifest = bad / "manifest.yaml"
            manifest.write_text("not_a_name: true\n")

            mgr = PluginManager(plugin_dir=plugin_dir)
            assert mgr.discover() == []

    def test_discover_skips_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_dir = Path(tmpdir) / "plugins"
            plugin_dir.mkdir()

            (plugin_dir / "not_a_plugin.txt").write_text("hello")

            mgr = PluginManager(plugin_dir=plugin_dir)
            assert mgr.discover() == []


class TestPluginLoading:
    def test_load_valid_plugin(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_dir = Path(tmpdir)
            entry = plugin_dir / "plugin.py"
            entry.write_text(
                "def pre_operation(**kwargs):\n"
                "    pass\n"
            )

            manifest = PluginManifest(
                name="test_plugin",
                hooks=["pre_operation"],
            )
            plugin = Plugin(manifest, plugin_dir)
            assert plugin.load() is True
            assert plugin.loaded is True

    def test_load_missing_entry(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest = PluginManifest(name="missing")
            plugin = Plugin(manifest, Path(tmpdir))
            assert plugin.load() is False
            assert plugin.loaded is False

    def test_call_hook(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_dir = Path(tmpdir)
            entry = plugin_dir / "plugin.py"
            entry.write_text(
                "called = False\n"
                "def on_alert(**kwargs):\n"
                "    global called\n"
                "    called = True\n"
            )

            manifest = PluginManifest(name="hook_test", hooks=["on_alert"])
            plugin = Plugin(manifest, plugin_dir)
            plugin.load()
            plugin.call_hook("on_alert", message="test alert")

    def test_call_hook_not_registered(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_dir = Path(tmpdir)
            entry = plugin_dir / "plugin.py"
            entry.write_text("pass\n")

            manifest = PluginManifest(name="nohook", hooks=[])
            plugin = Plugin(manifest, plugin_dir)
            plugin.load()
            plugin.call_hook("pre_operation")


class TestPluginManager:
    def test_load_all_empty(self):
        mgr = PluginManager(plugin_dir=Path("/nonexistent"))
        plugins = mgr.load_all()
        assert plugins == []

    def test_fire_hook_no_plugins(self):
        mgr = PluginManager(plugin_dir=Path("/nonexistent"))
        mgr.fire_hook("pre_operation")

    def test_run_command_not_found(self):
        mgr = PluginManager(plugin_dir=Path("/nonexistent"))
        assert mgr.run_command("nonexistent", "test") is False

    def test_list_plugins_empty(self):
        mgr = PluginManager(plugin_dir=Path("/nonexistent"))
        mgr.list_plugins()

    def test_get_plugin_commands_empty(self):
        mgr = PluginManager(plugin_dir=Path("/nonexistent"))
        assert mgr.get_plugin_commands() == {}

    def test_full_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_dir = Path(tmpdir) / "plugins"
            plugin_dir.mkdir()

            my_plugin = plugin_dir / "lifecycle_test"
            my_plugin.mkdir()

            (my_plugin / "manifest.yaml").write_text(
                "name: lifecycle_test\n"
                "version: '2.0.0'\n"
                "commands:\n  - greet\n"
                "hooks:\n  - pre_operation\n"
            )

            (my_plugin / "plugin.py").write_text(
                "def pre_operation(**kwargs):\n"
                "    pass\n\n"
                "def cmd_greet(args):\n"
                "    print('Hello!')\n"
            )

            mgr = PluginManager(plugin_dir=plugin_dir)
            plugins = mgr.load_all()
            assert len(plugins) == 1
            assert plugins[0].manifest.name == "lifecycle_test"

            mgr.fire_hook("pre_operation")
            assert mgr.run_command("lifecycle_test", "greet") is True
            assert mgr.run_command("nonexistent", "greet") is False

            cmds = mgr.get_plugin_commands()
            assert "plugin:lifecycle_test:greet" in cmds
