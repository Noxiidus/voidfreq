"""Plugin system — discovery, manifest, lifecycle hooks."""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from rich.console import Console
from rich.table import Table

from .logger import get_logger

console = Console()
log = get_logger("plugins")

PLUGIN_DIR = Path.home() / ".voidfreq" / "plugins"


@dataclass
class PluginManifest:
    name: str
    version: str = "0.1.0"
    description: str = ""
    author: str = ""
    commands: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    hooks: list[str] = field(default_factory=list)
    entry_point: str = "plugin.py"


class PluginHook:
    PRE_OPERATION = "pre_operation"
    POST_OPERATION = "post_operation"
    ON_ALERT = "on_alert"
    ON_CAPTURE = "on_capture"
    ON_CRACK = "on_crack"

    ALL = (PRE_OPERATION, POST_OPERATION, ON_ALERT, ON_CAPTURE, ON_CRACK)


class Plugin:
    def __init__(self, manifest: PluginManifest, path: Path) -> None:
        self.manifest = manifest
        self.path = path
        self._module = None
        self._loaded = False

    def load(self) -> bool:
        entry = self.path / self.manifest.entry_point
        if not entry.exists():
            log.error("Plugin %s: entry point not found: %s", self.manifest.name, entry)
            return False

        try:
            spec = importlib.util.spec_from_file_location(
                f"voidfreq_plugin_{self.manifest.name}", str(entry),
            )
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                self._module = mod
                self._loaded = True
                log.info("Loaded plugin: %s v%s", self.manifest.name, self.manifest.version)
                return True
        except Exception as e:
            log.error("Plugin %s failed to load: %s", self.manifest.name, e)

        return False

    def call_hook(self, hook: str, **kwargs) -> None:
        if not self._loaded or not self._module:
            return

        if hook not in self.manifest.hooks:
            return

        handler = getattr(self._module, hook, None)
        if callable(handler):
            try:
                handler(**kwargs)
            except Exception as e:
                log.error("Plugin %s hook %s failed: %s", self.manifest.name, hook, e)

    def run_command(self, command: str, args: list[str] | None = None) -> None:
        if not self._loaded or not self._module:
            return

        handler = getattr(self._module, f"cmd_{command}", None)
        if callable(handler):
            try:
                handler(args or [])
            except Exception as e:
                log.error("Plugin %s command %s failed: %s", self.manifest.name, command, e)

    @property
    def loaded(self) -> bool:
        return self._loaded


class PluginManager:
    def __init__(self, plugin_dir: Path | None = None) -> None:
        self.plugin_dir = plugin_dir or PLUGIN_DIR
        self._plugins: list[Plugin] = []

    def discover(self) -> list[PluginManifest]:
        if not self.plugin_dir.exists():
            return []

        manifests: list[PluginManifest] = []

        for item in self.plugin_dir.iterdir():
            if not item.is_dir():
                continue

            manifest_path = item / "manifest.yaml"
            if not manifest_path.exists():
                manifest_path = item / "manifest.yml"

            if not manifest_path.exists():
                continue

            manifest = self._load_manifest(manifest_path)
            if manifest:
                manifests.append(manifest)

        return manifests

    def load_all(self) -> list[Plugin]:
        manifests = self.discover()
        self._plugins = []

        for manifest in manifests:
            plugin_path = self.plugin_dir / manifest.name
            plugin = Plugin(manifest, plugin_path)

            if self._check_dependencies(manifest):
                if plugin.load():
                    self._plugins.append(plugin)
            else:
                log.warning(
                    "Plugin %s skipped — missing dependencies: %s",
                    manifest.name, manifest.dependencies,
                )

        if self._plugins:
            console.print(f"[green]{len(self._plugins)} plugin(s) loaded[/green]")

        return self._plugins

    def fire_hook(self, hook: str, **kwargs) -> None:
        for plugin in self._plugins:
            plugin.call_hook(hook, **kwargs)

    def run_command(self, plugin_name: str, command: str, args: list[str] | None = None) -> bool:
        for plugin in self._plugins:
            if plugin.manifest.name == plugin_name:
                plugin.run_command(command, args)
                return True
        return False

    def list_plugins(self) -> None:
        manifests = self.discover()

        if not manifests:
            console.print("[yellow]No plugins found[/yellow]")
            console.print(f"[dim]Plugin directory: {self.plugin_dir}[/dim]")
            return

        table = Table(title="Installed Plugins")
        table.add_column("Name", style="cyan")
        table.add_column("Version")
        table.add_column("Description")
        table.add_column("Commands")
        table.add_column("Hooks")
        table.add_column("Status")

        loaded_names = {p.manifest.name for p in self._plugins}

        for m in manifests:
            status = "[green]loaded[/green]" if m.name in loaded_names else "[dim]available[/dim]"
            table.add_row(
                m.name,
                m.version,
                m.description,
                ", ".join(m.commands) or "-",
                ", ".join(m.hooks) or "-",
                status,
            )

        console.print(table)

    def get_plugin_commands(self) -> dict[str, Plugin]:
        commands: dict[str, Plugin] = {}
        for plugin in self._plugins:
            for cmd in plugin.manifest.commands:
                commands[f"plugin:{plugin.manifest.name}:{cmd}"] = plugin
        return commands

    @property
    def plugins(self) -> list[Plugin]:
        return self._plugins

    def _load_manifest(self, path: Path) -> PluginManifest | None:
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
        except Exception as e:
            log.error("Failed to load manifest %s: %s", path, e)
            return None

        if not isinstance(data, dict) or "name" not in data:
            log.error("Invalid manifest %s — missing 'name'", path)
            return None

        return PluginManifest(
            name=data["name"],
            version=str(data.get("version", "0.1.0")),
            description=data.get("description", ""),
            author=data.get("author", ""),
            commands=data.get("commands", []),
            dependencies=data.get("dependencies", []),
            hooks=data.get("hooks", []),
            entry_point=data.get("entry_point", "plugin.py"),
        )

    def _check_dependencies(self, manifest: PluginManifest) -> bool:
        for dep in manifest.dependencies:
            try:
                importlib.util.find_spec(dep)
            except (ModuleNotFoundError, ValueError):
                return False
        return True
