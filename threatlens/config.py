"""Configuration loading and detector building for ThreatLens."""

from __future__ import annotations

import importlib.util
import logging
from pathlib import Path
from typing import Any

import yaml

from threatlens.detections import ALL_DETECTORS
from threatlens.detections.base import DetectionRule

logger = logging.getLogger("threatlens")

# File extensions recognized per input format
_FORMAT_EXTENSIONS: dict[str, list[str]] = {
    "json": ["*.json", "*.ndjson", "*.jsonl"],
    "evtx": ["*.evtx"],
    "syslog": ["*.log", "*.syslog"],
    "cef": ["*.cef"],
}


def load_rules_config(rules_path: Path | None) -> dict[str, Any]:
    """Load detection rule configuration from a YAML file."""
    if rules_path is None:
        default = Path(__file__).parent.parent / "rules" / "default_rules.yaml"
        if default.exists():
            rules_path = default
        else:
            return {}

    if not rules_path.exists():
        logger.warning("Rules file not found: %s", rules_path)
        return {}

    with open(rules_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data if isinstance(data, dict) else {}


def collect_log_files(
    path: Path,
    input_format: str | None = None,
    recursive: bool = False,
) -> list[Path]:
    """Gather log files from a file or directory path."""
    if path.is_file():
        return [path]
    if path.is_dir():
        if input_format and input_format in _FORMAT_EXTENSIONS:
            globs = _FORMAT_EXTENSIONS[input_format]
        else:
            globs = [g for exts in _FORMAT_EXTENSIONS.values() for g in exts]
        files: list[Path] = []
        for pattern in globs:
            if recursive:
                files.extend(sorted(path.rglob(pattern)))
            else:
                files.extend(sorted(path.glob(pattern)))
        return sorted(set(files))
    return []


def _build_detectors(
    args: Any,
    rules_config: dict[str, Any],
) -> list[Any]:
    """Build the list of detectors: built-in + custom YAML + Sigma + plugins."""
    detectors: list[Any] = []

    # Built-in detectors
    for detector_cls in ALL_DETECTORS:
        flat_config: dict[str, Any] = {}
        for section in rules_config.values():
            if isinstance(section, dict):
                flat_config.update(section)
        detectors.append(detector_cls(config=flat_config))

    # Custom YAML rules
    custom_path = getattr(args, "custom_rules", None)
    if custom_path:
        from threatlens.rules.yaml_rules import load_yaml_rules
        yaml_rules = load_yaml_rules(Path(custom_path))
        detectors.extend(yaml_rules)

    # Sigma rules
    sigma_path = getattr(args, "sigma_rules", None)
    if sigma_path:
        from threatlens.rules.sigma_loader import load_sigma_rules
        sigma_rules = load_sigma_rules(Path(sigma_path))
        detectors.extend(sigma_rules)

    # Plugin directory
    plugin_dir = getattr(args, "plugin_dir", None)
    if plugin_dir:
        plugin_classes = load_plugins(Path(plugin_dir))
        for cls in plugin_classes:
            flat_config_p: dict[str, Any] = {}
            for section in rules_config.values():
                if isinstance(section, dict):
                    flat_config_p.update(section)
            detectors.append(cls(config=flat_config_p))

    return detectors


def load_plugins(plugin_dir: Path) -> list[type]:
    """Load custom detector classes from a directory of .py files."""
    detectors: list[type] = []
    if not plugin_dir.is_dir():
        logger.warning("Plugin directory not found: %s", plugin_dir)
        return detectors

    for py_file in sorted(plugin_dir.glob("*.py")):
        try:
            spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            for obj in vars(module).values():
                if (
                    isinstance(obj, type)
                    and issubclass(obj, DetectionRule)
                    and obj is not DetectionRule
                ):
                    detectors.append(obj)
        except Exception as exc:
            logger.warning("Failed to load plugin %s: %s", py_file, exc)

    return detectors


def load_user_config() -> dict:
    """Load config from ~/.threatlens.yaml or ./.threatlens.yaml.

    Checks current working directory first, then the user's home directory.

    Supported keys: min_severity, custom_rules, sigma_rules, elastic_url,
    elastic_index, allowlist, no_color, recursive, plugin_dir,
    business_hours_start, business_hours_end
    """
    candidates = [
        Path.cwd() / ".threatlens.yaml",
        Path.home() / ".threatlens.yaml",
    ]

    for path in candidates:
        if path.is_file():
            try:
                with open(path, encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                if isinstance(data, dict):
                    logger.debug("Loaded user config from %s", path)
                    return data
            except Exception as exc:
                logger.warning("Failed to load config from %s: %s", path, exc)

    return {}
