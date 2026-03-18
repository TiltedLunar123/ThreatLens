"""ThreatLens - Log Analysis & Threat Hunting CLI."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("threatlens")
except PackageNotFoundError:
    __version__ = "1.1.0"  # fallback for uninstalled usage
__author__ = "Jude Hilgendorf"
