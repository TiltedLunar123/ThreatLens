"""ThreatLens - Log Analysis & Threat Hunting CLI."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("threatlens-cli")
except PackageNotFoundError:
    __version__ = "2.2.1"
__author__ = "Jude Hilgendorf"
