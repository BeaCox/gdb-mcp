"""GDB Model Context Protocol server."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("gdb-mcp")
except PackageNotFoundError:
    __version__ = "0+unknown"

__all__ = ["__version__", "config", "mi", "server", "session"]
