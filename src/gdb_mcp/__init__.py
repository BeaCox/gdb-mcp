"""GDB Model Context Protocol server."""

from importlib.metadata import PackageNotFoundError, version

DIST_NAME = "beacox-gdb-mcp"

try:
    __version__ = version(DIST_NAME)
except PackageNotFoundError:
    __version__ = "0+unknown"

__all__ = ["DIST_NAME", "__version__", "config", "installer", "mi", "server", "session"]
