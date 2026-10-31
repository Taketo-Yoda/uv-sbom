"""Python wrapper for uv-sbom CLI tool."""

from importlib.metadata import PackageNotFoundError as _PackageNotFoundError
from importlib.metadata import version as _version

try:
    __version__ = _version("uv-sbom-bin")
except _PackageNotFoundError:
    # Running from an uninstalled source checkout
    __version__ = "0.0.0+unknown"

from .install import ensure_binary, get_binary_path

__all__ = ["ensure_binary", "get_binary_path", "__version__"]
