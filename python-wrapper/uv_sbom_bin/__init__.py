"""Python wrapper for uv-sbom CLI tool."""

__version__ = "1.0.0"

from .install import ensure_binary, get_binary_path

__all__ = ["ensure_binary", "get_binary_path", "__version__"]
