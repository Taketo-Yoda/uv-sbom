"""CLI entry point for uv-sbom."""

import subprocess
import sys

from .install import ensure_binary


def main():
    """Main entry point that ensures binary is installed and runs it."""
    try:
        binary_path = ensure_binary()
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Run the binary with all arguments passed through
    try:
        result = subprocess.run(
            [str(binary_path)] + sys.argv[1:],
            check=False
        )
        return result.returncode
    except Exception as e:
        print(f"Error running uv-sbom: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
