"""Binary installation logic for uv-sbom."""

import os
import platform
import sys
import tarfile
import zipfile
from pathlib import Path
from urllib.request import urlretrieve

# Version of uv-sbom to install
UV_SBOM_VERSION = "1.0.0"

# GitHub release URL template
RELEASE_URL_TEMPLATE = (
    "https://github.com/Taketo-Yoda/uv-sbom/releases/download/"
    "v{version}/uv-sbom-{platform}.{ext}"
)


def get_platform_info():
    """Detect the current platform and return the appropriate binary info.

    Returns:
        tuple: (platform_string, file_extension)

    Raises:
        RuntimeError: If the platform is not supported
    """
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "darwin":
        if machine == "arm64":
            return "aarch64-apple-darwin", "tar.gz"
        elif machine == "x86_64":
            return "x86_64-apple-darwin", "tar.gz"
        else:
            raise RuntimeError(f"Unsupported macOS architecture: {machine}")

    elif system == "linux":
        if machine == "x86_64":
            return "x86_64-unknown-linux-gnu", "tar.gz"
        else:
            raise RuntimeError(
                f"Unsupported Linux architecture: {machine}. "
                "Only x86_64 is currently supported."
            )

    elif system == "windows":
        if machine in ("amd64", "x86_64"):
            return "x86_64-pc-windows-msvc", "zip"
        else:
            raise RuntimeError(f"Unsupported Windows architecture: {machine}")

    else:
        raise RuntimeError(f"Unsupported operating system: {system}")


def get_binary_path():
    """Get the path where the uv-sbom binary should be installed.

    Returns:
        Path: Path to the binary executable
    """
    package_dir = Path(__file__).parent
    binary_dir = package_dir / "bin"

    if platform.system().lower() == "windows":
        return binary_dir / "uv-sbom.exe"
    else:
        return binary_dir / "uv-sbom"


def download_binary(platform_str, extension, dest_dir):
    """Download the binary archive for the current platform.

    Args:
        platform_str: Platform identifier (e.g., "x86_64-apple-darwin")
        extension: File extension ("tar.gz" or "zip")
        dest_dir: Destination directory for the download

    Returns:
        Path: Path to the downloaded archive
    """
    url = RELEASE_URL_TEMPLATE.format(
        version=UV_SBOM_VERSION,
        platform=platform_str,
        ext=extension
    )

    archive_name = f"uv-sbom-{platform_str}.{extension}"
    archive_path = dest_dir / archive_name

    print(f"Downloading uv-sbom v{UV_SBOM_VERSION} for {platform_str}...")
    print(f"URL: {url}")

    try:
        urlretrieve(url, archive_path)
        print(f"Downloaded to {archive_path}")
        return archive_path
    except Exception as e:
        raise RuntimeError(
            f"Failed to download uv-sbom binary: {e}\n"
            f"URL: {url}"
        )


def extract_binary(archive_path, dest_dir):
    """Extract the binary from the downloaded archive.

    Args:
        archive_path: Path to the archive file
        dest_dir: Destination directory for extraction
    """
    print(f"Extracting {archive_path}...")

    if archive_path.suffix == ".zip" or archive_path.name.endswith(".zip"):
        with zipfile.ZipFile(archive_path, 'r') as zip_ref:
            zip_ref.extractall(dest_dir)
    else:  # tar.gz
        with tarfile.open(archive_path, 'r:gz') as tar_ref:
            tar_ref.extractall(dest_dir)

    print(f"Extracted to {dest_dir}")


def make_executable(binary_path):
    """Make the binary executable on Unix-like systems.

    Args:
        binary_path: Path to the binary file
    """
    if platform.system().lower() != "windows":
        os.chmod(binary_path, 0o755)
        print(f"Made {binary_path} executable")


def ensure_binary():
    """Ensure the uv-sbom binary is installed.

    Downloads and installs the binary if not already present.

    Returns:
        Path: Path to the installed binary

    Raises:
        RuntimeError: If installation fails
    """
    binary_path = get_binary_path()

    # Check if already installed
    if binary_path.exists():
        print(f"uv-sbom binary already installed at {binary_path}")
        return binary_path

    # Get platform info
    try:
        platform_str, extension = get_platform_info()
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        raise

    # Create binary directory
    binary_dir = binary_path.parent
    binary_dir.mkdir(parents=True, exist_ok=True)

    # Download and extract
    try:
        archive_path = download_binary(platform_str, extension, binary_dir)
        extract_binary(archive_path, binary_dir)

        # Verify the binary exists
        if not binary_path.exists():
            raise RuntimeError(
                f"Binary not found after extraction: {binary_path}"
            )

        # Make executable
        make_executable(binary_path)

        # Clean up archive
        archive_path.unlink()
        print(f"Cleaned up {archive_path}")

        print(f"✅ uv-sbom v{UV_SBOM_VERSION} installed successfully!")
        return binary_path

    except Exception as e:
        print(f"❌ Installation failed: {e}", file=sys.stderr)
        raise


if __name__ == "__main__":
    # Allow running as: python -m uv_sbom_bin.install
    ensure_binary()
