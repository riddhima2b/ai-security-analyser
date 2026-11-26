from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any
from platform_detect import get_platform
import ssl
import certifi
import urllib.request
import urllib.error
# GrepSec-managed binaries live here. No global PATH changes are required.
BIN_DIR = Path.home() / ".grepsec" / "bin"
BIN_DIR.mkdir(parents=True, exist_ok=True)

SEMGREP_ENV = BIN_DIR / "semgrep"

if os.name == "nt":
    SEMGREP_EXECUTABLE = SEMGREP_ENV / "Scripts" / "semgrep.exe"
    SEMGREP_PYTHON = SEMGREP_ENV / "Scripts" / "python.exe"
else:
    SEMGREP_EXECUTABLE = SEMGREP_ENV / "bin" / "semgrep"
    SEMGREP_PYTHON = SEMGREP_ENV / "bin" / "python"


DEPENDENCIES = {
    "Semgrep": {
        "command": "semgrep",
        "version_args": ["--version"],
        "installer": "pip",
    },
    "OSV-Scanner": {
        "command": "osv-scanner",
        "version_args": ["--version"],
        "installer": "github",
        "repo": "google/osv-scanner",
    },
    "Gitleaks": {
        "command": "gitleaks",
        "version_args": ["version"],
        "installer": "github",
        "repo": "gitleaks/gitleaks",
    },
}

SEMGREP_EXECUTABLE = (
    BIN_DIR / "semgrep" / "bin" / "semgrep"
)

def _executable_name(command: str) -> str:
    return command + ".exe" if os.name == "nt" else command


def _managed_executable(command: str) -> Path:
    return BIN_DIR / _executable_name(command)

def is_semgrep_installed():

    if not SEMGREP_EXECUTABLE.exists():
        return False

    try:
        result = subprocess.run(
            [str(SEMGREP_EXECUTABLE), "--version"],
            capture_output=True,
            text=True,
            timeout=30
        )

        return result.returncode == 0

    except (OSError, subprocess.SubprocessError):
        return False

def _find_executable(command: str) -> str | None:
    """Find a dependency on PATH first, then in GrepSec's managed bin directory."""
    found = shutil.which(command)
    if found:
        return found

    managed = _managed_executable(command)
    if managed.is_file():
        return str(managed)

    return None


def check_dependencies() -> dict[str, dict[str, Any]]:
    """Check availability and version of each configured dependency."""

    results: dict[str, dict[str, Any]] = {}

    print("\nChecking system dependencies...\n")

    for name, details in DEPENDENCIES.items():

        # Use GrepSec-managed Semgrep executable
        if name.lower() == "semgrep":
            executable = str(
                BIN_DIR / "semgrep" / "bin" / "semgrep"
            )
            if not Path(executable).is_file():
                executable = None

        else:
            executable = _find_executable(details["command"])

        if not executable:
            results[name] = {
                "installed": False,
                "path": None,
                "version": None,
            }

            print(f"  [MISSING] {name}")
            continue

        try:
            completed = subprocess.run(
                [executable, *details["version_args"]],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            version_output = (
                completed.stdout or completed.stderr
            ).strip()

            version = (
                version_output.splitlines()[0]
                if version_output else "Unknown"
            )

            healthy = completed.returncode == 0

            results[name] = {
                "installed": healthy,
                "path": executable,
                "version": version if healthy else None,
            }

            if healthy:
                print(f"  [OK] {name} ({version})")
            else:
                print(f"  [BROKEN] {name} (version check failed)")

        except (OSError, subprocess.TimeoutExpired) as exc:

            results[name] = {
                "installed": False,
                "path": executable,
                "version": None,
                "error": str(exc),
            }

            print(f"  [BROKEN] {name} ({exc})")

    return results


def get_missing_dependencies(
    results: dict[str, dict[str, Any]]
) -> list[str]:
    return [
        name
        for name, details in results.items()
        if not details["installed"]
    ]


def prompt_installation(missing_dependencies: list[str]) -> list[str]:
    """Ask once for permission to install missing dependencies."""
    if not missing_dependencies:
        print("\nAll required dependencies are installed!")
        return []

    print("\nRequired dependencies missing:\n")
    for dependency in missing_dependencies:
        print(f"  [MISSING] {dependency}")

    while True:
        choice = input(
            "\nWould you like us to install them? [Y/n] "
        ).strip().lower()

        if choice in ("", "y", "yes"):
            return missing_dependencies

        if choice in ("n", "no"):
            print("\nInstallation skipped.")
            return []

        print("Please enter Y or n.")



def _github_json(url: str) -> dict[str, Any]:
    context = ssl.create_default_context(cafile=certifi.where())

    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "GrepSec-dependency-installer",
        },
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=30,
            context=context
        ) as response:
            return json.loads(response.read().decode("utf-8"))

    except urllib.error.HTTPError as exc:
        raise RuntimeError(
            f"GitHub API request failed ({exc.code}) for {url}"
        ) from exc

    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"Could not reach GitHub: {exc.reason}"
        ) from exc


def get_latest_release(repo: str) -> dict[str, Any]:
    return _github_json(
        f"https://api.github.com/repos/{repo}/releases/latest"
    )



def download_file(url: str, destination: Path) -> None:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "GrepSec-dependency-installer"},
    )

    context = ssl.create_default_context(cafile=certifi.where())

    try:
        with urllib.request.urlopen(
            request,
            timeout=180,
            context=context
        ) as response:
            with destination.open("wb") as output:
                shutil.copyfileobj(response, output)

    except (urllib.error.URLError, urllib.error.HTTPError) as exc:
        raise RuntimeError(
            f"Download failed: {url}: {exc}"
        ) from exc


def verify_checksum(file_path: Path, expected_digest: str | None) -> None:
    """Verify the SHA-256 digest published for this exact GitHub release asset."""
    if not expected_digest or not expected_digest.startswith("sha256:"):
        raise RuntimeError(
            "GitHub did not provide a SHA-256 digest for this asset; "
            "refusing to install an unverified binary."
        )

    expected = expected_digest.split(":", 1)[1].lower()
    hasher = hashlib.sha256()

    with file_path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            hasher.update(chunk)

    actual = hasher.hexdigest()
    if actual != expected:
        raise RuntimeError(
            f"SHA-256 mismatch for {file_path.name}. "
            "The downloaded file may be corrupted or tampered with."
        )


def find_release_asset(
    release: dict[str, Any],
    tool: str,
    os_name: str,
    arch: str,
) -> dict[str, Any]:
    version = release["tag_name"].lstrip("v")

    if tool == "OSV-Scanner":
        filename = f"osv-scanner_{os_name}_{arch}"
        if os_name == "windows":
            filename += ".exe"
        candidates = {filename}

    elif tool == "Gitleaks":
        # Gitleaks calls AMD64 "x64" in its release asset names.
        gitleaks_arch = "x64" if arch == "amd64" else "arm64"
        base = f"gitleaks_{version}_{os_name}_{gitleaks_arch}"
        extension = ".zip" if os_name == "windows" else ".tar.gz"
        candidates = {base + extension}

    else:
        raise ValueError(f"No GitHub binary installer configured for {tool}")

    for asset in release.get("assets", []):
        if asset.get("name") in candidates:
            return asset

    available = ", ".join(
        asset.get("name", "<unnamed>")
        for asset in release.get("assets", [])
    )
    raise RuntimeError(
        f"No compatible {tool} release asset for {os_name}/{arch}. "
        f"Expected one of {sorted(candidates)}. Available assets: {available}"
    )


def _extract_gitleaks(archive_path: Path, destination: Path) -> None:
    """Extract only the Gitleaks executable; do not extract arbitrary archive paths."""
    expected_name = "gitleaks.exe" if os.name == "nt" else "gitleaks"

    if archive_path.name.endswith(".tar.gz"):
        with tarfile.open(archive_path, "r:gz") as archive:
            matches = [
                member for member in archive.getmembers()
                if Path(member.name).name == expected_name and member.isfile()
            ]
            if not matches:
                raise RuntimeError(f"{expected_name} not found in Gitleaks archive")

            source = archive.extractfile(matches[0])
            if source is None:
                raise RuntimeError("Could not read Gitleaks executable from archive")

            with source, destination.open("wb") as output:
                shutil.copyfileobj(source, output)

    elif archive_path.suffix == ".zip":
        with zipfile.ZipFile(archive_path) as archive:
            matches = [
                name for name in archive.namelist()
                if Path(name).name == expected_name
                and not name.endswith("/")
            ]
            if not matches:
                raise RuntimeError(f"{expected_name} not found in Gitleaks archive")

            with archive.open(matches[0]) as source, destination.open("wb") as output:
                shutil.copyfileobj(source, output)
    else:
        raise RuntimeError(f"Unsupported Gitleaks archive: {archive_path.name}")


def _install_semgrep() -> str:
    """Install Semgrep into GrepSec's dedicated environment."""

    print("\nInstalling Semgrep for GrepSec...")

    try:
        # Create dedicated virtual environment
        if not SEMGREP_PYTHON.exists():

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "venv",
                    str(SEMGREP_ENV)
                ],
                check=True,
                capture_output=True,
                text=True
            )

        # Install Semgrep
        subprocess.run(
            [
                str(SEMGREP_PYTHON),
                "-m",
                "pip",
                "install",
                "semgrep"
            ],
            check=True,
            capture_output=True,
            text=True
        )

        # Verify executable
        if not SEMGREP_EXECUTABLE.exists():
            raise RuntimeError("Semgrep executable was not created.")

        result = subprocess.run(
            [str(SEMGREP_EXECUTABLE), "--version"],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            raise RuntimeError("Semgrep executable verification failed.")

        print("Semgrep installed successfully.")
        print("Semgrep version:", result.stdout.strip())

        return str(SEMGREP_EXECUTABLE)

    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"Semgrep installation failed: {e.stderr or e}"
        ) from e

    except (OSError, subprocess.TimeoutExpired) as e:
        raise RuntimeError(f"Semgrep installation failed: {e}") from e

def install_tool(
    tool: str,
    os_name: str,
    arch: str,
) -> str:
    repo = DEPENDENCIES[tool]["repo"]
    print(f"\nInstalling {tool}...")

    release = get_latest_release(repo)
    asset = find_release_asset(release, tool, os_name, arch)

    BIN_DIR.mkdir(parents=True, exist_ok=True)

    command = DEPENDENCIES[tool]["command"]
    destination = _managed_executable(command)

    with tempfile.TemporaryDirectory(prefix="grepsec-") as temp:
        temp_dir = Path(temp)
        downloaded = temp_dir / asset["name"]
        extracted = temp_dir / _executable_name(command)

        download_file(asset["browser_download_url"], downloaded)
        verify_checksum(downloaded, asset.get("digest"))

        if tool == "Gitleaks":
            _extract_gitleaks(downloaded, extracted)
        else:
            # OSV-Scanner release asset is a standalone executable.
            shutil.copy2(downloaded, extracted)

        if os.name != "nt":
            extracted.chmod(
                extracted.stat().st_mode
                | stat.S_IXUSR
                | stat.S_IXGRP
                | stat.S_IXOTH
            )

        # Replace the old managed binary only after download and verification succeed.
        os.replace(extracted, destination)

    # Confirm that the installed executable actually starts.
    subprocess.run(
        [str(destination), *DEPENDENCIES[tool]["version_args"]],
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )

    print(f"[OK] {tool} installed at {destination}")
    return str(destination)


def install_dependencies(
    approved_dependencies: list[str],
) -> dict[str, str]:
    """Install only dependencies the user approved."""
    if not approved_dependencies:
        return {}

    os_name, arch = get_platform()
    print(f"\nDetected platform: {os_name} / {arch}")

    installed: dict[str, str] = {}
    failed: dict[str, str] = {}

    for tool in approved_dependencies:
        try:
            if tool == "Semgrep":
                installed[tool] = _install_semgrep()
            elif tool in ("OSV-Scanner", "Gitleaks"):
                installed[tool] = install_tool(tool, os_name, arch)
            else:
                raise ValueError(f"Unknown dependency: {tool}")

        except Exception as exc:
            failed[tool] = str(exc)
            print(f"[FAILED] {tool}: {exc}")

    if failed:
        print("\nSome dependencies could not be installed:")
        for tool, reason in failed.items():
            print(f"  [FAILED] {tool}: {reason}")

    return installed

def setup_dependencies() -> bool:
    """Run check -> prompt -> install -> verify. Returns True if all are ready."""
    results = check_dependencies()
    missing = get_missing_dependencies(results)

    if missing:
        approved = prompt_installation(missing)
        install_dependencies(approved)

    print("\nVerifying dependencies...\n")
    final_results = check_dependencies()
    still_missing = get_missing_dependencies(final_results)

    if still_missing:
        print("\nGrepSec cannot start because these dependencies are unavailable:")
        for name in still_missing:
            print(f"  [MISSING] {name}")
        return False

    print("\nAll dependencies are ready!")
    return True

if __name__ == "__main__":
    ready = setup_dependencies()
    raise SystemExit(0 if ready else 1)
