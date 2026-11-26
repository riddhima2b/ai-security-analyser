import platform

def get_platform():
    system = platform.system().lower()
    machine = platform.machine().lower()

    os_map = {
        "darwin": "darwin",
        "linux": "linux",
        "windows": "windows"
    }

    arch_map = {
        "arm64": "arm64",
        "aarch64": "arm64",
        "x86_64": "amd64",
        "amd64": "amd64"
    }

    if system not in os_map:
        raise RuntimeError(f"Unsupported operating system: {system}")

    if machine not in arch_map:
        raise RuntimeError(f"Unsupported architecture: {machine}")

    return os_map[system], arch_map[machine]