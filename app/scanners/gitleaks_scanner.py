
import subprocess
import shutil
from pathlib import Path

def gitLeaksScan(path="."):
    report_path = Path("gitleaks-report.json")
    report_path.parent.mkdir(parents=True, exist_ok=True)

    # First check managed installation
    gitleaks = Path.home() / ".grepsec" / "bin" / "gitleaks"

    # Fall back to system PATH
    if not gitleaks.exists():
        system_gitleaks = shutil.which("gitleaks")

        if system_gitleaks:
            gitleaks = Path(system_gitleaks)
        else:
            raise FileNotFoundError(
                "Gitleaks binary not found. Run GrepSec dependency installer."
            )

    result = subprocess.run(
        [
            str(gitleaks),
            "detect",
            "--source", str(Path(path).resolve()),
            "--report-format", "json",
            "--report-path", str(report_path.resolve()),
            "--no-git",
            "-v"
        ],
        capture_output=True,
        text=True
    )

    if result.returncode not in (0, 1):
        print("Gitleaks error:", result.stderr)
        return []

    if report_path.exists():
        import json
        with open(report_path, "r") as f:
            findings = json.load(f)
        return findings

    return []
