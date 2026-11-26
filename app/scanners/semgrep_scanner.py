import subprocess
import json
import shutil
import os
from pathlib import Path

def semgrepScan(path="."):
    findings = []

    semgrep = (Path.home()/ ".grepsec"/ "bin"/ "semgrep"/ "bin"/ "semgrep")

    if not semgrep.exists():
        system_semgrep = shutil.which("semgrep")

        if system_semgrep:
            semgrep = Path(system_semgrep)
        else:
            print("[ERROR] Semgrep is not installed.")
            return findings

    try:
        res = subprocess.run(
            [
                str(semgrep),
                "scan",
                "--config=auto",
                "--json",
                "--quiet",
                "--exclude", "__pycache__",
                "--exclude", ".git",
                "--exclude", "venv",
                "--exclude", "node_modules",
                str(Path(path).resolve())
            ],
            capture_output=True,
            text=True,
            timeout=300
        )

        if not res.stdout.strip():
            if res.returncode not in (0, 1):
                print("[ERROR] Semgrep scan failed.")
            return findings

        data = json.loads(res.stdout)

        for i in data.get("results", []):

            finding = {
                "line_number": i["start"]["line"],
                "rule_id": i["check_id"],
                "message": i["extra"]["message"],
                "fix": i["extra"].get("fix"),
                "file_path": os.path.relpath(i["path"], path)
            }

            findings.append(finding)

        return findings

    except json.JSONDecodeError:
        print("[ERROR] Could not parse Semgrep JSON output.")
        return findings

    except subprocess.TimeoutExpired:
        print("[ERROR] Semgrep scan timed out.")
        return findings

    except Exception as e:
        print(f"[ERROR] Semgrep: {e}")
        return findings
