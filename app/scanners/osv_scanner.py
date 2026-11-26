import subprocess
import json
import shutil
from pathlib import Path

def osv_scan(path="."):

    findings = []
    osv_scanner = Path.home() / ".grepsec" / "bin" / "osv-scanner"
    if not osv_scanner.exists():
        system_scanner = shutil.which("osv-scanner")

        if system_scanner:
            osv_scanner = Path(system_scanner)
        else:
            print("OSV Scanner is not installed.")
            return findings
    try:
        result = subprocess.run(
            [
                str(osv_scanner),
                "scan",
                "source",
                str(Path(path).resolve()),
                "--recursive",
                "--format=json"
            ],
            capture_output=True,
            text=True,
            timeout=300
        )

    except subprocess.TimeoutExpired:
        print("[ERROR] OSV Scanner timed out.")
        return findings

    except OSError:
        print("[ERROR] Could not execute OSV Scanner.")
        return findings

    # Parse JSON even if the scanner returned a non-zero exit code.
    # A non-zero exit code can also indicate discovered vulnerabilities.
    if not result.stdout.strip():
        return findings

    try:
        osv_data = json.loads(result.stdout)

        unique_findings = {}
        for result in osv_data.get("results", []):

            for package_data in result.get("packages", []):

                for vulnerability in package_data.get("vulnerabilities", []):

                    key = (
                        package_data["package"]["name"],
                        package_data["package"]["version"],
                        vulnerability["id"],
                        vulnerability.get("summary"),
                    )
                    if key not in unique_findings:
                        unique_findings[key] = {
                        "package_name": package_data["package"]["name"],
                        "version": package_data["package"]["version"],
                        "ecosystem": package_data["package"]["ecosystem"],
                        "summary": vulnerability.get("summary"),
                        "fixed_versions": []
                    }
                        
                    for affected_range in vulnerability.get("affected", []):

                        for range_item in affected_range.get("ranges", []):

                            for event in range_item.get("events", []):

                                fixed = event.get("fixed")

                                if (fixed and fixed not in unique_findings[key]["fixed_versions"]):
                                    unique_findings[key]["fixed_versions"].append(fixed)

        findings = list(unique_findings.values())

        return findings
    
    except json.JSONDecodeError:
        print("Could not parse OSV JSON output")
        print("stdout:", osv_data.stdout)
        print("stderr:", osv_data.stderr)

    return findings