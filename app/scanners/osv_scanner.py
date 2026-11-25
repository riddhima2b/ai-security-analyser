import subprocess
import json
import os
import tempfile
import shutil

def osv_scan(path):

    findings = []

    try:

        osv_data = subprocess.run(
            [
                "osv-scanner",
                "scan",
                "source",
                path,
                "--recursive",
                "--format=json"
            ],
            capture_output=True,
            text=True
        )
        

    except Exception as e:
        print("Error running OSV Scanner:", str(e))
        return findings
    except FileNotFoundError:
        print("OSV Scanner is not installed.")
        return findings

    except subprocess.TimeoutExpired:
        print("OSV Scanner timed out.")
        return findings

    except OSError as e:
        print("Error running OSV Scanner:", str(e))
        return findings

    if not osv_data.stdout.strip():
            return findings

    try:
        osv_data = json.loads(osv_data.stdout)

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