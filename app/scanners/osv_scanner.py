import subprocess
import json
import os
import tempfile
import shutil

def osv_scan(path):

    findings = []

    # report_file = tempfile.NamedTemporaryFile(
    #     suffix=".json",
    #     delete=False
    # )
    # report_file.close()
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

    # Check whether scanner execution failed
    if osv_data.returncode != 0:
        print("OSV Scanner exited with:", osv_data.returncode)
        print("stderr:", osv_data.stderr)
    if not osv_data.stdout.strip():
            return findings

    try:
        osv_data = json.loads(osv_data.stdout)

        for result in osv_data.get('results', []):

            for package_data in result.get('packages', []):

                for vulnerability in package_data.get("vulnerabilities", []):

                    for affected_range in vulnerability.get("affected", []):

                        for range_item in affected_range.get("ranges", []):

                            fixed_versions = [
                                event["fixed"]
                                for event in range_item.get("events", [])
                                if "fixed" in event
                            ]

                            findings.append({
                                "package_name": package_data["package"]["name"],
                                "version": package_data["package"]["version"],
                                "ecosystem": package_data["package"]["ecosystem"],
                                "vulnerability_id": vulnerability["id"],
                                "summary": vulnerability.get("summary"),
                                "fixed_version": fixed_versions[0] if fixed_versions else None,
                            })
        if not findings:
            print("No OSV vulnerabilities found")
    except json.JSONDecodeError:
        print("Could not parse OSV JSON output")
        print("stdout:", osv_data.stdout)
        print("stderr:", osv_data.stderr)

    return findings