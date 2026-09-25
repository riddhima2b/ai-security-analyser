import subprocess 
import json
import os
import tempfile
import shutil
import pandas as pd
repo = input("Enter the repository : ")
temp_dir = tempfile.mkdtemp()
findings = []
subprocess.run(["git", "clone", repo, temp_dir], capture_output=True, text=True)


osv_data = subprocess.run(["osv-scanner", "scan", "source" ,temp_dir, "--recursive", "--format=json"], capture_output=True, text=True)
osv_data = json.loads(osv_data.stdout)

for result in osv_data.get('results', []):

    for package_data in result.get('packages', []):

        for vulnerability in package_data.get("vulnerabilities", []):
            fixed_version = None
            for affected_range in vulnerability.get("affected", []):
                for range_item in affected_range.get("ranges", []):
                    if range_item.get("type") == "ECOSYSTEM":
                        for event in range_item.get("events", []):
                            if "fixed" in event:
                                fixed_version = event["fixed"]
                                break
            findings.append({
                "package_name": package_data["package"]["name"],
                "version": package_data["package"]["version"],
                "ecosystem": package_data["package"]["ecosystem"],
                "vulnerability_id": vulnerability["id"],
                "summary": vulnerability.get("summary"),
                "fixed_version": fixed_version
            })
print(json.dumps(findings, indent=4))
shutil.rmtree(temp_dir)