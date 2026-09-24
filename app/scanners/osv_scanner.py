import subprocess 
import json
import os
import tempfile
import shutil
import pandas as pd
repo = input("Enter the repository : ")
temp_dir = tempfile.mkdtemp()

subprocess.run(["git", "clone", repo, temp_dir], capture_output=True, text=True)


osv_data = subprocess.run(["osv-scanner", "scan", "source" ,temp_dir, "--recursive", "--format=json"], capture_output=True, text=True)
osv_data = json.loads(osv_data.stdout)

for result in osv_data.get('results', []):

    for package in result.get('packages', []):

        findings = {
            "package name" : result['packages'][0]['package']["name"],
        }
#print(osv_data['results'][0]['packages'][0]['package']["name"])
# print(osv_data['results'][]['vulnerabilities'])
print(findings)
# print(json.dumps(osv_data, indent=2))
shutil.rmtree(temp_dir)