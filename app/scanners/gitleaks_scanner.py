import subprocess
import os
import tempfile
import json
import shutil 
temp_dir = tempfile.mkdtemp()
report_path = os.path.join(temp_dir, "report.json")
repo = input("Enter the repo: ")
subprocess.run(["git","clone", repo, temp_dir], capture_output=True, text=True)

result = subprocess.run([
    "betterleaks", "detect", "--source", temp_dir, 
     "--report-format", "json",
        "--report-path", report_path, 
        "-v"], capture_output=True, text=True
)

with open(report_path) as f:
    findings = json.load(f)

print(json.dumps(findings, indent=2))
shutil.rmtree(temp_dir)
