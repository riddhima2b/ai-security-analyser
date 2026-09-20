import subprocess
import json
from google import genai
import os
from dotenv import load_dotenv


def scan(path):
    
    findings = []

    res = subprocess.run(
        ["semgrep", "scan", "--config=auto","--json", path], capture_output=True, text=True
        )

    data = json.loads(res.stdout)

    for i in data.get('results', []):

        finding = {
            "line_number": i['start']['line'],
            "rule_id": i['check_id'],
            "message": i['extra']['message'],
            "fix": i['extra'].get('fix'),
            "impact": i['extra']['metadata']['impact'],
            "file_path": i['path']
        }
        findings.append(finding)
    return findings
