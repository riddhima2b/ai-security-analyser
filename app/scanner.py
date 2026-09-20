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

# if res.returncode != 0:
#     print("Semgrep error:")
#     print(res.stderr)
#     exit()

    data = json.loads(res.stdout)

# if(not data['results']):
#     print("No issues found")
#     exit()

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




# ai_response = interaction.output_text
# ai_results = json.loads(ai_response)

# for finding, ai in zip(findings, ai_results):
#     ai['file_path'] = finding['file_path']
#     ai['line_number'] = finding['line_number']
#     ai['likelihood'] = finding['likelihood']
#     ai['impact'] = finding['impact']

# print(json.dumps(ai_results, indent=2))