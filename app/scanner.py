import subprocess
import json
from google import genai
import os
from dotenv import load_dotenv

findings = []
path = input("Enter file or folder path : ")

res = subprocess.run(
    ["semgrep", "scan", "--config=auto","--json", path], capture_output=True, text=True
    )

if res.returncode != 0:
    print("Semgrep error:")
    print(res.stderr)
    exit()

data = json.loads(res.stdout)

if(not data['results']):
    print("No issues found")
    exit()

for i in data['results']:

    finding = {
        "line_number": i['start']['line'],
        "rule_id": i['check_id'],
        "message": i['extra']['message'],
        "fix": i['extra'].get('fix'),
        "likelihood": i['extra']['metadata']['likelihood'],
        "impact": i['extra']['metadata']['impact'],
        "file_path": i['path']
    }
    findings.append(finding)

findings_json = json.dumps(findings, indent=2)

with open("prompts/security_review.txt", "r") as f:
    prompt_format = f.read()
prompt = prompt_format.replace("{findings_json}",findings_json)

load_dotenv()
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

interaction = client.interactions.create(
    model="gemini-3.5-flash-lite",
    input=prompt
)

ai_response = interaction.output_text
ai_results = json.loads(ai_response)

for finding, ai in zip(findings, ai_results):
    ai['file_path'] = finding['file_path']
    ai['line_number'] = finding['line_number']
    ai['likelihood'] = finding['likelihood']
    ai['impact'] = finding['impact']

print(json.dumps(ai_results, indent=2))