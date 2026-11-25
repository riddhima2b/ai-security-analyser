from fastapi import FastAPI
import json
from scanners.semgrep_scanner import semgrepScan
from scanners.gitleaks_scanner import gitLeaksScan
from scanners.osv_scanner import osv_scan
from test_gemini import analyser
from cloner import clone_repo
from concurrent.futures import ThreadPoolExecutor

import shutil 
app = FastAPI(title = "AI Security Vulnerability Analyser")

@app.get("/")
def root():
    return {"message": "Welcome to the AI Security Vulnerability Analyser API!"}

path = input("Enter the repo to scan: ")

cloned = clone_repo(path)

findings = {}
with ThreadPoolExecutor(max_workers=3) as executor:
    semgrep_future = executor.submit(semgrepScan, cloned)
    secrets_future = executor.submit(gitLeaksScan, cloned)
    osv_future = executor.submit(osv_scan, cloned)

    findings = {
        "semgrep": semgrep_future.result(),
        "secrets": secrets_future.result(),
        "osv": osv_future.result()
    }
if not any(findings.values()):
    print("No issues found")
    exit()

ai_response = analyser(findings)
if ai_response["analysis"]:
    with open("ai_report.md", "w") as file:
        file.write(ai_response["analysis"])

else:
    with open("ai_report.md", "w") as file:
        file.write("Gemini analysis failed. Please check the findings and try again.")
        file.write(json.dumps(findings, indent=4))
    
shutil.rmtree(cloned)