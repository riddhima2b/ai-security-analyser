from fastapi import FastAPI
from scanners.semgrep_scanner import semgrepScan
from scanners.gitleaks_scanner import gitLeaksScan
from scanners.osv_scanner import osv_scan
from test_gemini import analyser
from cloner import clone_repo
import shutil 
app = FastAPI(title = "AI Security Vulnerability Analyser")

@app.get("/")
def root():
    return {"message": "Welcome to the AI Security Vulnerability Analyser API!"}

path = input("Enter the repo to scan: ")

cloned = clone_repo(path)
findings = {
    "semgrep":semgrepScan(cloned),
    "secrets": gitLeaksScan(cloned),
    "osv": osv_scan(cloned)
    }

if not any(findings.values()):
    print("No issues found")
    exit()

ai_response = analyser(findings)

print(ai_response)
shutil.rmtree(cloned)