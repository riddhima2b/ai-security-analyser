from fastapi import FastAPI
from scanners.semgrep_scanner import scan
from test_gemini import analyser

app = FastAPI(title = "AI Security Vulnerability Analyser")

@app.get("/")
def root():
    return {"message": "Welcome to the AI Security Vulnerability Analyser API!"}

path = input("Enter the path to scan: ")

findings = scan(path)

if not findings:
    print("No issues found")
    exit()

ai_response = analyser(findings)

print(ai_response)