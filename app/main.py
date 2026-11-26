import json
from scanners.semgrep_scanner import semgrepScan
from scanners.gitleaks_scanner import gitLeaksScan
from scanners.osv_scanner import osv_scan
from test_gemini import analyser, generate_fallback_report
from cloner import clone_repo
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import shutil 


def scan_repo_path(source="."):
    cloned = None

    if Path(source).expanduser().is_dir():
        repo_path = str(Path(source).expanduser().resolve())
    else:
        cloned = clone_repo(source)
        if cloned is None:
            raise RuntimeError("Repository cloning failed.")

        if not cloned:
            raise RuntimeError("Unable to clone repository")

        repo_path = cloned

    try:
        findings = {
            "Code Issues": ["None found"],
            "Leaked Secrets": ["None found"],
            "Open-Source Vulnerabilities": ["None found"]
        }
        with ThreadPoolExecutor(max_workers=3) as executor:

            semgrep_future = executor.submit(semgrepScan, repo_path)
            secrets_future = executor.submit(gitLeaksScan, repo_path)
            osv_future = executor.submit(osv_scan, repo_path)

            findings = {
                "Code Issues": semgrep_future.result(),
                "Leaked Secrets": secrets_future.result(),
                "Open-Source Vulnerabilities": osv_future.result()
            }

        if not any(findings.values()):
            report = "# GrepSec Security Report\n\nNo security issues found."

        else:
            ai_response = analyser(findings)

            if ai_response and ai_response.get("analysis"):
                report = ai_response["analysis"]

            else:
                report = generate_fallback_report(findings)

        with open("ai_report.md", "w", encoding="utf-8") as file:
            file.write(report)

        print("Analysis report saved to ai_report.md")

        return findings

    finally:
        if cloned:
            shutil.rmtree(cloned, ignore_errors=True)
