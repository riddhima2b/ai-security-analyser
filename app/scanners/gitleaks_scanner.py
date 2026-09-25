import subprocess
import os
import tempfile
import json

def gitLeaksScan(path):
    findings = []
    report_file = tempfile.NamedTemporaryFile(
        suffix=".json",
        delete=False
    )
    report_path = report_file.name
    report_file.close()


    try:
        result = subprocess.run([
            "gitleaks", "detect", "--source", path, 
            "--report-format", "json",
                "--report-path", report_path, 
                "-v"], capture_output=True, text=True
        )
        if result.returncode not in(0,1):
            print("Error running gitleaks:", result.stderr)
            return findings
        if not os.path.exists(report_path):
            return findings
        with open(report_path, "r") as f:
            result = json.load(f)

        for finding in result:
            findings.append({
                "rule_id": finding.get("RuleID"),
                "description": finding.get("Description"),
                "file_path": finding.get("File"),
                "line_number": finding.get("StartLine"),
                "fix": "Rotate the credentials and remove the file from the codebase. "
                "You may also use git-filter repo to remove the file from the git history.",
            })
    except json.JSONDecodeError:
        print("Could not parse Gitleaks JSON output")
        return findings
    except Exception as e:
        print("Error running Gitleaks:", str(e))
        return findings
    finally:
        if os.path.exists(report_path):
            os.remove(report_path)
    return findings