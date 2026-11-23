import subprocess
import json
import os
def semgrepScan(path):
    findings = []
    try:
         
        res = subprocess.run(
            ["semgrep", "scan", "--config=auto","--json", 
            "--exclude", "__pycache__",
            "--exclude", ".git",
            "--exclude", "venv",
            "--exclude", "node_modules",
            path], capture_output=True, text=True
                )
        if res.returncode != 0:
            print("Error running semgrep:", res.stderr)
            return findings

    

        data = json.loads(res.stdout)
        

        for i in data.get('results', []):

                finding = {
                    "line_number": i['start']['line'],
                    "rule_id": i['check_id'],
                    "message": i['extra']['message'],
                    "fix": i['extra'].get('fix'),
                    "file_path": os.path.relpath(i["path"], path)
                }
                findings.append(finding)
        return findings
    except json.JSONDecodeError:
        print("Could not parse Semgrep JSON output")
        return findings
    except Exception as e:
        print("Error running Semgrep:", str(e))
        return findings
