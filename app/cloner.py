import subprocess
import tempfile
import re


def clone_repo(repo_url):
    temp_dir = tempfile.mkdtemp()

    if not re.match(r'^(https?|git)://', repo_url):
        raise ValueError("Refusing to clone non-http(s)/git URL. ")
    try:
        clone = subprocess.run(["git", "clone", repo_url, temp_dir], capture_output=True, text=True)
        if clone.returncode != 0:
            print("Error cloning the repository:", clone.stderr)
            return None
        return temp_dir
    except Exception as e:
        print("An error occurred while cloning the repository - ", str(e))
        return None
    