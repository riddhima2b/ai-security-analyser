import tempfile
import subprocess
from urllib.parse import urlparse


def clone_repo(repo_url: str):
    parsed = urlparse(repo_url)

    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.port not in (None, 443)
    ):
        raise ValueError("Only valid HTTPS repository URLs are allowed.")

    temp_dir = tempfile.mkdtemp()

    try:
        clone = subprocess.run(
            ["git", "clone", "--", repo_url, temp_dir],
            capture_output=True,
            text=True,
            timeout=300
        )

        if clone.returncode != 0:
            print("Error cloning the repository:", clone.stderr)
            return None

        return temp_dir

    except Exception as e:
        print("An error occurred while cloning the repository:", str(e))
        return None
