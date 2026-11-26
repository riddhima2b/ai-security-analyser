# 🔐 GrepSec

**An AI-powered security scanner that helps developers identify vulnerabilities, exposed secrets, and vulnerable dependencies in their codebases.**

GrepSec is a Python-based command-line security tool that combines established security scanners with optional Google Gemini AI analysis to make application security scanning more accessible to developers.

<details>
<summary>Project status</summary>

Currently published on **TestPyPI**. This is a testing release and not yet a production PyPI release.

</details>

## ✨ Features

GrepSec integrates three security scanning tools:

| Tool | Security Category | Description |
|---|---|---|
| [Semgrep](https://semgrep.dev/) | SAST | Detects potential vulnerabilities and insecure coding patterns. |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Secret Detection | Identifies exposed API keys, passwords, tokens, and credentials. |
| [OSV-Scanner](https://github.com/google/osv-scanner) | SCA | Detects known vulnerabilities in open-source dependencies. |

### What else?

- Scan local directories and remote GitHub repositories.
- Execute security scanners concurrently.
- Generate consolidated Markdown security reports.
- Optional AI-powered security analysis using Google Gemini.
- Get additional explanations and insights for detected vulnerabilities.
- Generate scanner-based reports without requiring an AI API key.

## 🛠️ Tech Stack

- Python
- Semgrep
- Gitleaks
- OSV-Scanner
- Google Gemini API
- Git

## 📦 Installation

GrepSec is currently available on **TestPyPI**.

### Prerequisites

- Python 3.10+
- Git
- pip

### Install from TestPyPI

```bash
pip install -i https://test.pypi.org/simple/ grepsec
```

If you encounter missing dependencies because TestPyPI does not host all third-party packages, install them from the regular PyPI index:

```bash
pip install --extra-index-url https://pypi.org/simple/ -i https://test.pypi.org/simple/ grepsec
```

## 🚀 Usage

GrepSec supports two scanning modes.

### 1. Standard Security Scan

AI analysis is disabled by default.

Scan the current directory:

```bash
grepsec scan
```

Scan a GitHub repository:

```bash
grepsec scan https://github.com/username/repository
```

### 2. AI-Powered Security Scan

Enable Gemini AI analysis using the `--ai` flag:

```bash
grepsec scan --ai
```


Scan a GitHub repository:

```bash
grepsec scan --ai https://github.com/username/repository
```

### Gemini API Configuration

AI analysis requires a Google Gemini API key.

Set your API key as an environment variable:

**macOS / Linux**

```bash
export GEMINI_API_KEY="your_api_key"
```

**Windows PowerShell**

```powershell
$env:GEMINI_API_KEY="your_api_key"
```

Get your API key from [Google AI Studio](https://aistudio.google.com/apikey).

**Note:**
- AI analysis is optional.
- Each user must provide their own Gemini API key.
- GrepSec does not include a shared developer API key. This is to ensure security and privacy.
- Keep your API key private and never commit it to source control.

## 🔍 How It Works

```text
             User Input
                  |
                  v
              GrepSec CLI
                  |
                  v
          Repository Setup
           /           \
      Local Path      GitHub URL
           \           /
                  |
                  v
         Parallel Security Scans
          /         |         \
      Semgrep    Gitleaks     OSV
         \          |          /
                  |
                  v
               Findings
                  |
           +------+------+
           |             |
        No AI           AI Mode
           |             |
           v             v
      Standard       Gemini AI
       Report        Analysis
           |             |
           +------+------+
                  |
                  v
          Security Report
```

## 📄 Security Reports

GrepSec generates a consolidated Markdown report containing:

- **Code Issues:** Potential vulnerabilities identified by Semgrep.
- **Leaked Secrets:** Exposed credentials detected by Gitleaks.
- **Open-Source Vulnerabilities:** Vulnerable dependencies identified by OSV-Scanner.
- **AI Analysis:** Additional explanations and security insights from Gemini when AI mode is enabled and analysis succeeds.

## 🔒 Security & Privacy

- Users provide their own Gemini API key.
- API keys should never be committed to source control.
- AI analysis is optional.
- Standard security scanning does not require a Gemini API key.

## ⚠️ Limitations

- Scanner results may contain false positives and require manual verification.
- Vulnerability detection depends on the scanner databases and supported ecosystems.
- AI-generated explanations may be inaccurate.
- A clean scan does not guarantee that a repository is completely secure.

## 🗺️ Future Improvements

- Improved vulnerability prioritization.
- Expanded programming language and framework support.
- Support for more AI Agents and models.

## 🤝 Contributing

Contributions, bug reports, and feature suggestions are welcome!

Feel free to open an issue or submit a pull request.

## 📜 License

See the repository for license information.

---

**GrepSec — Scan smarter. Build safer.**
