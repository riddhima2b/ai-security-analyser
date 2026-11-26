def generate_fallback_report(findings):

    report = [
        "# GrepSec Security Report",
        "",
        "> AI analysis unavailable. Showing automated scan results.",
        ""
    ]

    sections = {
        "Code Issues": "## 1. Code Issues (Semgrep)",
        "Leaked Secrets": "## 2. Leaked Secrets (Gitleaks)",
        "Open-Source Vulnerabilities": "## 3. Open-Source Vulnerabilities (OSV)"
    }

    for category, heading in sections.items():

        report.append(heading)
        report.append("")

        items = findings.get(category, [])

        if not items:
            report.append("No findings detected.")
        else:
            for index, item in enumerate(items, 1):
                report.append(f"### Finding {index}")

                if isinstance(item, dict):
                    for key, value in item.items():
                        report.append(f"- **{key.replace('_', ' ').title()}:** {value}")
                else:
                    report.append(f"- {item}")

                report.append("")

        report.append("")

    return "\n".join(report)