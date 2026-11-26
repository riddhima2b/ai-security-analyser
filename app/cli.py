import argparse
import getpass
import os

from main import scan_repo_path

def main():

    parser = argparse.ArgumentParser(
        prog="grepsec",
        description="AI-powered security scanner"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True
    )

    # Security scan
    scan_parser = subparsers.add_parser("scan")

    scan_parser.add_argument(
        "source",
        nargs="?",
        default="."
    )
    scan_parser.add_argument(
        "--ai",
        action="store_true",
        help="Enable Gemini AI analysis"
    )

    subparsers.add_parser("ai")

    args = parser.parse_args()

    if args.command == "scan":

        if args.command == "scan":
            try:
                if args.ai and not os.getenv("GEMINI_API_KEY"):
                    api_key = getpass.getpass(
                        "Enter your Gemini API key: "
                    ).strip()

                    if not api_key:
                        parser.error("API key cannot be empty.")

                    os.environ["GEMINI_API_KEY"] = api_key

                scan_repo_path(
                    args.source,
                    ai_enabled=args.ai
                )

            except (ValueError, RuntimeError) as e:
                parser.error(str(e))


if __name__ == "__main__":
    main()
