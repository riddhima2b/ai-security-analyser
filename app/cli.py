
import argparse
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

    scan_parser = subparsers.add_parser("scan")

    scan_parser.add_argument(
        "source",
        nargs="?",
        default="."
    )

    args = parser.parse_args()

    if args.command == "scan":
        try:
            scan_repo_path(args.source)
        except (ValueError, RuntimeError) as e:
            parser.error(str(e))


if __name__ == "__main__":
    main()
