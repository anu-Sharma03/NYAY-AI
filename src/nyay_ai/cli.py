"""CLI entry point for NYAY-AI forensic analyzer."""

import argparse

from nyay_ai.forensic.file_analyzer import FileForensicAnalyzer


def main() -> None:
    """Run forensic analysis on a given file."""
    parser = argparse.ArgumentParser(description="NYAY-AI forensic analyzer")
    parser.add_argument("file_path", help="Path to the evidence file")
    parser.add_argument(
        "--declared-mime",
        default="application/octet-stream",
        help="Declared MIME type",
    )
    args = parser.parse_args()

    analyzer = FileForensicAnalyzer()
    print("SHA-256:", analyzer.calculate_sha256(args.file_path))
    print("Metadata:", analyzer.extract_metadata(args.file_path))
    print(
        "Signature check:",
        analyzer.verify_file_signature(args.file_path, args.declared_mime),
    )


if __name__ == "__main__":
    main()
