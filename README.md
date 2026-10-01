# NYAY-AI

NYAY-AI is a forensic analysis framework for preserving evidence integrity, validating file authenticity, and extracting metadata without modifying original evidence.

## Principles

- Never overwrite original evidence files.
- Use SHA-256 for deterministic integrity verification.
- Extract metadata, filesystem timestamps, and header attributes.
- Validate file signatures against declared MIME types.
- Avoid forensic certainty without evidence.

## Project structure

```text
NYAY-AI/
├── README.md
├── pyproject.toml
├── .gitignore
├── src/
│   └── nyay_ai/
│       ├── __init__.py
│       ├── cli.py
│       ├── core/
│       │   ├── __init__.py
│       │   └── base_analyzer.py
│       ├── forensic/
│       │   ├── __init__.py
│       │   └── file_analyzer.py
│       └── utils/
│           ├── __init__.py
│           ├── hash_utils.py
│           ├── metadata_utils.py
│           └── signature_utils.py
└── tests/
    └── test_file_analyzer.py
```

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\\Scripts\\Activate.ps1
pip install -e .
```

## Example usage

```python
from nyay_ai.forensic.file_analyzer import FileForensicAnalyzer

analyzer = FileForensicAnalyzer()
print(analyzer.calculate_sha256("evidence/incident.jpg"))
print(analyzer.extract_metadata("evidence/incident.jpg"))
print(analyzer.verify_file_signature("evidence/incident.jpg", "image/jpeg"))
```

## License

This project is distributed under the MIT License.
