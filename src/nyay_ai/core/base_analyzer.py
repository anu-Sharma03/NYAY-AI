"""Base forensic analyzer interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseForensicAnalyzer(ABC):
    """Abstract interface for forensic analysis engines.

    Design rules:
    - Never overwrite original evidence.
    - Use SHA-256 for evidence integrity.
    - Do not claim certainty without evidence.
    """

    @abstractmethod
    def calculate_sha256(self, file_path: str) -> str:
        """Return the SHA-256 hash of a file as a hexadecimal string."""

    @abstractmethod
    def extract_metadata(self, file_path: str) -> Dict[str, Any]:
        """Return metadata, filesystem attributes, and integrity indicators."""

    @abstractmethod
    def verify_file_signature(self, file_path: str, declared_mime: str) -> Dict[str, Any]:
        """Validate the file header against the declared MIME type."""
