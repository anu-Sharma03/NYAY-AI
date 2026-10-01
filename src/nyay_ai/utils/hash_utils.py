"""Hashing utilities for NYAY-AI."""

import hashlib


def calculate_sha256(file_path: str) -> str:
    """Compute a file SHA-256 hash in streaming chunks."""
    digest = hashlib.sha256()
    with open(file_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()
