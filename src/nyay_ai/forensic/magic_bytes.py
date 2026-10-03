```python
"""Magic-byte validation helpers."""


def detect_mime_from_magic(header: bytes) -> str:
    """Detect MIME type based on a common header signature."""
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if header.startswith(b"\xFF\xD8\xFF"):
        return "image/jpeg"
    if header.startswith(b"GIF87a") or header.startswith(b"GIF89a"):
        return "image/gif"
    if header.startswith(b"PK\x03\x04"):
        return "application/zip"
    if header.startswith(b"%PDF-"):
        return "application/pdf"
    return "application/octet-stream"
```
