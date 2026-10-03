"""Unit tests for magic-byte MIME detection."""

import unittest

from nyay_ai.forensic.magic_bytes import detect_mime_from_magic


class TestMagicBytes(unittest.TestCase):
    """Test common file signature detection."""

    def test_png_signature(self) -> None:
        """Detect PNG files from their magic bytes."""
        header = b"\x89PNG\r\n\x1a\n" + b"test"
        self.assertEqual(detect_mime_from_magic(header), "image/png")

    def test_jpeg_signature(self) -> None:
        """Detect JPEG files from their magic bytes."""
        header = b"\xFF\xD8\xFF" + b"test"
        self.assertEqual(detect_mime_from_magic(header), "image/jpeg")

    def test_gif_signature(self) -> None:
        """Detect GIF files from their magic bytes."""
        header = b"GIF89a" + b"test"
        self.assertEqual(detect_mime_from_magic(header), "image/gif")

    def test_zip_signature(self) -> None:
        """Detect ZIP files from their magic bytes."""
        header = b"PK\x03\x04" + b"test"
        self.assertEqual(
            detect_mime_from_magic(header),
            "application/zip",
        )

    def test_pdf_signature(self) -> None:
        """Detect PDF files from their magic bytes."""
        header = b"%PDF-1.7" + b"test"
        self.assertEqual(
            detect_mime_from_magic(header),
            "application/pdf",
        )

    def test_elf_signature(self) -> None:
        """Detect ELF executable files from their magic bytes."""
        header = b"\x7FELF" + b"test"
        self.assertEqual(
            detect_mime_from_magic(header),
            "application/x-executable",
        )

    def test_mz_signature(self) -> None:
        """Detect Windows executable files from their magic bytes."""
        header = b"MZ" + b"test"
        self.assertEqual(
            detect_mime_from_magic(header),
            "application/x-msdownload",
        )

    def test_unknown_signature(self) -> None:
        """Return a generic MIME type for unknown signatures."""
        header = b"UNKNOWN"
        self.assertEqual(
            detect_mime_from_magic(header),
            "application/octet-stream",
        )


if __name__ == "__main__":
    unittest.main()
