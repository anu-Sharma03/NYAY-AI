"""Unit tests for FileForensicAnalyzer."""

import os
import tempfile
import unittest

from nyay_ai.forensic.file_analyzer import FileForensicAnalyzer


class TestFileForensicAnalyzer(unittest.TestCase):
    """Test suite for forensic file analysis."""

    def setUp(self) -> None:
        """Create a temporary test file."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_file = os.path.join(self.temp_dir.name, "test.txt")
        with open(self.test_file, "w") as f:
            f.write("Test evidence data")
        self.analyzer = FileForensicAnalyzer()

    def tearDown(self) -> None:
        """Clean up temporary files."""
        self.temp_dir.cleanup()

    def test_calculate_sha256(self) -> None:
        """Test SHA-256 calculation."""
        hash_result = self.analyzer.calculate_sha256(self.test_file)
        self.assertEqual(len(hash_result), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in hash_result))

    def test_extract_metadata(self) -> None:
        """Test metadata extraction."""
        metadata = self.analyzer.extract_metadata(self.test_file)
        self.assertIn("file_name", metadata)
        self.assertIn("file_size_bytes", metadata)
        self.assertIn("sha256", metadata)
        self.assertEqual(metadata["file_name"], "test.txt")

    def test_verify_file_signature(self) -> None:
        """Test file signature verification."""
        result = self.analyzer.verify_file_signature(self.test_file, "text/plain")
        self.assertIn("declared_mime", result)
        self.assertIn("detected_mime", result)
        self.assertIn("matches_declared_mime", result)

    def test_nonexistent_file(self) -> None:
        """Test handling of nonexistent files."""
        with self.assertRaises(FileNotFoundError):
            self.analyzer.calculate_sha256("/nonexistent/file.txt")
                def test_png_signature_matches_declared_mime(self) -> None:
        """Test that a PNG signature matches image/png."""
        file_path = os.path.join(self.temp_dir.name, "test.png")

        png_signature = b"\x89PNG\r\n\x1a\n"

        with open(file_path, "wb") as f:
            f.write(png_signature + b"\x00" * 100)

        result = self.analyzer.verify_file_signature(
            file_path,
            "image/png",
        )

        self.assertEqual(result["detected_mime"], "image/png")
        self.assertEqual(result["declared_mime"], "image/png")
        self.assertTrue(result["matches_declared_mime"])


    def test_pdf_signature_matches_declared_mime(self) -> None:
        """Test that a PDF signature matches application/pdf."""
        file_path = os.path.join(self.temp_dir.name, "test.pdf")

        pdf_signature = b"%PDF-1.7\n"

        with open(file_path, "wb") as f:
            f.write(pdf_signature + b"\x00" * 100)

        result = self.analyzer.verify_file_signature(
            file_path,
            "application/pdf",
        )

        self.assertEqual(result["detected_mime"], "application/pdf")
        self.assertEqual(result["declared_mime"], "application/pdf")
        self.assertTrue(result["matches_declared_mime"])


    def test_mime_mismatch_is_detected(self) -> None:
        """Test detection of extension/MIME spoofing."""
        file_path = os.path.join(self.temp_dir.name, "fake.jpg")

        pdf_signature = b"%PDF-1.7\n"

        with open(file_path, "wb") as f:
            f.write(pdf_signature + b"\x00" * 100)

        result = self.analyzer.verify_file_signature(
            file_path,
            "image/jpeg",
        )

        self.assertEqual(result["declared_mime"], "image/jpeg")
        self.assertEqual(result["detected_mime"], "application/pdf")
        self.assertFalse(result["matches_declared_mime"])


    def test_signature_contains_magic_bytes(self) -> None:
        """Test that magic bytes are returned as hexadecimal."""
        file_path = os.path.join(self.temp_dir.name, "test.png")

        png_signature = b"\x89PNG\r\n\x1a\n"

        with open(file_path, "wb") as f:
            f.write(png_signature + b"\x00" * 100)

        result = self.analyzer.verify_file_signature(
            file_path,
            "image/png",
        )

        self.assertTrue(
            result["magic_bytes_hex"].startswith(
                "89504e470d0a1a0a"
            )
        )


    def test_missing_file_signature_raises_error(self) -> None:
        """Test that missing evidence raises FileNotFoundError."""
        file_path = os.path.join(
            self.temp_dir.name,
            "missing.jpg",
        )

        with self.assertRaises(FileNotFoundError):
            self.analyzer.verify_file_signature(
                file_path,
                "image/jpeg",
            )


if __name__ == "__main__":
    unittest.main()


"""Unit tests for FileForensicAnalyzer."""

import os
import tempfile
import unittest

from nyay_ai.forensic.file_analyzer import FileForensicAnalyzer


class TestFileForensicAnalyzer(unittest.TestCase):
    """Test suite for forensic file analysis."""

    def setUp(self) -> None:
        """Create a temporary test file."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_file = os.path.join(self.temp_dir.name, "test.txt")
        with open(self.test_file, "w") as f:
            f.write("Test evidence data")
        self.analyzer = FileForensicAnalyzer()

    def tearDown(self) -> None:
        """Clean up temporary files."""
        self.temp_dir.cleanup()

    def test_calculate_sha256(self) -> None:
        """Test SHA-256 calculation."""
        hash_result = self.analyzer.calculate_sha256(self.test_file)
        self.assertEqual(len(hash_result), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in hash_result))

    def test_extract_metadata(self) -> None:
        """Test metadata extraction."""
        metadata = self.analyzer.extract_metadata(self.test_file)
        self.assertIn("file_name", metadata)
        self.assertIn("file_size_bytes", metadata)
        self.assertIn("sha256", metadata)
        self.assertEqual(metadata["file_name"], "test.txt")

    def test_verify_file_signature(self) -> None:
        """Test file signature verification."""
        result = self.analyzer.verify_file_signature(self.test_file, "text/plain")
        self.assertIn("declared_mime", result)
        self.assertIn("detected_mime", result)
        self.assertIn("matches_declared_mime", result)

    def test_nonexistent_file(self) -> None:
        """Test handling of nonexistent files."""
        with self.assertRaises(FileNotFoundError):
            self.analyzer.calculate_sha256("/nonexistent/file.txt")
                def test_png_signature_matches_declared_mime(self) -> None:
        """Test that a PNG signature matches image/png."""
        file_path = os.path.join(self.temp_dir.name, "test.png")

        png_signature = b"\x89PNG\r\n\x1a\n"

        with open(file_path, "wb") as f:
            f.write(png_signature + b"\x00" * 100)

        result = self.analyzer.verify_file_signature(
            file_path,
            "image/png",
        )

        self.assertEqual(result["detected_mime"], "image/png")
        self.assertEqual(result["declared_mime"], "image/png")
        self.assertTrue(result["matches_declared_mime"])


    def test_pdf_signature_matches_declared_mime(self) -> None:
        """Test that a PDF signature matches application/pdf."""
        file_path = os.path.join(self.temp_dir.name, "test.pdf")

        pdf_signature = b"%PDF-1.7\n"

        with open(file_path, "wb") as f:
            f.write(pdf_signature + b"\x00" * 100)

        result = self.analyzer.verify_file_signature(
            file_path,
            "application/pdf",
        )

        self.assertEqual(result["detected_mime"], "application/pdf")
        self.assertEqual(result["declared_mime"], "application/pdf")
        self.assertTrue(result["matches_declared_mime"])


    def test_mime_mismatch_is_detected(self) -> None:
        """Test detection of extension/MIME spoofing."""
        file_path = os.path.join(self.temp_dir.name, "fake.jpg")

        pdf_signature = b"%PDF-1.7\n"

        with open(file_path, "wb") as f:
            f.write(pdf_signature + b"\x00" * 100)

        result = self.analyzer.verify_file_signature(
            file_path,
            "image/jpeg",
        )

        self.assertEqual(result["declared_mime"], "image/jpeg")
        self.assertEqual(result["detected_mime"], "application/pdf")
        self.assertFalse(result["matches_declared_mime"])


    def test_signature_contains_magic_bytes(self) -> None:
        """Test that magic bytes are returned as hexadecimal."""
        file_path = os.path.join(self.temp_dir.name, "test.png")

        png_signature = b"\x89PNG\r\n\x1a\n"

        with open(file_path, "wb") as f:
            f.write(png_signature + b"\x00" * 100)

        result = self.analyzer.verify_file_signature(
            file_path,
            "image/png",
        )

        self.assertTrue(
            result["magic_bytes_hex"].startswith(
                "89504e470d0a1a0a"
            )
        )


    def test_missing_file_signature_raises_error(self) -> None:
        """Test that missing evidence raises FileNotFoundError."""
        file_path = os.path.join(
            self.temp_dir.name,
            "missing.jpg",
        )

        with self.assertRaises(FileNotFoundError):
            self.analyzer.verify_file_signature(
                file_path,
                "image/jpeg",
            )


if __name__ == "__main__":
    unittest.main()


```python
"""Unit tests for FileForensicAnalyzer."""

import os
import tempfile
import unittest

from nyay_ai.forensic.file_analyzer import FileForensicAnalyzer


class TestFileForensicAnalyzer(unittest.TestCase):
    """Test suite for forensic file analysis."""

    def setUp(self) -> None:
        """Create a temporary test file."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_file = os.path.join(self.temp_dir.name, "test.txt")

        with open(self.test_file, "w") as f:
            f.write("Test evidence data")

        self.analyzer = FileForensicAnalyzer()

    def tearDown(self) -> None:
        """Clean up temporary files."""
        self.temp_dir.cleanup()

    def test_calculate_sha256(self) -> None:
        """Test SHA-256 calculation."""
        hash_result = self.analyzer.calculate_sha256(self.test_file)

        self.assertEqual(len(hash_result), 64)
        self.assertTrue(
            all(c in "0123456789abcdef" for c in hash_result)
        )

    def test_extract_metadata(self) -> None:
        """Test metadata extraction."""
        metadata = self.analyzer.extract_metadata(self.test_file)

        self.assertIn("file_name", metadata)
        self.assertIn("file_size_bytes", metadata)
        self.assertIn("sha256", metadata)
        self.assertEqual(metadata["file_name"], "test.txt")

    def test_verify_file_signature(self) -> None:
        """Test file signature verification."""
        result = self.analyzer.verify_file_signature(
            self.test_file,
            "text/plain",
        )

        self.assertIn("declared_mime", result)
        self.assertIn("detected_mime", result)
        self.assertIn("matches_declared_mime", result)

    def test_nonexistent_file(self) -> None:
        """Test handling of nonexistent files."""
        with self.assertRaises(FileNotFoundError):
            self.analyzer.calculate_sha256(
                "/nonexistent/file.txt"
            )

    def test_png_signature_matches_declared_mime(self) -> None:
        """Test that a PNG signature matches image/png."""
        file_path = os.path.join(
            self.temp_dir.name,
            "test.png",
        )

        png_signature = b"\x89PNG\r\n\x1a\n"

        with open(file_path, "wb") as f:
            f.write(png_signature + b"\x00" * 100)

        result = self.analyzer.verify_file_signature(
            file_path,
            "image/png",
        )

        self.assertEqual(
            result["detected_mime"],
            "image/png",
        )
        self.assertEqual(
            result["declared_mime"],
            "image/png",
        )
        self.assertTrue(
            result["matches_declared_mime"]
        )

    def test_pdf_signature_matches_declared_mime(self) -> None:
        """Test that a PDF signature matches application/pdf."""
        file_path = os.path.join(
            self.temp_dir.name,
            "test.pdf",
        )

        pdf_signature = b"%PDF-1.7\n"

        with open(file_path, "wb") as f:
            f.write(pdf_signature + b"\x00" * 100)

        result = self.analyzer.verify_file_signature(
            file_path,
            "application/pdf",
        )

        self.assertEqual(
            result["detected_mime"],
            "application/pdf",
        )
        self.assertEqual(
            result["declared_mime"],
            "application/pdf",
        )
        self.assertTrue(
            result["matches_declared_mime"]
        )

    def test_mime_mismatch_is_detected(self) -> None:
        """Test detection of extension/MIME spoofing."""
        file_path = os.path.join(
            self.temp_dir.name,
            "fake.jpg",
        )

        pdf_signature = b"%PDF-1.7\n"

        with open(file_path, "wb") as f:
            f.write(pdf_signature + b"\x00" * 100)

        result = self.analyzer.verify_file_signature(
            file_path,
            "image/jpeg",
        )

        self.assertEqual(
            result["declared_mime"],
            "image/jpeg",
        )
        self.assertEqual(
            result["detected_mime"],
            "application/pdf",
        )
        self.assertFalse(
            result["matches_declared_mime"]
        )

    def test_signature_contains_magic_bytes(self) -> None:
        """Test that magic bytes are returned as hexadecimal."""
        file_path = os.path.join(
            self.temp_dir.name,
            "test.png",
        )

        png_signature = b"\x89PNG\r\n\x1a\n"

        with open(file_path, "wb") as f:
            f.write(png_signature + b"\x00" * 100)

        result = self.analyzer.verify_file_signature(
            file_path,
            "image/png",
        )

        self.assertTrue(
            result["magic_bytes_hex"].startswith(
                "89504e470d0a1a0a"
            )
        )

    def test_missing_file_signature_raises_error(self) -> None:
        """Test that missing evidence raises FileNotFoundError."""
        file_path = os.path.join(
            self.temp_dir.name,
            "missing.jpg",
        )

        with self.assertRaises(FileNotFoundError):
            self.analyzer.verify_file_signature(
                file_path,
                "image/jpeg",
            )


if __name__ == "__main__":
    unittest.main()
```
