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


if __name__ == "__main__":
    unittest.main()
