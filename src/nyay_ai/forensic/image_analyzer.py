"""
NYAYAI - Forensic Image Analyzer
Module Lead: Anu Sharma (Forensic & AI Analysis Engineer)

Provides non-destructive image inspection including:
- Image format
- Dimensions
- Color mode
- EXIF metadata
- SHA-256 evidence hash
- Basic tamper indicators

The original evidence file is opened read-only and is never modified.
"""

from typing import Dict, Any
import hashlib

from PIL import Image, ExifTags


class ForensicImageAnalyzer:
    """
    Non-destructive forensic image inspection engine.
    """

    def calculate_sha256(self, file_path: str) -> str:
        """
        Calculate SHA-256 hash of the original evidence file.

        The file is read in binary mode and is never modified.
        """

        sha256 = hashlib.sha256()

        with open(file_path, "rb") as file:
            for chunk in iter(lambda: file.read(65536), b""):
                sha256.update(chunk)

        return sha256.hexdigest()

    def extract_exif(self, image: Image.Image) -> Dict[str, Any]:
        """
        Extract available EXIF metadata from an image.
        """

        exif_data: Dict[str, Any] = {}

        try:
            raw_exif = image.getexif()

            for tag_id, value in raw_exif.items():
                tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))

                try:
                    exif_data[tag_name] = str(value)
                except Exception:
                    exif_data[tag_name] = repr(value)

        except Exception:
            return {}

        return exif_data

    def detect_tamper_indicators(
        self,
        image: Image.Image,
        exif_metadata: Dict[str, Any],
    ) -> list:
        """
        Detect basic indicators that may warrant further forensic review.

        These are indicators only and do not prove that an image was tampered.
        """

        indicators = []

        # Indicator 1: Image has no EXIF metadata.
        if not exif_metadata:
            indicators.append(
                "No EXIF metadata found; metadata may have been removed "
                "or the image may have been exported without EXIF."
            )

        # Indicator 2: JPEG image without common camera metadata.
        if image.format == "JPEG" and exif_metadata:
            camera_tags = {
                "Make",
                "Model",
                "DateTimeOriginal",
                "LensModel",
            }

            if not any(tag in exif_metadata for tag in camera_tags):
                indicators.append(
                    "JPEG contains EXIF data but no common camera metadata "
                    "was found."
                )

        # Indicator 3: Unusual image dimensions.
        if image.width < 32 or image.height < 32:
            indicators.append(
                "Very small image dimensions detected; further review "
                "may be required."
            )

        return indicators

    def analyze(self, file_path: str) -> Dict[str, Any]:
        """
        Perform non-destructive forensic inspection of an image.
        """

        try:
            file_hash = self.calculate_sha256(file_path)

            with Image.open(file_path) as image:

                exif_metadata = self.extract_exif(image)

                tamper_indicators = self.detect_tamper_indicators(
                    image,
                    exif_metadata,
                )

                return {
                    "analysis_type": "image",
                    "format": image.format,
                    "width": image.width,
                    "height": image.height,
                    "mode": image.mode,
                    "sha256": file_hash,
                    "has_exif": bool(exif_metadata),
                    "exif_metadata": exif_metadata,
                    "tamper_indicators": tamper_indicators,
                    "anomalies": tamper_indicators,
                }

        except FileNotFoundError:
            raise FileNotFoundError(
                f"Evidence image not found: {file_path}"
            )

        except Exception as exc:
            return {
                "analysis_type": "image",
                "format": None,
                "width": None,
                "height": None,
                "mode": None,
                "sha256": None,
                "has_exif": False,
                "exif_metadata": {},
                "tamper_indicators": [],
                "anomalies": [
                    f"Unable to analyze image: {str(exc)}"
                ],
            }
