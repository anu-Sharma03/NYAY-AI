"""
NYAYAI - Forensic Video Analyzer
Module Lead: Anu Sharma (Forensic & AI Analysis Engineer)

Provides non-destructive video inspection including:
- SHA-256 evidence hash
- Video format
- Frame count
- Frame rate
- Duration
- Resolution

The original evidence file is opened read-only and is never modified.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any, Dict

import cv2


class ForensicVideoAnalyzer:
    """
    Non-destructive forensic video inspection engine.
    """

    CHUNK_SIZE = 65536

    def calculate_sha256(self, file_path: str) -> str:
        """
        Calculate SHA-256 hash of the video evidence file.
        """

        sha256 = hashlib.sha256()

        with open(file_path, "rb") as file:
            for chunk in iter(
                lambda: file.read(self.CHUNK_SIZE),
                b"",
            ):
                sha256.update(chunk)

        return sha256.hexdigest()

    def analyze(self, file_path: str) -> Dict[str, Any]:
        """
        Perform non-destructive forensic inspection of a video.
        """

        if not os.path.exists(file_path):
            raise FileNotFoundError(
                f"Evidence video not found: {file_path}"
            )

        try:
            file_hash = self.calculate_sha256(file_path)

            capture = cv2.VideoCapture(file_path)

            if not capture.isOpened():
                return {
                    "analysis_type": "video",
                    "format": os.path.splitext(file_path)[1].lower(),
                    "sha256": file_hash,
                    "frame_count": None,
                    "fps": None,
                    "duration_seconds": None,
                    "width": None,
                    "height": None,
                    "tamper_indicators": [
                        "Video could not be opened for metadata analysis."
                    ],
                }

            frame_count = int(
                capture.get(cv2.CAP_PROP_FRAME_COUNT)
            )

            fps = float(
                capture.get(cv2.CAP_PROP_FPS)
            )

            width = int(
                capture.get(cv2.CAP_PROP_FRAME_WIDTH)
            )

            height = int(
                capture.get(cv2.CAP_PROP_FRAME_HEIGHT)
            )

            capture.release()

            duration_seconds = (
                frame_count / fps
                if fps > 0
                else None
            )

            tamper_indicators = []

            if fps <= 0:
                tamper_indicators.append(
                    "Invalid or unavailable video frame rate detected."
                )

            if frame_count <= 0:
                tamper_indicators.append(
                    "No video frames were detected."
                )

            if width <= 0 or height <= 0:
                tamper_indicators.append(
                    "Invalid or unavailable video resolution detected."
                )

            return {
                "analysis_type": "video",
                "format": os.path.splitext(file_path)[1].lower(),
                "sha256": file_hash,
                "frame_count": frame_count,
                "fps": fps,
                "duration_seconds": duration_seconds,
                "width": width,
                "height": height,
                "tamper_indicators": tamper_indicators,
            }

        except Exception as exc:
            return {
                "analysis_type": "video",
                "format": os.path.splitext(file_path)[1].lower(),
                "sha256": None,
                "frame_count": None,
                "fps": None,
                "duration_seconds": None,
                "width": None,
                "height": None,
                "tamper_indicators": [
                    f"Unable to analyze video: {str(exc)}"
                ],
            }
