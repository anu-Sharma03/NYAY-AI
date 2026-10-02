"""
NYAYAI - Forensic Audio Analyzer
Module Lead: Anu Sharma (Forensic & AI Analysis Engineer)

Provides non-destructive audio inspection including:
- SHA-256 evidence hash
- Audio format
- Duration
- Sample rate
- Channel count
- Basic forensic indicators

The original evidence file is opened read-only and is never modified.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any, Dict

from pydub import AudioSegment


class ForensicAudioAnalyzer:
    """
    Non-destructive forensic audio inspection engine.
    """

    CHUNK_SIZE = 65536

    def calculate_sha256(self, file_path: str) -> str:
        """
        Calculate SHA-256 hash of the audio evidence file.
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
        Perform non-destructive forensic inspection of an audio file.
        """

        if not os.path.exists(file_path):
            raise FileNotFoundError(
                f"Evidence audio not found: {file_path}"
            )

        try:
            file_hash = self.calculate_sha256(file_path)

            audio = AudioSegment.from_file(file_path)

            duration_seconds = len(audio) / 1000.0
            sample_rate = audio.frame_rate
            channels = audio.channels

            tamper_indicators = []

            if duration_seconds <= 0:
                tamper_indicators.append(
                    "Audio duration is zero or unavailable."
                )

            if sample_rate <= 0:
                tamper_indicators.append(
                    "Invalid or unavailable audio sample rate detected."
                )

            if channels <= 0:
                tamper_indicators.append(
                    "Invalid or unavailable audio channel information."
                )

            return {
                "analysis_type": "audio",
                "format": os.path.splitext(file_path)[1].lower(),
                "sha256": file_hash,
                "duration_seconds": duration_seconds,
                "sample_rate": sample_rate,
                "channels": channels,
                "sample_width_bytes": audio.sample_width,
                "tamper_indicators": tamper_indicators,
            }

        except Exception as exc:
            return {
                "analysis_type": "audio",
                "format": os.path.splitext(file_path)[1].lower(),
                "sha256": None,
                "duration_seconds": None,
                "sample_rate": None,
                "channels": None,
                "sample_width_bytes": None,
                "tamper_indicators": [
                    f"Unable to analyze audio: {str(exc)}"
                ],
            }
