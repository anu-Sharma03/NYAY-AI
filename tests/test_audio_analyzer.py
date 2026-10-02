import wave

from nyay_ai.forensic.audio_analyzer import ForensicAudioAnalyzer


def create_test_wav(file_path):
    """
    Create a small valid WAV file for testing.
    """

    sample_rate = 8000
    channels = 1
    sample_width = 2
    duration_seconds = 1

    total_frames = sample_rate * duration_seconds

    audio_data = b"\x00\x00" * total_frames

    with wave.open(str(file_path), "wb") as audio_file:
        audio_file.setnchannels(channels)
        audio_file.setsampwidth(sample_width)
        audio_file.setframerate(sample_rate)
        audio_file.writeframes(audio_data)


def test_audio_analyzer(tmp_path):
    analyzer = ForensicAudioAnalyzer()

    audio_path = tmp_path / "test.wav"

    create_test_wav(audio_path)

    result = analyzer.analyze(str(audio_path))

    assert result["analysis_type"] == "audio"
    assert result["format"] == ".wav"
    assert result["sha256"] is not None
    assert len(result["sha256"]) == 64
    assert result["duration_seconds"] == 1.0
    assert result["sample_rate"] == 8000
    assert result["channels"] == 1
    assert result["sample_width_bytes"] == 2


def test_audio_tamper_indicators_field_exists(tmp_path):
    analyzer = ForensicAudioAnalyzer()

    audio_path = tmp_path / "indicator.wav"

    create_test_wav(audio_path)

    result = analyzer.analyze(str(audio_path))

    assert "tamper_indicators" in result
    assert isinstance(result["tamper_indicators"], list)


def test_audio_sha256_is_stable(tmp_path):
    analyzer = ForensicAudioAnalyzer()

    audio_path = tmp_path / "hash.wav"

    create_test_wav(audio_path)

    first_hash = analyzer.calculate_sha256(str(audio_path))
    second_hash = analyzer.calculate_sha256(str(audio_path))

    assert first_hash == second_hash
    assert len(first_hash) == 64


def test_audio_evidence_is_not_modified(tmp_path):
    analyzer = ForensicAudioAnalyzer()

    audio_path = tmp_path / "original.wav"

    create_test_wav(audio_path)

    original_hash = analyzer.calculate_sha256(str(audio_path))

    analyzer.analyze(str(audio_path))

    final_hash = analyzer.calculate_sha256(str(audio_path))

    assert original_hash == final_hash


def test_missing_audio_file(tmp_path):
    analyzer = ForensicAudioAnalyzer()

    audio_path = tmp_path / "missing.wav"

    try:
        analyzer.analyze(str(audio_path))
        assert False, "Expected FileNotFoundError"
    except FileNotFoundError:
        assert True
