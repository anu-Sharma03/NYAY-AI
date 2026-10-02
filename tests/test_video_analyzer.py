import cv2

from nyay_ai.forensic.video_analyzer import ForensicVideoAnalyzer


def test_video_analyzer_missing_file(tmp_path):
    analyzer = ForensicVideoAnalyzer()

    video_path = tmp_path / "missing.mp4"

    try:
        analyzer.analyze(str(video_path))
        assert False, "Expected FileNotFoundError"
    except FileNotFoundError:
        assert True


def test_video_sha256_is_generated(tmp_path):
    analyzer = ForensicVideoAnalyzer()

    video_path = tmp_path / "test.mp4"

    writer = cv2.VideoWriter(
        str(video_path),
        cv2.VideoWriter_fourcc(*"mp4v"),
        10.0,
        (64, 64),
    )

    for _ in range(5):
        frame = cv2.UMat(64, 64, cv2.CV_8UC3)
        writer.write(frame.get())

    writer.release()

    result = analyzer.analyze(str(video_path))

    assert result["sha256"] is not None
    assert len(result["sha256"]) == 64


def test_video_analysis_returns_metadata(tmp_path):
    analyzer = ForensicVideoAnalyzer()

    video_path = tmp_path / "metadata.mp4"

    writer = cv2.VideoWriter(
        str(video_path),
        cv2.VideoWriter_fourcc(*"mp4v"),
        10.0,
        (64, 64),
    )

    for _ in range(10):
        frame = cv2.UMat(64, 64, cv2.CV_8UC3)
        writer.write(frame.get())

    writer.release()

    result = analyzer.analyze(str(video_path))

    assert result["analysis_type"] == "video"
    assert result["frame_count"] > 0
    assert result["fps"] > 0
    assert result["width"] == 64
    assert result["height"] == 64
    assert result["duration_seconds"] is not None


def test_video_has_tamper_indicators_field(tmp_path):
    analyzer = ForensicVideoAnalyzer()

    video_path = tmp_path / "indicator.mp4"

    writer = cv2.VideoWriter(
        str(video_path),
        cv2.VideoWriter_fourcc(*"mp4v"),
        10.0,
        (64, 64),
    )

    for _ in range(5):
        frame = cv2.UMat(64, 64, cv2.CV_8UC3)
        writer.write(frame.get())

    writer.release()

    result = analyzer.analyze(str(video_path))

    assert "tamper_indicators" in result
    assert isinstance(result["tamper_indicators"], list)
