from PIL import Image

from nyay_ai.forensic.image_analyzer import ForensicImageAnalyzer


def test_image_analyzer(tmp_path):
    analyzer = ForensicImageAnalyzer()

    image_path = tmp_path / "test_image.jpg"

    image = Image.new("RGB", (100, 100))
    image.save(image_path)

    result = analyzer.analyze(str(image_path))

    assert result["analysis_type"] == "image"
    assert result["format"] == "JPEG"
    assert result["width"] == 100
    assert result["height"] == 100
    assert result["mode"] == "RGB"
    assert result["has_exif"] is False


def test_sha256_hash_is_generated(tmp_path):
    analyzer = ForensicImageAnalyzer()

    image_path = tmp_path / "hash_test.jpg"

    image = Image.new("RGB", (100, 100))
    image.save(image_path)

    result = analyzer.analyze(str(image_path))

    assert result["sha256"] is not None
    assert len(result["sha256"]) == 64


def test_tamper_indicators_field_exists(tmp_path):
    analyzer = ForensicImageAnalyzer()

    image_path = tmp_path / "tamper_test.jpg"

    image = Image.new("RGB", (100, 100))
    image.save(image_path)

    result = analyzer.analyze(str(image_path))

    assert "tamper_indicators" in result
    assert isinstance(result["tamper_indicators"], list)


def test_missing_exif_creates_indicator(tmp_path):
    analyzer = ForensicImageAnalyzer()

    image_path = tmp_path / "no_exif.jpg"

    image = Image.new("RGB", (100, 100))
    image.save(image_path)

    result = analyzer.analyze(str(image_path))

    assert result["has_exif"] is False
    assert len(result["tamper_indicators"]) >= 1


def test_small_image_creates_indicator(tmp_path):
    analyzer = ForensicImageAnalyzer()

    image_path = tmp_path / "small_image.jpg"

    image = Image.new("RGB", (16, 16))
    image.save(image_path)

    result = analyzer.analyze(str(image_path))

    assert any(
        "small image dimensions" in indicator.lower()
        for indicator in result["tamper_indicators"]
    )


def test_original_evidence_is_not_modified(tmp_path):
    analyzer = ForensicImageAnalyzer()

    image_path = tmp_path / "original.jpg"

    image = Image.new("RGB", (100, 100))
    image.save(image_path)

    original_hash = analyzer.calculate_sha256(str(image_path))

    analyzer.analyze(str(image_path))

    final_hash = analyzer.calculate_sha256(str(image_path))

    assert original_hash == final_hash
