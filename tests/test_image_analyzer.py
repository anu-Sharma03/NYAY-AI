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
