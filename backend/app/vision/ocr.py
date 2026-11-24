from __future__ import annotations

from pathlib import Path


def extract_text(image_path: Path, *, languages: str = "eng+ara") -> dict:
    """Optional OCR adapter. It is the first cut item and safely reports unavailability."""
    try:
        import pytesseract  # type: ignore[import-not-found]
        from PIL import Image  # type: ignore[import-not-found]
    except ImportError:
        return {"available": False, "engine": "unavailable", "text": None, "languages": languages}

    try:
        with Image.open(image_path) as image:
            text = pytesseract.image_to_string(image, lang=languages)
    except Exception as exc:
        return {"available": False, "engine": "error", "error": type(exc).__name__, "text": None}
    return {"available": True, "engine": "tesseract", "text": text.strip(), "languages": languages}
