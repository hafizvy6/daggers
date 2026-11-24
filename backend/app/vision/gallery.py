from __future__ import annotations

import json
from pathlib import Path

try:
    from PIL import Image, ImageFont  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - evidence composition degrades to None
    Image = None  # type: ignore[assignment]
    ImageFont = None  # type: ignore[assignment]

PAPER = (250, 247, 241)
SURFACE = (255, 255, 255)
INK = (38, 38, 46)
MUTED = (107, 107, 120)
ACCENT = (15, 118, 110)
ACCENT_TINT = (227, 241, 239)
LINE_SOFT = (231, 225, 215)

FONT_CANDIDATES = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/liberation2/LiberationSans-Bold.ttf",
    "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf",
)


def load_font(size: int, bold: bool = False):
    """Load a font for real evidence captions; degrade cleanly if FreeType is broken."""
    if ImageFont is None:
        return None
    candidates = FONT_CANDIDATES if bold else FONT_CANDIDATES[::-1]
    for candidate in candidates:
        if Path(candidate).exists():
            try:
                return ImageFont.truetype(candidate, size=size)
            except Exception:
                continue
    try:
        return ImageFont.load_default(size=size)
    except Exception:
        pass
    try:
        return ImageFont.load_default()
    except Exception:
        return None


def perceptual_hash(image) -> str:
    """imagehash.phash when available; a deterministic 64-bit average hash otherwise."""
    if Image is None:
        return "0" * 16
    try:
        import imagehash  # type: ignore[import-not-found]

        return str(imagehash.phash(image))
    except Exception:
        gray = image.convert("L").resize((8, 8), Image.Resampling.LANCZOS)
        pixels = list(gray.getdata())
        average = sum(pixels) / len(pixels)
        bits = "".join("1" if pixel > average else "0" for pixel in pixels)
        return f"{int(bits, 2):016x}"


def hamming(left: str, right: str) -> int:
    try:
        return (int(str(left), 16) ^ int(str(right), 16)).bit_count()
    except (TypeError, ValueError):
        return 64


def load_gallery(index_path: Path) -> list[dict]:
    """Optional operator-supplied index of real reference captures."""
    if not index_path.exists():
        return []
    try:
        data = json.loads(index_path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []
