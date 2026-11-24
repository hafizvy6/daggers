from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

try:
    from PIL import Image, ImageDraw, ImageFont  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - evidence generation degrades to bundled JPGs
    Image = None  # type: ignore[assignment]
    ImageDraw = None  # type: ignore[assignment]
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
    if not index_path.exists():
        return []
    try:
        data = json.loads(index_path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def best_match(image_path: Path, gallery: Iterable[dict], threshold: int = 12) -> dict | None:
    if Image is None or not Path(image_path).exists():
        return None
    try:
        with Image.open(image_path) as opened:
            query_hash = perceptual_hash(opened.convert("RGB"))
    except OSError:
        return None
    best: dict | None = None
    for entry in gallery:
        distance = hamming(query_hash, str(entry.get("phash", "")))
        candidate = {
            "entry": entry,
            "distance": distance,
            "similarity": round(max(0.0, (64 - distance) / 64 * 100), 1),
        }
        if best is None or distance < best["distance"]:
            best = candidate
    return best if best and best["distance"] < threshold else None


def create_official_reference(brand: dict | str, view: str = "desktop", size: tuple[int, int] = (640, 420)):
    """A clean, projector-readable reference page used for the gallery and evidence panels."""
    if Image is None or ImageDraw is None:
        return None
    token = str(brand.get("token", "brand")) if isinstance(brand, dict) else str(brand)
    official = str(brand.get("official_domain", f"{token}.ae")) if isinstance(brand, dict) else f"{token}.ae"
    width, height = size
    image = Image.new("RGB", size, PAPER)
    draw = ImageDraw.Draw(image)
    title_font = load_font(26 if width >= 500 else 20, bold=True)
    body_font = load_font(16 if width >= 500 else 13)
    small_font = load_font(13 if width >= 500 else 11, bold=True)
    draw.rectangle((10, 10, width - 10, height - 10), fill=SURFACE, outline=INK, width=3)
    draw.rectangle((10, 10, width - 10, 62 if width >= 500 else 48), fill=ACCENT_TINT, outline=INK, width=3)
    draw.text((28, 24), "OFFICIAL REFERENCE", fill=ACCENT, font=small_font)
    draw.text((28, 78 if width >= 500 else 60), token.upper(), fill=INK, font=title_font)
    draw.text((28, 116 if width >= 500 else 90), official, fill=MUTED, font=body_font)
    form_top = 160 if width >= 500 else 125
    form_bottom = min(height - 36, form_top + 190)
    draw.rounded_rectangle((28, form_top, width - 28, form_bottom), radius=6, fill=PAPER, outline=INK, width=2)
    draw.text((48, form_top + 22), "Secure customer sign in", fill=INK, font=body_font)
    for index, label in enumerate(("Customer ID", "One-time passcode")):
        y = form_top + 64 + index * 52
        draw.rectangle((48, y, width - 48, y + 34), fill=SURFACE, outline=MUTED, width=1)
        draw.text((60, y + 9), label, fill=MUTED, font=small_font)
    button_y = min(form_bottom - 46, form_top + 144)
    draw.rectangle((48, button_y, min(width - 48, 210), button_y + 34), fill=ACCENT, outline=INK, width=2)
    draw.text((82, button_y + 8), "CONTINUE", fill=SURFACE, font=small_font)
    draw.text((28, height - 30), f"{view.upper()} · deterministic gallery fixture", fill=MUTED, font=small_font)
    return image


def generate_gallery_images(
    brands: Iterable[dict],
    image_dir: Path,
    index_path: Path,
    *,
    count: int = 30,
) -> list[dict]:
    """Build 60 offline reference shots and their precomputed perceptual hashes.

    A broken local FreeType/Pillow build, missing font, or unwritable runtime
    directory must never break cold start: the committed index remains the
    source of truth for the offline demo.
    """
    if Image is None:
        return load_gallery(index_path)
    try:
        image_dir.mkdir(parents=True, exist_ok=True)
        selected = list(brands)[:count]
        entries: list[dict] = []
        for brand in selected:
            token = str(brand.get("token", "brand"))
            official = str(brand.get("official_domain", f"{token}.ae"))
            for view, size in (("desktop", (640, 420)), ("mobile", (360, 640))):
                image = create_official_reference(brand, view, size)
                assert image is not None
                filename = f"{token}_{view}.jpg"
                image.save(image_dir / filename, "JPEG", quality=88)
                entries.append(
                    {
                        "id": f"{token}-{view}",
                        "brand": token,
                        "official_domain": official,
                        "url": f"{official}/{'login' if view == 'desktop' else 'home'}",
                        "view": view,
                        "phash": perceptual_hash(image),
                        "path": f"gallery/{filename}",
                    }
                )
        index_path.parent.mkdir(parents=True, exist_ok=True)
        index_path.write_text(json.dumps(entries, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return entries
    except Exception:
        return load_gallery(index_path)
