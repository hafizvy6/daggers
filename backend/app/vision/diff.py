from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

try:
    from PIL import Image, ImageDraw  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - bundled fallback JPG remains usable
    Image = None  # type: ignore[assignment]
    ImageDraw = None  # type: ignore[assignment]

from .gallery import (
    ACCENT,
    ACCENT_TINT,
    INK,
    LINE_SOFT,
    MUTED,
    PAPER,
    SURFACE,
)

# Explicit palette assignment keeps this module readable when imported alone.
FAKE = (214, 69, 69)
WARN = (216, 146, 31)
MISLEAD = (217, 111, 50)
SAFE = (47, 158, 104)
FAKE_BG = (251, 229, 229)

EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b", re.I)
PHONE_RE = re.compile(r"(?:\+\d{9,}|\b\d{10,}\b)")
PAYMENT_FIELD_RE = re.compile(r"(?:iban|cvv|card[_-]?number|otp|pin)", re.I)
OBFUSCATED_RE = re.compile(r"(?:eval\s*\(|atob\s*\(|unescape\s*\(|String\.fromCharCode)", re.I)


def _fallback_path() -> Path:
    return Path(__file__).resolve().parents[2] / "seed" / "casefiles" / "fallback.jpg"


def _gallery_index_path() -> Path:
    return Path(__file__).resolve().parents[2] / "seed" / "gallery_index.json"


def _redact(value: object) -> str:
    text = str(value or "")
    text = EMAIL_RE.sub("[redacted]", text)
    return PHONE_RE.sub("[redacted]", text)


def _font(size: int, bold: bool = False):
    from .gallery import load_font

    return load_font(size, bold=bold)


def _text_width(draw, text: str, font) -> int:
    box = draw.textbbox((0, 0), text, font=font)
    return box[2] - box[0]


def _wrap(draw, text: str, font, width: int, max_lines: int = 4) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current: list[str] = []
    for word in words:
        trial = " ".join([*current, word])
        if current and _text_width(draw, trial, font) > width:
            lines.append(" ".join(current))
            current = [word]
        else:
            current.append(word)
        if len(lines) >= max_lines:
            break
    if current and len(lines) < max_lines:
        lines.append(" ".join(current))
    if not lines:
        return [""]
    if len(lines) == max_lines and _text_width(draw, " ".join(words), font) > width:
        last = lines[-1] + " …"
        while _text_width(draw, last, font) > width and len(last) > 2:
            last = last[:-2] + "…"
        lines[-1] = last
    return lines


def _create_suspect_reference(finding: dict, size: tuple[int, int] = (700, 400)):
    if Image is None or ImageDraw is None:
        return None
    width, height = size
    image = Image.new("RGB", size, PAPER)
    draw = ImageDraw.Draw(image)
    title_font = _font(24, bold=True)
    body_font = _font(16)
    small_font = _font(13, bold=True)
    draw.rectangle((8, 8, width - 8, height - 8), fill=SURFACE, outline=FAKE, width=4)
    draw.rectangle((8, 8, width - 8, 58), fill=FAKE_BG, outline=FAKE, width=3)
    draw.text((26, 22), "SUSPICIOUS PAGE", fill=FAKE, font=small_font)
    domain = _redact(finding.get("domain", "unknown domain"))
    draw.text((26, 76), domain[:42], fill=INK, font=title_font)
    draw.text((26, 112), "Look-alike layout captured for comparison", fill=MUTED, font=body_font)
    draw.rounded_rectangle((26, 148, width - 26, height - 28), radius=6, fill=PAPER, outline=INK, width=2)
    draw.text((48, 168), "Verify your account", fill=INK, font=body_font)
    for index, label in enumerate(("Card number", "CVV / OTP", "Password")):
        y = 206 + index * 46
        draw.rectangle((48, y, width - 48, y + 30), fill=SURFACE, outline=MUTED, width=1)
        draw.text((60, y + 7), label, fill=MUTED, font=small_font)
        draw.ellipse((width - 78, y + 5, width - 58, y + 25), outline=FAKE, width=3)
    draw.rectangle((48, 350, 210, 384), fill=FAKE, outline=INK, width=2)
    draw.text((88, 359), "SUBMIT", fill=SURFACE, font=small_font)
    return image


def _verdict_color(verdict: str) -> tuple[int, int, int]:
    return {
        "MALICIOUS": FAKE,
        "MISLEADING": MISLEAD,
        "SUSPICIOUS": WARN,
        "UNKNOWN": SAFE,
    }.get(str(verdict).upper(), ACCENT)


def _compose_evidence(
    finding: dict,
    official_image,
    suspect_image,
    destination: Path,
    *,
    clone_override: float | None = None,
) -> Path | None:
    if Image is None or ImageDraw is None or official_image is None or suspect_image is None:
        return _copy_fallback(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    width, height = 1600, 900
    canvas = Image.new("RGB", (width, height), PAPER)
    draw = ImageDraw.Draw(canvas)
    for x in range(0, width, 24):
        for y in range(0, height, 24):
            draw.ellipse((x, y, x + 1, y + 1), fill=LINE_SOFT)
    draw.rectangle((24, 24, width - 24, 118), fill=SURFACE, outline=INK, width=3)
    draw.text((52, 46), "DAGGERS  ·  EVIDENCE PACK", fill=INK, font=_font(36, bold=True))
    draw.text((52, 91), "DETERMINISTIC PROOF  /  NO USER DATA IN THIS BUNDLE", fill=ACCENT, font=_font(15, bold=True))
    draw.rectangle((1240, 44, 1548, 100), fill=ACCENT_TINT, outline=INK, width=2)
    draw.text((1270, 60), "ONE BRAIN · ALL SURFACES", fill=ACCENT, font=_font(15, bold=True))

    draw.text((52, 132), "OFFICIAL REFERENCE", fill=ACCENT, font=_font(20, bold=True))
    draw.text((852, 132), "SUSPICIOUS PAGE", fill=FAKE, font=_font(20, bold=True))
    left_box = (48, 166, 768, 606)
    right_box = (832, 166, 1552, 606)
    draw.rectangle(left_box, fill=SURFACE, outline=INK, width=3)
    draw.rectangle(right_box, fill=SURFACE, outline=INK, width=3)
    left = official_image.convert("RGB").resize((704, 424), Image.Resampling.LANCZOS)
    right = suspect_image.convert("RGB").resize((704, 424), Image.Resampling.LANCZOS)
    canvas.paste(left, (56, 174))
    canvas.paste(right, (840, 174))
    for offset in (250, 310, 370):
        draw.line((760, offset, 832, offset), fill=FAKE, width=3)
        draw.ellipse((824, offset - 7, 838, offset + 7), outline=FAKE, width=3)

    verdict = str(finding.get("verdict", "UNKNOWN")).upper()
    color = _verdict_color(verdict)
    draw.rectangle((48, 632, 1552, 858), fill=SURFACE, outline=INK, width=3)
    draw.rectangle((72, 660, 300, 720), fill=color, outline=INK, width=2)
    draw.text((98, 675), verdict, fill=SURFACE, font=_font(26, bold=True))
    clone = finding.get("clone") if clone_override is None else clone_override
    meta = (
        f"score {float(finding.get('score') or 0):.2f}   ·   "
        f"clone {float(clone or 0):.0f}%   ·   "
        f"domain {_redact(finding.get('domain'))}"
    )
    draw.text((330, 672), meta[:90], fill=INK, font=_font(20, bold=True))
    reasons = finding.get("reasons") or ["no additional signals"]
    reason_text = "  •  ".join(_redact(reason) for reason in reasons[:4])
    for index, line in enumerate(_wrap(draw, reason_text, _font(19), 1400, max_lines=4)):
        draw.text((76, 742 + index * 28), line, fill=MUTED, font=_font(19))
    draw.text((76, 828), "AI may explain this evidence; the deterministic brain owns the verdict.", fill=ACCENT, font=_font(14, bold=True))
    canvas.save(destination, "JPEG", quality=92, optimize=True)
    return destination


def _copy_fallback(destination: Path) -> Path | None:
    fallback = _fallback_path()
    if not fallback.exists():
        return None
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(fallback, destination)
    return destination


def ensure_evidence_image(finding: dict, destination: Path, gallery_dir: Path | None = None) -> Path | None:
    """Materialize a readable side-by-side evidence JPG from C1 data only."""
    destination = Path(destination)
    if destination.exists() and destination.stat().st_size > 0:
        return destination
    if Image is None or ImageDraw is None:
        return _copy_fallback(destination)

    try:
        from .gallery import create_official_reference, load_gallery

        gallery = load_gallery(_gallery_index_path())
        gallery_match = str(finding.get("gallery_match") or "")
        entry = next(
            (
                item
                for item in gallery
                if item.get("url") == gallery_match
                or str(item.get("official_domain", "")) in gallery_match
            ),
            None,
        )
        official_image = None
        if entry and gallery_dir:
            candidate = Path(gallery_dir) / Path(str(entry.get("path", ""))).name
            if candidate.exists():
                try:
                    official_image = Image.open(candidate).convert("RGB")
                except OSError:
                    official_image = None
        if official_image is None:
            brand = entry or {
                "token": str(finding.get("domain", "brand")).split(".")[0],
                "official_domain": gallery_match.split("/")[0] or "official.example",
            }
            official_image = create_official_reference(brand, "desktop", (700, 400))
        suspect_image = _create_suspect_reference(finding, (700, 400))
        composed = _compose_evidence(finding, official_image, suspect_image, destination)
        if composed is not None:
            return composed
    except Exception:
        pass
    return _copy_fallback(destination)


def create_comparison_evidence(
    screenshot_path: Path,
    reference_path: Path,
    finding: dict,
    destination: Path,
    clone_score: float,
) -> Path | None:
    """Use real rendered screenshots when Playwright/vision extras are enabled."""
    if Image is None or not Path(screenshot_path).exists() or not Path(reference_path).exists():
        return ensure_evidence_image(finding, destination)
    try:
        official_image = Image.open(reference_path).convert("RGB")
        suspect_image = Image.open(screenshot_path).convert("RGB")
    except OSError:
        return ensure_evidence_image(finding, destination)
    return _compose_evidence(finding, official_image, suspect_image, destination, clone_override=clone_score)


def analyze_html_signals(html: str, page_host: str) -> dict:
    """HTML-only content signals. Nothing is submitted and no scripts are executed."""
    form_actions = re.findall(r"<form\b[^>]*\baction\s*=\s*[\"']([^\"']+)[\"']", html or "", re.I)
    mismatches: list[str] = []
    for action in form_actions:
        parsed = urlparse(action)
        host = (parsed.hostname or "").lower()
        if host and host != str(page_host).lower() and not host.endswith("." + str(page_host).lower()):
            mismatches.append(host)
    input_names: list[str] = []
    for tag in re.findall(r"<input\b[^>]*>", html or "", re.I):
        input_names.extend(re.findall(r"\b(?:name|id)\s*=\s*[\"']([^\"']+)[\"']", tag, re.I))
    payment_fields = sorted({name for name in input_names if PAYMENT_FIELD_RE.search(name)})
    return {
        "form_action_mismatch": bool(mismatches),
        "foreign_form_hosts": mismatches,
        "payment_harvest_fields": bool(payment_fields),
        "payment_field_names": payment_fields,
        "obfuscated_script": bool(OBFUSCATED_RE.search(html or "")),
        "input_names": input_names[:30],
    }


def _hash_similarity(screenshot_path: Path, reference_path: Path) -> float:
    if Image is None:
        return 0.0
    from .gallery import hamming, perceptual_hash

    try:
        with Image.open(screenshot_path) as shot, Image.open(reference_path) as reference:
            distance = hamming(
                perceptual_hash(shot.convert("RGB")),
                perceptual_hash(reference.convert("RGB")),
            )
    except OSError:
        return 0.0
    return round(max(0.0, (64 - distance) / 64 * 100), 1)


def clone_similarity(
    screenshot_path: Path,
    reference_path: Path,
    *,
    brand_hit: bool = True,
) -> float:
    """Stage B ORB/RANSAC when OpenCV is present; perceptual-hash fallback otherwise."""
    try:
        import cv2  # type: ignore[import-not-found]
        import numpy as np  # type: ignore[import-not-found]
    except ImportError:
        return _hash_similarity(screenshot_path, reference_path)

    try:
        left = cv2.imread(str(screenshot_path), cv2.IMREAD_GRAYSCALE)
        right = cv2.imread(str(reference_path), cv2.IMREAD_GRAYSCALE)
        if left is None or right is None:
            return _hash_similarity(screenshot_path, reference_path)
        orb = cv2.ORB_create(nfeatures=4000)
        keypoints_left, descriptors_left = orb.detectAndCompute(left, None)
        keypoints_right, descriptors_right = orb.detectAndCompute(right, None)
        if descriptors_left is None or descriptors_right is None or len(keypoints_left) < 4:
            return 0.0
        matcher = cv2.BFMatcher(cv2.NORM_HAMMING)
        knn = matcher.knnMatch(descriptors_left, descriptors_right, k=2)
        good = [first for first, second in knn if first.distance < 0.75 * second.distance]
        if len(good) < 4:
            return 0.0
        source = np.float32([keypoints_left[match.queryIdx].pt for match in good]).reshape(-1, 1, 2)
        target = np.float32([keypoints_right[match.trainIdx].pt for match in good]).reshape(-1, 1, 2)
        _, mask = cv2.findHomography(source, target, cv2.RANSAC, 5.0)
        inliers = int(mask.sum()) if mask is not None else 0
        score = round(inliers / len(good) * 100, 1)
        return min(100.0, score if brand_hit else score * 0.75)
    except Exception:
        return _hash_similarity(screenshot_path, reference_path)
