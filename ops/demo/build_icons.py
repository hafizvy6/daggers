#!/usr/bin/env python3
"""Daggers icons — flat dagger-in-shield mark. 192/512 + maskable."""
import pathlib
from PIL import Image, ImageDraw

OUT = pathlib.Path(__file__).resolve().parents[2] / "web/icons"
OUT.mkdir(parents=True, exist_ok=True)
PAPER = (250, 247, 241)
INK = (38, 38, 46)
ACCENT = (15, 118, 110)
ACCENT_TINT = (227, 241, 239)

def mark(size, pad_ratio=0.12, bg=PAPER, radius_ratio=0.22):
    S = size * 4  # supersample
    im = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    r = int(S * radius_ratio)
    d.rounded_rectangle([0, 0, S - 1, S - 1], radius=r, fill=bg)
    p = int(S * pad_ratio)
    w = S - 2 * p
    # shield outline (ink, thick) with teal tint fill
    top = p
    bot = p + w
    midx = S / 2
    inset = w * 0.08
    shield = [
        (midx, top),
        (p + w - inset, top + w * 0.16),
        (p + w - inset, top + w * 0.56),
        (midx, bot),
        (p + inset, top + w * 0.56),
        (p + inset, top + w * 0.16),
    ]
    lw = max(6, int(S * 0.045))
    d.polygon(shield, fill=ACCENT_TINT, outline=INK, width=lw)
    # dagger: blade (teal), guard + pommel (ink)
    cx = midx
    blade_top = top + w * 0.20
    blade_bot = top + w * 0.68
    bw = w * 0.085
    d.polygon([(cx - bw, blade_top), (cx + bw, blade_top), (cx, blade_bot)], fill=ACCENT)
    d.line([(cx, blade_top), (cx, blade_bot)], fill=INK, width=max(3, int(S * 0.012)))
    guard_y = blade_top + w * 0.045
    gw = w * 0.20
    d.line([(cx - gw, guard_y), (cx + gw, guard_y)], fill=INK, width=max(6, int(S * 0.032)))
    ph = w * 0.075
    d.line([(cx, blade_top - ph), (cx, blade_top)], fill=INK, width=max(5, int(S * 0.026)))
    d.ellipse([cx - w * 0.035, blade_top - ph - w * 0.035, cx + w * 0.035, blade_top - ph + w * 0.035], fill=ACCENT, outline=INK, width=max(3, int(S * 0.014)))
    return im.resize((size, size), Image.LANCZOS)

mark(192).save(OUT / "icon-192.png")
mark(512).save(OUT / "icon-512.png")
mark(512, pad_ratio=0.24, radius_ratio=0.0).save(OUT / "maskable-512.png")  # safe zone, full bleed
mark(180).save(OUT / "apple-touch-icon.png")
print("icons written:", [p.name for p in sorted(OUT.glob('*.png'))])
