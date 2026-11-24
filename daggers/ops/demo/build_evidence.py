#!/usr/bin/env python3
"""Daggers · WS3 evidence renderer (demo assets).

Produces evidence JPEGs in the style of the vision/diff stage:
  - each half = a page screenshot mock (gallery "official" vs suspect render)
  - circled regions where the clone matches the reference
  - baked caption strip with reason chips
Files: web/evidence/<finding_id>.jpg  (also copied to backend/seed/evidence/)

Deterministic, no network. Real Stage-C renderer lives in vision/ (WS1);
these are the frozen demo case files, like plan Scenario 6b.
"""
import pathlib
from PIL import Image, ImageDraw, ImageFont

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUTS = [ROOT / "web/evidence", ROOT / "backend/seed/evidence"]
for d in OUTS:
    d.mkdir(parents=True, exist_ok=True)

# ---- palette (mirrors tokens.css) ------------------------------------
PAPER = (250, 247, 241)
SURFACE = (255, 255, 255)
INK = (38, 38, 46)
MUTED = (107, 107, 120)
LINE = (231, 225, 215)
ACCENT = (15, 118, 110)
ACCENT_TINT = (227, 241, 239)
SAFE = (47, 158, 104)
SAFE_BG = (228, 244, 235)
FAKE = (214, 69, 69)
FAKE_BG = (251, 229, 229)
WARN = (216, 146, 31)
MISLEAD = (217, 111, 50)

F = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FB = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
FM = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"

def font(path, size): return ImageFont.truetype(path, size)

def rrect(d, box, r, fill=None, outline=None, width=2):
    d.rounded_rectangle(box, radius=r, fill=fill, outline=outline, width=width)

def text(d, xy, s, f, fill=INK, anchor="la"):
    d.text(xy, s, font=f, fill=fill, anchor=anchor)

# ---- tiny vector brand marks (not real logos — stand-in shapes) -------
def mark_adcb(d, x, y, color=(0, 108, 87)):
    d.rectangle([x, y, x + 30, y + 30], fill=color)
    d.rectangle([x + 7, y + 7, x + 23, y + 23], outline=(255, 255, 255), width=3)

def mark_enbd(d, x, y, color=(0, 62, 122)):
    d.ellipse([x, y, x + 30, y + 30], fill=color, outline=None)
    d.ellipse([x + 9, y + 9, x + 21, y + 21], fill=(255, 255, 255))

def mark_aramex(d, x, y, color=(216, 30, 46)):
    d.polygon([(x, y + 28), (x + 14, y), (x + 28, y + 28)], fill=color)

def mark_police(d, x, y, color=(20, 60, 40)):
    d.rectangle([x, y, x + 30, y + 30], fill=color)
    d.polygon([(x + 15, y + 6), (x + 24, y + 12), (x + 24, y + 22), (x + 15, y + 26),
               (x + 6, y + 22), (x + 6, y + 12)], fill=(255, 255, 255))

def mark_bank(d, x, y, color=ACCENT):
    rrect(d, [x, y + 6, x + 30, y + 30], 4, fill=color)
    d.polygon([(x - 2, y + 8), (x + 32, y + 8), (x + 15, y - 4)], fill=color)

MARKS = {"adcb": mark_adcb, "enbd": mark_enbd, "aramex": mark_aramex,
         "police": mark_police, "bank": mark_bank}

def page_mock(w, h, *, title, fields, button, domain, brand, accent, fake=False):
    """One half of the evidence: a page screenshot mock."""
    im = Image.new("RGB", (w, h), SURFACE)
    d = ImageDraw.Draw(im)
    # browser chrome
    d.rectangle([0, 0, w, 34], fill=(238, 233, 224))
    d.rectangle([0, 33, w, 35], fill=LINE)
    for i, c in enumerate([(255, 107, 97), (255, 197, 84), (61, 195, 84)]):
        d.ellipse([12 + i * 18, 11, 24 + i * 18, 23], fill=c)
    # url bar
    rrect(d, [80, 7, w - 16, 28], 10, fill=(255, 255, 255), outline=LINE, width=1)
    lock = (SAFE if not fake else FAKE)
    d.ellipse([90, 14, 98, 22], outline=lock, width=2)
    f_url = font(FM, 12)
    text(d, (106, 17), domain, f_url, INK if not fake else FAKE, anchor="lm")
    # header
    d.rectangle([0, 35, w, 96], fill=accent)
    MARKS[brand](d, 22, 49, color=(255, 255, 255) if brand != "adcb" else (255, 255, 255))
    text(d, (62, 66), brand.upper() if brand != "police" else "ABU DHABI POLICE", font(FB, 17), (255, 255, 255), "lm")
    # nav dots
    for i in range(3):
        rrect(d, [w - 170 + i * 52, 58, w - 128 + i * 52, 74], 3, fill=accent)
        d.rectangle([w - 168 + i * 52, 62, w - 134 + i * 52, 70], fill=(255, 255, 255))
    # login card
    cx0, cy0, cx1, cy1 = 40, 130, w - 40, h - 74
    rrect(d, [cx0, cy0, cx1, cy1], 10, fill=SURFACE, outline=LINE, width=2)
    text(d, ((cx0 + cx1) // 2, cy0 + 34), title, font(FB, 17), INK, "mm")
    text(d, ((cx0 + cx1) // 2, cy0 + 58), "Secure access · 24/7", font(F, 13), MUTED, "mm")
    fy = cy0 + 86
    for ph in fields:
        rrect(d, [cx0 + 36, fy, cx1 - 36, fy + 40], 6, fill=(250, 250, 248), outline=INK, width=2)
        text(d, (cx0 + 50, fy + 20), ph, font(F, 13), MUTED, "lm")
        fy += 54
    # button
    btn_fill = accent
    rrect(d, [cx0 + 36, fy, cx1 - 36, fy + 46], 6, fill=btn_fill, outline=INK, width=2)
    text(d, ((cx0 + cx1) // 2, fy + 23), button, font(FB, 15), (255, 255, 255), "mm")
    # footer strip
    d.rectangle([0, h - 30, w, h], fill=(246, 242, 234))
    note = "© 2026 — all rights reserved" if not fake else "© 2026 — all rights reserved    v2.1"
    text(d, (16, h - 15), note, font(FM, 11), MUTED, "lm")
    # fake markers: sloppy details the clone got wrong
    if fake:
        # a typo and a foreign host hint in the corner
        text(d, (w - 16, h - 15), "form → collect.verify-host.top", font(FM, 10), FAKE, "rm")
    return im

def circle_matches(d, boxes, color):
    for (x0, y0, x1, y1) in boxes:
        d.ellipse([x0, y0, x1, y1], outline=color, width=4)

def build(fid, *, real, fake, brand, real_domain, fake_domain, real_accent, fake_accent,
          match_boxes, caption, clone_pct, file_name=None, fake_url_note=None):
    W_HALF, H = 640, 460
    HEAD, CAP, FOOT = 46, 34, 78
    W = W_HALF * 2 + 24
    im = Image.new("RGB", (W, HEAD + H + FOOT + CAP + 20), PAPER)
    d = ImageDraw.Draw(im)

    # header band
    d.rectangle([0, 0, W, HEAD], fill=INK)
    text(d, (18, HEAD // 2), f"EVIDENCE · FINDING #{fid}", font(FB, 16), (255, 255, 255), "lm")
    text(d, (W - 18, HEAD // 2), "DAGGERS RADAR · SIDE-BY-SIDE", font(FM, 12), (220, 215, 205), "rm")

    left = page_mock(W_HALF, H, domain=real_domain, brand=brand,
                     accent=real_accent, fake=False, **real)
    right = page_mock(W_HALF, H, domain=fake_domain, brand=brand,
                      accent=fake_accent, fake=True, **fake)
    # lens-box the matching regions on both halves
    dr = ImageDraw.Draw(right)
    circle_matches(dr, match_boxes, FAKE)
    dl = ImageDraw.Draw(left)
    circle_matches(dl, match_boxes, SAFE)

    im.paste(left, (0, HEAD))
    im.paste(right, (W_HALF + 24, HEAD))

    # half captions
    d.rectangle([0, HEAD + H, W, HEAD + H + CAP], fill=SURFACE)
    d.line([0, HEAD + H, W, HEAD + H], fill=INK, width=2)
    d.line([W // 2, HEAD + H, W // 2, HEAD + H + CAP], fill=INK, width=2)
    d.ellipse([16, HEAD + H + 11, 28, HEAD + H + 23], fill=SAFE, outline=INK, width=2)
    text(d, (38, HEAD + H + CAP // 2), "OFFICIAL", font(FB, 13), INK, "lm")
    text(d, (108, HEAD + H + CAP // 2), real_domain, font(FM, 12), MUTED, "lm")
    d.ellipse([W // 2 + 16, HEAD + H + 11, W // 2 + 28, HEAD + H + 23], fill=FAKE, outline=INK, width=2)
    text(d, (W // 2 + 38, HEAD + H + CAP // 2), "SUSPECT", font(FB, 13), INK, "lm")
    text(d, (W // 2 + 108, HEAD + H + CAP // 2), fake_domain, font(FM, 12), FAKE, "lm")

    # footer caption strip
    y0 = HEAD + H + CAP
    d.rectangle([0, y0, W, y0 + FOOT + 20], fill=SURFACE)
    d.line([0, y0, W, y0], fill=INK, width=2)
    d.rectangle([0, y0, 10, y0 + FOOT + 20], fill=FAKE)
    text(d, (24, y0 + 22), f"{clone_pct}% clone match  ·  {caption}", font(FB, 14), INK, "lm")
    sub = fake_url_note or "Forms never submitted · rendered in a locked sandbox · matches circled in red"
    text(d, (24, y0 + 46), sub, font(FM, 11), MUTED, "lm")
    rrect(d, [W - 118, y0 + 14, W - 16, y0 + 40], 4, fill=FAKE_BG, outline=FAKE, width=2)
    text(d, (W - 67, y0 + 27), "CLONE", font(FB, 12), (166, 43, 43), "mm")

    out_name = file_name or f"{fid}.jpg"
    for out in OUTS:
        im.save(out / out_name, quality=88, optimize=True)
    print("wrote", out_name)

BOXES = [(46, 216, 594, 262), (46, 270, 594, 316), (46, 378, 594, 424)]

def spec(title, fields, button):
    return dict(title=title, fields=fields, button=button)

BANK   = spec("Sign in to online banking", ["Card number", "PIN", "One-time code (OTP)"], "Sign in securely")
REFUND = spec("Request a refund", ["IBAN", "One-time code (OTP)", "Registered mobile"], "Claim my refund")
SHIP   = spec("Track your shipment", ["Tracking number", "Full name", "Card number"], "Continue to payment")
FINE   = spec("Pay your traffic fine", ["Fine number", "Card number", "Expiry & CVV"], "Pay now")
CONTACT= spec("Customer care", ["Full name", "Mobile number", "Your message"], "Send message")
GRANT  = spec("Claim your national grant", ["Full name", "Emirates ID", "Processing fee card"], "Claim 1,000,000 AED")
DEALS  = spec("Today's deals", ["Search products", "Email", "Card number"], "Add to cart")
UPGRADE= spec("Upgrade to 5G", ["Mobile number", "Emirates ID", "Confirm"], "Upgrade now")
BILL   = spec("Pay your bill", ["Account number", "Card number", "Expiry & CVV"], "Pay bill")

CASES = [
    dict(fid=42, real=BANK, fake=spec("Sign in to online banking", ["Card number", "PIN", "One-time code (OTP)"], "Sign in securely"),
         brand="adcb", real_domain="www.adcb.ae/login",
         fake_domain="adcb-secure-login.xyz/verify", real_accent=(0, 108, 87), fake_accent=(0, 108, 87),
         match_boxes=BOXES, clone_pct=97,
         caption="logo, layout, and field order identical · Arabic/English switch copied",
         fake_url_note="Clone posts card + PIN + OTP to collect.adcb-verify.top (foreign host)"),
    dict(fid=41, real=REFUND, fake=REFUND,
         brand="enbd", real_domain="www.emiratesnbd.com/refunds",
         fake_domain="emiratesnbd-refund.help/claim", real_accent=(0, 62, 122), fake_accent=(0, 62, 122),
         match_boxes=BOXES, clone_pct=94,
         caption="bank colours and headings copied · 'refund' lure added to the form",
         fake_url_note="Clone asks for IBAN and the one-time code on one page"),
    dict(fid=40, real=SHIP, fake=SHIP,
         brand="aramex", real_domain="www.aramex.com/track",
         fake_domain="aramex-delivery-fee.click/pay", real_accent=(216, 30, 46), fake_accent=(216, 30, 46),
         match_boxes=BOXES, clone_pct=89,
         caption="tracking page layout copied · 'pay 5 AED to release' form inserted",
         fake_url_note="Payment form posts to an external collector · never submit a real card"),
    dict(fid=39, real=FINE, fake=FINE,
         brand="police", real_domain="www.adpolice.gov.ae/fines",
         fake_domain="dubaipolice-fine-pay.info/pay-fine", real_accent=(20, 60, 40), fake_accent=(20, 60, 40),
         match_boxes=BOXES, clone_pct=96,
         caption="official fines layout copied · asks card + OTP on a single screen",
         fake_url_note="Government impersonation · filed P1 · registrar notified"),
    dict(fid=38, real=GRANT, fake=GRANT,
         brand="bank", real_domain="(no official page makes this claim)",
         fake_domain="cbuae-grant-1m.award/claim", real_accent=(140, 116, 80), fake_accent=(140, 116, 80),
         match_boxes=[], clone_pct=41,
         caption="no official source makes the '1 million dirham grant' claim",
         fake_url_note="Claims check: scan of official domains returned zero matches"),
    dict(fid=37, real=BANK, fake=BANK,
         brand="bank", real_domain="www.bankfab.com/online-banking",
         fake_domain="fab-online.secure-login.cc/login", real_accent=(108, 46, 130), fake_accent=(108, 46, 130),
         match_boxes=BOXES, clone_pct=92,
         caption="business banking login copied · form posts off-domain",
         fake_url_note="Foreign host form action · certificate 5 hours old"),
    dict(fid=36, real=UPGRADE, fake=UPGRADE,
         brand="bank", real_domain="www.eand.ae/personal",
         fake_domain="etisalat-5g-upgrade.site/upgrade", real_accent=(96, 96, 96), fake_accent=(96, 96, 96),
         match_boxes=BOXES[:2], clone_pct=61,
         caption="partial match — similar layout, different claims",
         fake_url_note="Collects phone numbers for a fake '5G upgrade'"),
    dict(fid=35, real=BILL, fake=BILL,
         brand="bank", real_domain="www.dewa.gov.ae/bill-payment",
         fake_domain="dewa-bill-pay.online/pay", real_accent=(0, 110, 130), fake_accent=(0, 110, 130),
         match_boxes=BOXES, clone_pct=78,
         caption="bill payment layout copied with altered wording",
         fake_url_note="Similar layout, not the real page — treat as suspicious"),
    dict(fid=34, real=CONTACT, fake=CONTACT,
         brand="adcb", real_domain="www.adcb.ae/contact-us",
         fake_domain="adcb-care.support", real_accent=(0, 108, 87), fake_accent=(0, 108, 87),
         match_boxes=[BOXES[0]], clone_pct=74,
         caption="Maps listing 'ADCB Customer Care Center' — wrong number, clone site",
         fake_url_note="Listing phone +971 2 555 0199 is not published by ADCB"),
    dict(fid=33, real=DEALS, fake=DEALS,
         brand="bank", real_domain="www.amazon.ae/deals",
         fake_domain="amazon-ae-deals.xyz/deals", real_accent=(255, 153, 0), fake_accent=(255, 153, 0),
         match_boxes=BOXES, clone_pct=77,
         caption="product page layout copied · ends in a card form",
         fake_url_note="Deals that end in a card form · URLhaus listed"),
    dict(fid=32, real=BANK, fake=BANK,
         brand="adcb", real_domain="www.adcb.ae/login",
         fake_domain="adcb.ae-verify.top/verify", real_accent=(0, 108, 87), fake_accent=(0, 108, 87),
         match_boxes=BOXES, clone_pct=90,
         caption="real address embedded inside a fake one — 'adcb.ae' + '-verify.top'",
         fake_url_note="Official domain embedded in a foreign registration"),
    dict(fid=31, real=CONTACT, fake=spec("Need help?", ["Call: +971 4 999 8877", "Hours: 24/7", "WhatsApp us"], "Call now"),
         brand="adcb", real_domain="www.adcb.ae/contact-us",
         fake_domain="adcb-care-number.info/support", real_accent=(0, 108, 87), fake_accent=(0, 108, 87),
         match_boxes=[BOXES[1]], clone_pct=38,
         caption="publishes a 'customer care' number ADCB never issued",
         fake_url_note="Unofficial support number · number pattern matches 6 reports"),
    # live-demo landing (streams in during the show)
    dict(fid=43, real=BANK, fake=BANK,
         brand="adcb", real_domain="www.adcb.ae/login",
         fake_domain="adcb-login-verify.top/login", real_accent=(0, 108, 87), fake_accent=(0, 108, 87),
         match_boxes=BOXES, clone_pct=94,
         caption="born minutes ago · login clone posts off-domain",
         fake_url_note="Certificate issued 2 minutes before detection"),
]

if __name__ == "__main__":
    for c in CASES:
        build(**c)
