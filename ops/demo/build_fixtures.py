#!/usr/bin/env python3
"""Daggers · WS3 fixture builder — single source of the demo narrative.

Writes the same JSON to:
  backend/seed/fixtures/   (WS1 `make seed` reads here)
  web/fixtures/            (static DEMO_MODE fallback, served by Pages)

Shapes match daggers-workstream-3-face.md §3 contracts C1–C4.
Additive, optional extension fields used by the UI (safe to drop):
  Finding.signals[]      score breakdown bars
  Finding.brand          display brand name
  Finding.maps_listing   {name, phone, website} for Maps cases (plan #11)
  Finding.verdict_note   one-line reason for the Guard page
Timestamps are authored as `age_min` offsets; web/js/api.js freshens them
at load, so the demo always looks like it happened minutes ago.
"""
import json, pathlib, shutil

ROOT = pathlib.Path(__file__).resolve().parents[2]
# web/fixtures/      → the canonical WS3 demo data (demo mode + service-worker cache)
# backend/seed/fixtures/ → ONLY the three files the brief assigns to WS3
#                          (feed · reports · status) so WS1's `make seed` can read them
OUT_ALL = ROOT / "web/fixtures"
OUT_SHARED = ROOT / "backend/seed/fixtures"
SHARED = {"feed.json", "reports.json", "status.json"}

AR_TEXT = {42: {"verdict_note_ar": "نسخة من صفحة دخول بنك أبوظبي التجاري ترسل ما تكتبه إلى خادم خارجي.", "reasons_ar": ["خطأ في اسم العلامة «adcb» (مسافة حرف واحد) على نطاق غير رسمي", "صدرت الشهادة قبل 42 دقيقة — موقع حديث الولادة", "نموذج الدخول يُرسل البيانات إلى خادم خارجي: collect.adcb-verify.top", "تطابق بصري 97% مع صفحة adcb.ae/login", "امتداد نطاق عالي الخطورة .xyz", "يطلب رقم البطاقة والرقم السري ورمز التحقق في صفحة واحدة"]}, 41: {"verdict_note_ar": "صفحة استرجاع تقلّد بنك الإمارات دبي الوطني وتطلب رقم الآيبان والرمز الذي يرسله بنكك.", "reasons_ar": ["اسم العلامة «emiratesnbd» على نطاق غير رسمي", "كلمة إغراء «refund» في العنوان", "صدرت الشهادة قبل 3 ساعات", "تطابق بصري 94% مع صفحة الاسترجاع الأصلية", "يطلب رقم الآيبان ورمز التحقق لمرة واحدة"]}, 40: {"verdict_note_ar": "صفحة «شحنتك محتجزة، ادفع 5 دراهم» — نموذج يجمع بيانات البطاقة متخفّيًا بأرامكس.", "reasons_ar": ["اسم العلامة «aramex» على نطاق غير رسمي", "كلمتا إغراء «delivery» و«fee» في العنوان", "صدرت الشهادة قبل 3 ساعات", "تطابق بصري 89% مع صفحة تتبّع أرامكس", "نموذج الدفع يُرسل البيانات إلى خادم خارجي"]}, 39: {"verdict_note_ar": "ينتحل خدمة سداد مخالفات شرطة أبوظبي لجمع بيانات البطاقات.", "reasons_ar": ["ادعاء انتساب لجهة حكومية على نطاق غير رسمي", "كلمتا إغراء «fine» و«pay» في العنوان", "صدرت الشهادة قبل 90 دقيقة", "تطابق بصري 96% مع صفحة سداد المخالفات الرسمية", "يطلب بيانات البطاقة كاملة ورمز التحقق"]}, 38: {"verdict_note_ar": "يوعد بمنحة مليون درهم لم تعلنها أي جهة رسمية.", "reasons_ar": ["يدّعي «منحة وطنية» بمليون درهم — لا يعلنها أي موقع رسمي", "اسم العلامة «cbuae» على نطاق غير رسمي", "صدرت الشهادة قبل ساعتين", "يطلب «رسوم معالجة» قبل صرف المنحة"]}, 37: {"verdict_note_ar": "نسخة من دخول الخدمات المصرفية لبنك أبوظبي الأول تُحوّل بيانات دخولك إلى خادم خارجي.", "reasons_ar": ["اسم العلامة «fab» على نطاق غير رسمي", "كلمة إغراء «secure-login» في العنوان", "صدرت الشهادة قبل 5 ساعات", "تطابق بصري 92% مع صفحة الدخول الأصلية", "نموذج الدخول يُرسل البيانات إلى خادم خارجي"]}, 36: {"verdict_note_ar": "يشبه e& لكنه ليس كذلك — يجمع أرقام الهواتف لـ«ترقية 5G» وهمية.", "reasons_ar": ["اسم العلامة «etisalat» على نطاق غير رسمي", "كلمة إغراء «upgrade» في العنوان", "تطابق بصري 61% — تخطيط مشابه وصياغة مختلفة", "صدرت الشهادة قبل 9 ساعات"]}, 35: {"verdict_note_ar": "نسخة من صفحة سداد فواتير ديوا — قريبة من الصفحة الأصلية لكنها ليست هي.", "reasons_ar": ["اسم العلامة «dewa» على نطاق غير رسمي", "كلمتا إغراء «bill» و«pay» في العنوان", "تطابق بصري 78% مع صفحة سداد الفواتير الأصلية", "صدرت الشهادة قبل 7 ساعات"]}, 34: {"verdict_note_ar": "قائمة خرائط مزيفة باسم «خدمة عملاء ADCB» — رقم خاطئ وموقع منسوخ.", "reasons_ar": ["قائمة في الخرائط باسم «ADCB Customer Care Center» تستخدم رقمًا لم ينشره البنك", "موقع القائمة «adcb-care.support» ليس الموقع الرسمي adcb.ae", "خطأ في اسم العلامة «adcb» على نطاق غير رسمي", "صدرت الشهادة قبل 4 ساعات", "الرقم نفسه يظهر في 6 قوائم أخرى مبلّغ عنها"]}, 33: {"verdict_note_ar": "عروض أمازون الإمارات مزيفة تنتهي بنموذج بطاقة.", "reasons_ar": ["اسم العلامة «amazon-ae» على نطاق غير رسمي", "كلمة إغراء «deals» في العنوان", "صدرت الشهادة قبل 6 ساعات", "تطابق بصري 77% مع صفحة منتج على أمازون الإمارات"]}, 32: {"verdict_note_ar": "يضع عنوان البنك الحقيقي داخل عنوان مزيف ليبدو رسميًا.", "reasons_ar": ["النطاق الرسمي مضمّن داخل نطاق مختلف", "كلمة إغراء «verify» في العنوان", "صدرت الشهادة قبل 11 ساعة", "تطابق بصري 90% مع صفحة دخول adcb.ae"]}, 31: {"verdict_note_ar": "صفحة تنشر رقم «خدمة عملاء ADCB» مزيفًا.", "reasons_ar": ["تنشر رقم «خدمة عملاء» لا يصدره البنك", "خطأ في اسم العلامة «adcb» على نطاق غير رسمي", "صدرت الشهادة قبل 14 ساعة"]}}
SIGNALS_AR = {42: ["خطأ في العلامة على نطاق غير رسمي", "شهادة عمرها أقل من 24 ساعة", "نسخة بصرية من صفحة الدخول", "نموذج يُرسل لخادم خارجي", "حقول جمع بطاقة + رقم سري + رمز", "امتداد نطاق عالي الخطورة"], 41: ["اسم العلامة على نطاق غير رسمي", "كلمة إغراء في العنوان", "شهادة عمرها أقل من 24 ساعة", "نسخة بصرية من صفحة الاسترجاع", "حقول جمع آيبان + رمز تحقق"], 40: ["اسم العلامة على نطاق غير رسمي", "كلمات إغراء في العنوان", "شهادة عمرها أقل من 24 ساعة", "نسخة بصرية من صفحة التتبّع", "نموذج دفع لخادم خارجي"], 39: ["ادعاء حكومي على نطاق غير رسمي", "شهادة عمرها أقل من 24 ساعة", "نسخة بصرية من الصفحة الرسمية", "حقول جمع بطاقة + رمز تحقق"], 38: ["ادعاء جائزة غير موجود على أي موقع رسمي", "اسم العلامة على نطاق غير رسمي", "شهادة عمرها أقل من 24 ساعة", "طلب دفع مقدّم"], 37: ["اسم العلامة على نطاق غير رسمي", "كلمة إغراء «secure-login»", "شهادة عمرها أقل من 24 ساعة", "نسخة بصرية من صفحة الدخول", "نموذج دخول لخادم خارجي"], 36: ["اسم العلامة على نطاق غير رسمي", "كلمة إغراء «upgrade»", "تطابق بصري جزئي", "شهادة عمرها أقل من 24 ساعة"], 35: ["اسم العلامة على نطاق غير رسمي", "كلمات إغراء في العنوان", "تطابق بصري جزئي", "شهادة عمرها أقل من 24 ساعة"], 34: ["رقم غير رسمي في قائمة الخرائط", "خطأ في العلامة على نطاق غير رسمي", "شهادة عمرها أقل من 24 ساعة", "الرقم مكرر في قوائم أخرى"], 33: ["اسم العلامة على نطاق غير رسمي", "كلمة إغراء «deals»", "شهادة عمرها أقل من 24 ساعة", "تطابق بصري مع صفحة منتج"], 32: ["النطاق الرسمي داخل نطاق غريب", "كلمة إغراء «verify»", "شهادة عمرها أقل من 24 ساعة", "نسخة بصرية من صفحة الدخول"], 31: ["رقم دعم غير رسمي", "خطأ في العلامة على نطاق غير رسمي", "شهادة عمرها أقل من 24 ساعة"]}
STREAM_AR = {"verdict_note_ar": "نسخة أخرى من صفحة دخول بنك أبوظبي التجاري، وُلدت قبل دقائق.", "reasons_ar": ["خطأ في اسم العلامة «adcb» (مسافة حرف واحد) على نطاق غير رسمي", "صدرت الشهادة قبل دقيقتين", "تطابق بصري 94% مع صفحة adcb.ae/login", "نموذج الدخول يُرسل البيانات إلى خادم خارجي"]}

NOW = "2026-11-24T07:58:00Z"  # authored baseline; api.js re-anchors to real now


def sig(label, weight, note=""):
    return {"label": label, "weight": weight, "note": note}


FINDINGS = [
    {
        "id": 42,
        "domain": "adcb-secure-login.xyz",
        "verdict": "MALICIOUS",
        "score": 0.93,
        "brand": "ADCB",
        "reasons": [
            "brand typo 'adcb' (distance 1) on a non-official domain",
            "certificate issued 42 minutes ago — brand-new site",
            "login form posts to a foreign host: collect.adcb-verify.top",
            "97% visual match with adcb.ae/login",
            "risky TLD .xyz",
            "asks for card number, PIN, and OTP on the same page",
        ],
        "cert_issued": NOW,
        "first_seen": NOW,
        "clone": 97,
        "evidence_url": None,
        "gallery_match": "adcb.ae/login",
        "source": "crt.sh",
        "is_case_file": False,
        "age_min": 47,
        "cert_age_min": 42,
        "registrar": "NameCheap, Inc.",
        "path": "/verify",
        "verdict_note": "A copy of the ADCB login page that sends what you type to a foreign host.",
        "scam_type": "fake-banking-login",
        "signals": [
            sig("Brand typo on a non-official domain", 0.55),
            sig("Certificate younger than 24 hours", 0.25),
            sig("Visual clone of the real login page", 0.60),
            sig("Login form posts to a foreign host", 0.30),
            sig("Payment-harvest fields (card + PIN + OTP)", 0.25),
            sig("Risky TLD .xyz", 0.15),
        ],
    },
    {
        "id": 41,
        "domain": "emiratesnbd-refund.help",
        "verdict": "MALICIOUS",
        "score": 0.88,
        "brand": "Emirates NBD",
        "reasons": [
            "brand name 'emiratesnbd' on a non-official domain",
            "lure keyword 'refund' in the address",
            "certificate issued 3 hours ago",
            "94% visual match with emiratesnbd.com refund page",
            "asks for IBAN and a one-time code",
        ],
        "cert_issued": NOW,
        "first_seen": NOW,
        "clone": 94,
        "evidence_url": None,
        "gallery_match": "emiratesnbd.com/personal/refunds",
        "source": "crt.sh",
        "is_case_file": False,
        "age_min": 190,
        "cert_age_min": 178,
        "registrar": "Hostinger operations UAB",
        "path": "/claim",
        "verdict_note": "A refund page that copies Emirates NBD and asks for your IBAN and the code your bank texts you.",
        "scam_type": "fake-banking-login",
        "signals": [
            sig("Brand name on a non-official domain", 0.25),
            sig("Lure keyword 'refund' in the address", 0.20),
            sig("Certificate younger than 24 hours", 0.25),
            sig("Visual clone of the real refund page", 0.60),
            sig("Payment-harvest fields (IBAN + OTP)", 0.25),
        ],
    },
    {
        "id": 40,
        "domain": "aramex-delivery-fee.click",
        "verdict": "MALICIOUS",
        "score": 0.81,
        "brand": "Aramex",
        "reasons": [
            "brand name 'aramex' on a non-official domain",
            "lure keywords 'delivery' + 'fee' in the address",
            "certificate issued 3 hours ago",
            "89% visual match with the Aramex tracking page",
            "payment form posts to a foreign host",
        ],
        "cert_issued": NOW,
        "first_seen": NOW,
        "clone": 89,
        "evidence_url": None,
        "gallery_match": "aramex.com/track",
        "source": "crt.sh",
        "is_case_file": False,
        "age_min": 240,
        "cert_age_min": 226,
        "registrar": "NameSilo, LLC",
        "path": "/pay",
        "verdict_note": "The 'your package is on hold, pay 5 dirhams' page — a card-harvest form wearing Aramex's jacket.",
        "scam_type": "fake-delivery-fee",
        "signals": [
            sig("Brand name on a non-official domain", 0.25),
            sig("Lure keywords in the address", 0.20),
            sig("Certificate younger than 24 hours", 0.25),
            sig("Visual clone of the tracking page", 0.60),
            sig("Payment form posts to a foreign host", 0.30),
        ],
    },
    {
        "id": 39,
        "domain": "dubaipolice-fine-pay.info",
        "verdict": "MALICIOUS",
        "score": 0.90,
        "brand": "Abu Dhabi Police",
        "reasons": [
            "claims to be Abu Dhabi Police on a non-official domain",
            "lure keywords 'fine' + 'pay' in the address",
            "certificate issued 90 minutes ago",
            "96% visual match with the official fines payment page",
            "asks for full card details and the OTP",
        ],
        "cert_issued": NOW,
        "first_seen": NOW,
        "clone": 96,
        "evidence_url": None,
        "gallery_match": "adpolice.gov.ae/en/fines",
        "source": "crt.sh",
        "is_case_file": False,
        "age_min": 96,
        "cert_age_min": 90,
        "registrar": "ALIBABA.COM SINGAPORE E-COMMERCE PTE LTD",
        "path": "/pay-fine",
        "verdict_note": "Impersonates Abu Dhabi Police fines payment to collect card details.",
        "scam_type": "fake-gov-fine",
        "signals": [
            sig("Government entity claim on a non-official domain", 0.55),
            sig("Certificate younger than 24 hours", 0.25),
            sig("Visual clone of the official page", 0.60),
            sig("Payment-harvest fields (card + OTP)", 0.25),
        ],
    },
    {
        "id": 38,
        "domain": "cbuae-grant-1m.award",
        "verdict": "SUSPICIOUS",
        "score": 0.58,
        "brand": "Central Bank of the UAE",
        "reasons": [
            "claims a 1 million dirham 'national grant' — no official site says this",
            "brand name 'cbuae' on a non-official domain",
            "certificate issued 2 hours ago",
            "asks for a 'processing payment' before the grant",
        ],
        "cert_issued": NOW,
        "first_seen": NOW,
        "clone": 41,
        "evidence_url": None,
        "gallery_match": None,
        "source": "crt.sh",
        "is_case_file": False,
        "age_min": 130,
        "cert_age_min": 122,
        "registrar": "PDR Ltd. d/b/a PublicDomainRegistry.com",
        "path": "/claim",
        "verdict_note": "Promises a 1 million dirham grant that no official site ever announced.",
        "scam_type": "fake-giveaway",
        "signals": [
            sig("Giveaway claim not on any official site", 0.50),
            sig("Brand name on a non-official domain", 0.25),
            sig("Certificate younger than 24 hours", 0.25),
            sig("Advance-fee request", 0.20),
        ],
    },
    {
        "id": 37,
        "domain": "fab-online.secure-login.cc",
        "verdict": "MALICIOUS",
        "score": 0.86,
        "brand": "First Abu Dhabi Bank",
        "reasons": [
            "brand name 'fab' on a non-official domain",
            "lure keyword 'secure-login' in the address",
            "certificate issued 5 hours ago",
            "92% visual match with FAB's online banking login",
            "login form posts to a foreign host",
        ],
        "cert_issued": NOW,
        "first_seen": NOW,
        "clone": 92,
        "evidence_url": None,
        "gallery_match": "bankfab.com/en/business-banking/online-banking",
        "source": "crt.sh",
        "is_case_file": False,
        "age_min": 330,
        "cert_age_min": 310,
        "registrar": "Dynadot LLC",
        "path": "/login",
        "verdict_note": "Copies FAB online banking and forwards your login to a foreign host.",
        "scam_type": "fake-banking-login",
        "signals": [
            sig("Brand name on a non-official domain", 0.25),
            sig("Lure keyword 'secure-login'", 0.20),
            sig("Certificate younger than 24 hours", 0.25),
            sig("Visual clone of the login page", 0.60),
            sig("Login form posts to a foreign host", 0.30),
        ],
    },
    {
        "id": 36,
        "domain": "etisalat-5g-upgrade.site",
        "verdict": "SUSPICIOUS",
        "score": 0.52,
        "brand": "e& (Etisalat)",
        "reasons": [
            "brand name 'etisalat' on a non-official domain",
            "lure keyword 'upgrade' in the address",
            "61% visual match — similar layout, different wording",
            "certificate issued 9 hours ago",
        ],
        "cert_issued": NOW,
        "first_seen": NOW,
        "clone": 61,
        "evidence_url": None,
        "gallery_match": "eand.ae/en/personal",
        "source": "openphish",
        "is_case_file": False,
        "age_min": 560,
        "cert_age_min": 540,
        "registrar": "GoDaddy.com, LLC",
        "path": "/upgrade",
        "verdict_note": "Looks like e& but isn't — collects your number for a fake '5G upgrade'.",
        "scam_type": "brand-impersonation",
        "signals": [
            sig("Brand name on a non-official domain", 0.25),
            sig("Lure keyword 'upgrade'", 0.20),
            sig("Partial visual match", 0.35),
            sig("Certificate younger than 24 hours", 0.25),
        ],
    },
    {
        "id": 35,
        "domain": "dewa-bill-pay.online",
        "verdict": "SUSPICIOUS",
        "score": 0.61,
        "brand": "DEWA",
        "reasons": [
            "brand name 'dewa' on a non-official domain",
            "lure keywords 'bill' + 'pay' in the address",
            "78% visual match with the DEWA bill payment page",
            "certificate issued 7 hours ago",
        ],
        "cert_issued": NOW,
        "first_seen": NOW,
        "clone": 78,
        "evidence_url": None,
        "gallery_match": "dewa.gov.ae/en/consumer/bill-payment",
        "source": "crt.sh",
        "is_case_file": False,
        "age_min": 430,
        "cert_age_min": 410,
        "registrar": "NameCheap, Inc.",
        "path": "/pay",
        "verdict_note": "A DEWA bill payment look-alike — close to the real page, not the real page.",
        "scam_type": "brand-impersonation",
        "signals": [
            sig("Brand name on a non-official domain", 0.25),
            sig("Lure keywords in the address", 0.20),
            sig("Partial visual match", 0.35),
            sig("Certificate younger than 24 hours", 0.25),
        ],
    },
    {
        "id": 34,
        "domain": "adcb-care.support",
        "verdict": "MALICIOUS",
        "score": 0.84,
        "brand": "ADCB",
        "reasons": [
            "Maps listing 'ADCB Customer Care Center' uses a number ADCB never published",
            "listing website 'adcb-care.support' is not the official adcb.ae",
            "brand typo 'adcb' (distance 1) on a non-official domain",
            "certificate issued 4 hours ago",
            "number appears in 6 other reported listings",
        ],
        "cert_issued": NOW,
        "first_seen": NOW,
        "clone": 74,
        "evidence_url": None,
        "gallery_match": "adcb.ae/contact-us",
        "source": "maps-sweep",
        "is_case_file": False,
        "age_min": 260,
        "cert_age_min": 240,
        "registrar": "NameSilo, LLC",
        "path": "/",
        "verdict_note": "A fake 'ADCB Customer Care' Maps listing — wrong number, clone website.",
        "scam_type": "fake-maps-listing",
        "maps_listing": {
            "name": "ADCB Customer Care Center",
            "phone": "+971 2 555 0199",
            "website": "https://adcb-care.support",
            "category": "Bank customer service",
        },
        "signals": [
            sig("Unofficial phone number on a Maps listing", 0.45),
            sig("Brand typo on a non-official domain", 0.55),
            sig("Certificate younger than 24 hours", 0.25),
            sig("Number reported in other listings", 0.20),
        ],
    },
    {
        "id": 33,
        "domain": "amazon-ae-deals.xyz",
        "verdict": "MALICIOUS",
        "score": 0.79,
        "brand": "Amazon.ae",
        "reasons": [
            "brand name 'amazon-ae' on a non-official domain",
            "lure keyword 'deals' in the address",
            "certificate issued 6 hours ago",
            "77% visual match with an Amazon.ae product page",
        ],
        "cert_issued": NOW,
        "first_seen": NOW,
        "clone": 77,
        "evidence_url": None,
        "gallery_match": "amazon.ae/deals",
        "source": "urlhaus",
        "is_case_file": False,
        "age_min": 380,
        "cert_age_min": 360,
        "registrar": "NameCheap, Inc.",
        "path": "/deals",
        "verdict_note": "Fake Amazon.ae deals that end in a card form.",
        "scam_type": "fake-shop",
        "signals": [
            sig("Brand name on a non-official domain", 0.25),
            sig("Lure keyword 'deals'", 0.20),
            sig("Certificate younger than 24 hours", 0.25),
            sig("Visual match with a product page", 0.35),
        ],
    },
    {
        "id": 32,
        "domain": "adcb.ae-verify.top",  # IDN-free sibling, older
        "verdict": "MALICIOUS",
        "score": 0.87,
        "brand": "ADCB",
        "reasons": [
            "official domain embedded inside a different domain",
            "lure keyword 'verify' in the address",
            "certificate issued 11 hours ago",
            "90% visual match with adcb.ae login",
        ],
        "cert_issued": NOW,
        "first_seen": NOW,
        "clone": 90,
        "evidence_url": None,
        "gallery_match": "adcb.ae/login",
        "source": "crt.sh",
        "is_case_file": False,
        "age_min": 700,
        "cert_age_min": 660,
        "registrar": "PDR Ltd. d/b/a PublicDomainRegistry.com",
        "path": "/verify",
        "verdict_note": "Puts the real bank address inside a fake one to look official.",
        "scam_type": "fake-banking-login",
        "signals": [
            sig("Official domain embedded in a foreign domain", 0.45),
            sig("Lure keyword 'verify'", 0.20),
            sig("Certificate younger than 24 hours", 0.25),
            sig("Visual clone of the login page", 0.60),
        ],
    },
    {
        "id": 31,
        "domain": "adcb-care-number.info",
        "verdict": "SUSPICIOUS",
        "score": 0.49,
        "brand": "ADCB",
        "reasons": [
            "lists a 'customer care' number ADCB does not publish",
            "brand typo 'adcb' (distance 1) on a non-official domain",
            "certificate issued 14 hours ago",
        ],
        "cert_issued": NOW,
        "first_seen": NOW,
        "clone": 38,
        "evidence_url": None,
        "gallery_match": None,
        "source": "crt.sh",
        "is_case_file": False,
        "age_min": 880,
        "cert_age_min": 840,
        "registrar": "GoDaddy.com, LLC",
        "path": "/support",
        "verdict_note": "A page that publishes a fake 'ADCB customer care' phone number.",
        "scam_type": "brand-impersonation",
        "signals": [
            sig("Unofficial support number", 0.45),
            sig("Brand typo on a non-official domain", 0.35),
            sig("Certificate younger than 24 hours", 0.15),
        ],
    },
]


def report(rid, finding_id, status, auto, filed_age_min, hits, channel="web"):
    return {
        "id": rid,
        "finding_id": finding_id,
        "domain": next(f["domain"] for f in FINDINGS if f["id"] == finding_id),
        "status": status,
        "auto": auto,
        "filed_at": NOW,
        "filed_age_min": filed_age_min,
        "blocked_hits": hits,
        "channel": channel,
        "evidence": next(f for f in FINDINGS if f["id"] == finding_id),
    }


REPORTS = [
    report(7, 42, "SUBMITTED", True, 4, 1243),
    report(6, 40, "SUBMITTED", True, 26, 388),
    report(5, 39, "SEEN", True, 72, 902),
    report(4, 38, "QUEUED", True, 118, 212),
    report(3, 41, "SEEN", True, 181, 121),
    report(2, 34, "SUBMITTED", True, 236, 57, channel="maps"),
    report(1, 37, "SEEN", True, 301, 78),
]


def sweep_row(pos, url, title, snippet, verdict, score, reasons, finding_id=None):
    return {
        "position": pos, "url": url, "title": title, "snippet": snippet,
        "verdict": verdict, "score": score, "reasons": reasons,
        "finding_id": finding_id,
    }


SWEEP_WEB = {
    "id": 9, "query": "Emirates NBD refund", "query_ar": "استرجاع بنك الإمارات دبي الوطني",
    "lang": "en", "channel": "web", "engine": "serper", "cached": True,
    "results": [
        sweep_row(1, "https://www.emiratesnbd.com/en/personal/refunds",
                  "Refunds & disputes | Emirates NBD",
                  "How to raise a refund request with Emirates NBD and how long it takes.",
                  "SAFE", 0.02, ["matches the official Emirates NBD domain"], 41),
        sweep_row(2, "https://emiratesnbd-refund.help/claim",
                  "Emirates NBD Refund — Claim Your Refund Now",
                  "Fast refund approval. Enter your IBAN and the one-time code to receive your money within 24 hours.",
                  "MALICIOUS", 0.88,
                  ["brand name 'emiratesnbd' on a non-official domain",
                   "94% visual match with the real refund page",
                   "asks for IBAN and a one-time code"], 41),
        sweep_row(3, "https://www.emiratesnbd.com/en/help/refund-policy",
                  "Refund policy | Emirates NBD",
                  "The official refund policy, step by step.",
                  "SAFE", 0.03, ["matches the official Emirates NBD domain"], 41),
        sweep_row(4, "https://emiratesnbd-refunds.pro/track",
                  "Emirates NBD Refunds — Track Your Case",
                  "Track a refund case. Pay a 49 AED processing fee to release it.",
                  "SUSPICIOUS", 0.57,
                  ["brand name on a non-official domain",
                   "'processing fee' request that no bank charges",
                   "certificate issued 3 hours ago"]),
        sweep_row(5, "https://www.gulfnews.com/business/banking/uae-refund-scams",
                  "How refund scams work in the UAE — Gulf News",
                  "Banks never ask for your one-time code. Here is what to watch for.",
                  "SAFE", 0.04, ["established news domain — no impersonation"]),
        sweep_row(6, "https://enbd-helpdesk.click/refund",
                  "Emirates NBD Helpdesk — 24/7 Refund Support",
                  "Talk to an agent. Enter your card number to verify.",
                  "MALICIOUS", 0.83,
                  ["brand name on a non-official domain",
                   "asks for the full card number",
                   "certificate issued 5 hours ago"]),
        sweep_row(7, "https://www.emiratesnbd.com/en/personal/credit-cards",
                  "Credit cards | Emirates NBD",
                  "Compare the official Emirates NBD credit cards.",
                  "SAFE", 0.02, ["matches the official Emirates NBD domain"], 41),
    ],
}

SWEEP_MAPS = {
    "id": 10, "query": "ADCB customer care", "query_ar": "خدمة عملاء بنك أبوظبي التجاري",
    "lang": "en", "channel": "maps", "engine": "places-fixtures", "cached": True,
    "results": [
        {**sweep_row(1, "https://adcb.ae/contact-us", "ADCB Head Office",
                     "Sheikh Zayed Road, Abu Dhabi · 600 50 30 30",
                     "SAFE", 0.03, ["official ADCB number and website"]),
         "listing": {"name": "ADCB Head Office", "phone": "600 50 30 30", "website": "https://adcb.ae"}},
        {**sweep_row(2, "https://adcb-care.support", "ADCB Customer Care Center",
                     "Call us 24/7 for account support · +971 2 555 0199",
                     "MALICIOUS", 0.84,
                     ["number ADCB never published",
                      "website is not adcb.ae",
                      "brand typo on a non-official domain"], 34),
         "listing": {"name": "ADCB Customer Care Center", "phone": "+971 2 555 0199", "website": "https://adcb-care.support"}},
        {**sweep_row(3, "https://adcb.ae/branches", "ADCB — Al Ain Branch",
                     "Al Ain Mall, ground floor · 600 50 30 30",
                     "SAFE", 0.03, ["official ADCB number and website"]),
         "listing": {"name": "ADCB Al Ain Branch", "phone": "600 50 30 30", "website": "https://adcb.ae/branches"}},
        {**sweep_row(4, "", "ADCB Support (24/7)",
                     "WhatsApp support line · +971 56 999 1122",
                     "SUSPICIOUS", 0.61,
                     ["mobile number on a 'bank support' listing",
                      "number appears in 11 reported listings",
                      "no official website"]),
         "listing": {"name": "ADCB Support (24/7)", "phone": "+971 56 999 1122", "website": ""}},
        {**sweep_row(5, "https://adcb.ae", "ADCB — Official Site",
                     "Al Hilal Bank and Abu Dhabi Commercial Bank.",
                     "SAFE", 0.01, ["official domain"]),
         "listing": {"name": "ADCB Official Site", "phone": "600 50 30 30", "website": "https://adcb.ae"}},
    ],
}

SCANS = [
    {
        "kind": "url", "input": "https://adcb-secure-login.xyz/verify",
        "verdict": "MALICIOUS", "score": 0.93,
        "reasons": ["brand typo 'adcb' (distance 1) on a non-official domain",
                    "certificate issued 42 minutes ago",
                    "login form posts to a foreign host",
                    "97% visual match with adcb.ae/login"],
        "evidence_url": None, "scam_type": "fake-banking-login",
        "offline_capable": True, "finding_id": 42,
    },
    {
        "kind": "url", "input": "https://www.adcb.ae/personal.html",
        "verdict": "SAFE", "score": 0.02,
        "reasons": ["matches the official ADCB domain and certificate"],
        "evidence_url": None, "scam_type": None,
        "offline_capable": True, "finding_id": None,
    },
    {
        "kind": "text",
        "input": "Congrats! Abu Dhabi is giving away 1 million dirhams to celebrate the national day. Claim here: https://cbuae-grant-1m.award",
        "verdict": "SUSPICIOUS", "score": 0.58,
        "reasons": ["claims a 1 million dirham giveaway no official site announces",
                    "link 'cbuae-grant-1m.award' is not an official domain",
                    "asks for a 'processing payment' before the grant"],
        "evidence_url": None, "scam_type": "fake-giveaway",
        "offline_capable": True, "finding_id": 38,
    },
    {
        "kind": "text",
        "input": "Your package is on hold. Pay 5 AED within 24 hours here: https://aramex-delivery-fee.click/pay",
        "verdict": "MALICIOUS", "score": 0.81,
        "reasons": ["brand name 'aramex' on a non-official domain",
                    "small 'clearance fee' before delivery — classic pattern",
                    "89% visual match with the Aramex tracking page"],
        "evidence_url": None, "scam_type": "fake-delivery-fee",
        "offline_capable": True, "finding_id": 40,
    },
    {
        "kind": "url", "input": "https://аmazon.ae/deals",
        "verdict": "MALICIOUS", "score": 0.90,
        "reasons": ["look-alike letters from a different alphabet (mixed-script)",
                    "visually identical to amazon.ae but a different site underneath",
                    "certificate issued 6 hours ago"],
        "evidence_url": None, "scam_type": "homograph",
        "offline_capable": True, "finding_id": None,
    },
]

NUMBERS = [
    {
        "number": "+971900123456", "verdict": "MALICIOUS", "score": 0.78,
        "reasons": ["premium-rate range (0900) — billed per minute",
                    "known pattern: missed-call bait, you call back and pay",
                    "reported by 14 people"],
        "label": "Premium-rate bait",
    },
    {
        "number": "+971569991122", "verdict": "MALICIOUS", "score": 0.71,
        "reasons": ["same number as the fake 'ADCB Support' Maps listing",
                    "known pattern: WhatsApp 'customer care' impersonation",
                    "reported by 11 people"],
        "label": "Fake bank support",
    },
    {
        "number": "+971600540000", "verdict": "SAFE", "score": 0.05,
        "reasons": ["official Emirates NBD customer service number"],
        "label": "Official bank line",
    },
    {
        "number": "+97141234567", "verdict": "SUSPICIOUS", "score": 0.42,
        "reasons": ["matches a known 'fine payment' robocall pattern",
                    "reported by 6 people this week"],
        "label": "Fine-payment robocall",
    },
]

AI_CASES = {
    "7": {
        "summary_en": (
            "This is a credential-harvesting clone of the ADCB online banking login page, "
            "hosted on adcb-secure-login.xyz. The site impersonates Abu Dhabi Commercial Bank (ADCB) "
            "and reproduces the bank's login page at a 97% visual match, including the logo, layout, "
            "and the Arabic/English language switch. It works by asking for the card number, PIN, and a "
            "one-time code on a single page, then posting everything to a foreign host "
            "(collect.adcb-verify.top) controlled by the operator. The certificate was issued 42 minutes "
            "before detection and the domain has no legitimate history. Recommended action: keep the "
            "domain blocked at the Guard, initiate registrar takedown, and prioritise outreach to ADCB "
            "fraud operations. Priority: P1 — active banking credential theft."
        ),
        "summary_ar": (
            "هذا موقع منسوخ يستهدف سرقة بيانات الدخول إلى الخدمات المصرفية عبر الإنترنت لبنك أبوظبي التجاري، "
            "ويُستضاف على النطاق adcb-secure-login.xyz. ينتحل الموقع شخصية بنك أبوظبي التجاري (ADCB) "
            "ويطابق صفحة تسجيل الدخول الأصلية بنسبة 97٪، بما في ذلك الشعار والتخطيط ومفتاح التبديل بين العربية والإنجليزية. "
            "ويعمل الموقع عبر طلب رقم البطاقة والرقم السري ورمز التحقق لمرة واحدة في صفحة واحدة، "
            "ثم إرسالها جميعًا إلى خادم خارجي يتحكم فيه المشغّل (collect.adcb-verify.top). "
            "صدرت شهادة الموقع قبل 42 دقيقة فقط من اكتشافه، ولا يوجد للنطاق سجل استخدام مشروع. "
            "الإجراء الموصى به: إبقاء النطاق محجوبًا في الحارس، وبدء إجراء الإزالة لدى مسجّل النطاق، "
            "والتواصل مع إدارة مكافحة الاحتيال في البنك بأولوية. الأولوية: قصوى (P1) — سرقة بيانات مصرفية نشطة."
        ),
        "provider": "gemini",
        "fallback": False,
    },
    "6": {
        "summary_en": (
            "This is a payment-harvesting look-alike of the Aramex shipment tracking page at "
            "aramex-delivery-fee.click, matching the real page at 89%. It impersonates Aramex and works "
            "through the familiar 'parcel on hold, pay a small clearance fee' message: the victim enters "
            "card details on a page that posts them to a foreign host. The certificate is three hours old "
            "and the domain carries two lure keywords ('delivery' and 'fee'). Recommended action: keep it "
            "blocked, notify Aramex brand protection, and file the registrar abuse report. Priority: P2."
        ),
        "summary_ar": (
            "هذا موقع منسوخ يستهدف سرقة بيانات الدفع، ويقلّد صفحة تتبّع الشحنات الخاصة بأرامكس على النطاق "
            "aramex-delivery-fee.click بنسبة تطابق 89٪. ينتحل الموقع شخصية أرامكس ويعمل عبر الرسالة المألوفة: "
            "«شحنتك محتجزة، ادفع رسمًا جمركيًا بسيطًا»، إذ يُدخل الضحية بيانات بطاقته في صفحة تُرسلها إلى خادم خارجي. "
            "عمر الشهادة ثلاث ساعات فقط، ويحتوي النطاق على كلمتين مُغريتين هما «delivery» و«fee». "
            "الإجراء الموصى به: إبقاء الحجب، وإبلاغ فريق حماية العلامة في أرامكس، وتقديم بلاغ الإساءة إلى المسجّل. الأولوية: عالية (P2)."
        ),
        "provider": "gemini",
        "fallback": False,
    },
    "5": {
        "summary_en": (
            "This site impersonates Abu Dhabi Police's fines payment service on dubaipolice-fine-pay.info "
            "and reproduces the official payment page at 96%. It works by presenting a fake traffic fine and "
            "requesting full card details plus the one-time code on one screen, then forwarding them to an "
            "external collector. The certificate is 90 minutes old. Recommended action: keep the block in "
            "place, notify the Police cybercrime unit through this portal, and request registrar takedown. "
            "Priority: P1 — government impersonation."
        ),
        "summary_ar": (
            "ينتحل هذا الموقع خدمة سداد المخالفات المرورية الخاصة بشرطة أبوظبي على النطاق dubaipolice-fine-pay.info، "
            "ويطابق صفحة الدفع الرسمية بنسبة 96٪. ويعمل بعرض مخالفة مرورية وهمية وطلب بيانات البطاقة كاملة "
            "ورمز التحقق لمرة واحدة في شاشة واحدة، ثم تحويلها إلى جهة خارجية. عمر الشهادة 90 دقيقة. "
            "الإجراء الموصى به: استمرار الحجب، وإبلاغ وحدة الجرائم الإلكترونية عبر هذه البوابة، "
            "وطلب الإزالة من مسجّل النطاق. الأولوية: قصوى (P1) — انتحال جهة حكومية."
        ),
        "provider": "gemini",
        "fallback": False,
    },
}

TAKEDOWNS = {
    "7": {
        "letter_en": (
            "To: abuse@namecheap.com\n"
            "Subject: Abuse report — phishing site on your network (adcb-secure-login.xyz)\n\n"
            "Dear Abuse Team,\n\n"
            "We are reporting a phishing website hosted on a domain registered through NameCheap, Inc. "
            "The site at https://adcb-secure-login.xyz/verify impersonates the online banking login page of "
            "Abu Dhabi Commercial Bank (ADCB) and collects card numbers, PINs, and one-time codes, "
            "forwarding them to a foreign host (collect.adcb-verify.top).\n\n"
            "Evidence on file: 97% visual match with the official adcb.ae/login page, a TLS certificate "
            "issued 42 minutes before detection, and a form action pointing to a host outside the domain. "
            "This activity was caught by the Daggers radar before any user interaction, and the domain is "
            "currently blocked on protected devices.\n\n"
            "We ask that you suspend the domain and preserve registration records for law enforcement. "
            "The corresponding report has been filed with Abu Dhabi Police.\n\n"
            "Regards,\n"
            "Daggers — automated abuse desk\n"
            "reference: case #7 · adcb-secure-login.xyz"
        )
    }
}

# ---- UI demo inputs (were hardcoded inside views/*.js) -------------------
EXAMPLES = {
    "check": [
        {"payload": "https://adcb-secure-login.xyz/verify", "label_key": "check.exampleUrl"},
        {"payload": "Your package is on hold. Pay 5 AED: https://aramex-delivery-fee.click/pay", "label_key": "check.exampleText"},
        {"payload": "https://www.adcb.ae/personal.html", "label_key": "check.exampleSafe"},
    ],
    "numbers": ["+971 900 123 456", "+971 56 999 1122", "+971 600 540 000", "+971 4 123 4567"],
    "sweep_web": [
        {"q": "Emirates NBD refund", "lang": "en"},
        {"q": "استرجاع بنك الإمارات دبي الوطني", "lang": "ar"},
        {"q": "ADCB customer care", "lang": "en"},
        {"q": "خدمة عملاء بنك أبوظبي التجاري", "lang": "ar"},
        {"q": "DEWA bill payment", "lang": "en"},
    ],
    "sweep_maps": [
        {"q": "ADCB customer care", "lang": "en"},
        {"q": "خدمة عملاء بنك أبوظبي التجاري", "lang": "ar"},
        {"q": "Aramex drop-off", "lang": "en"},
    ],
}

# ---- offline rules tier (was hardcoded inside api.js) --------------------
OFFLINE_RULES = {
    "note": "Rules the Checker applies with no network. Pattern data only — the UI "
            "supplies the wording via i18n keys (offline.*). Mirrors core/ output shape.",
    "premium_prefixes": ["971900", "971909"],
    "risky_tlds": ["xyz", "top", "click", "info", "support", "site", "online", "cc", "award", "help"],
    "lure_keywords": ["login", "verify", "secure", "refund", "fine", "pay", "delivery", "grant", "care"],
    "brand_tokens": ["adcb", "emiratesnbd", "enbd", "fab", "aramex", "dewa", "etisalat", "cbuae", "amazon"],
    "official_domains": ["adcb.ae", "emiratesnbd.com", "bankfab.com", "aramex.com",
                          "dewa.gov.ae", "eand.ae", "adpolice.gov.ae", "amazon.ae"],
    "weights": {"brand": 0.45, "risky_tld": 0.2, "lure": 0.2, "premium": 0.74},
}

STATUS = {
    "mode": "live",
    "heartbeats": {"crt_poller": 38, "pipeline": 3, "vision": 54, "guard_sync": 71},
    "counts": {"domains": 18422, "findings": len(FINDINGS), "reports": len(REPORTS), "blocked_today": 1243},
    "uptime_s": 53211,
}

GUARD_STATS = {"blocked_today": 1243, "feed_size": len([f for f in FINDINGS if f["verdict"] == "MALICIOUS"])}

# Demo stream: a brand-new fake lands while you watch (plan §7 beat 4)
STREAM_DEMO = {
    "beat_delay_ms": 14000,
    "finding": {
        "id": 43,
        "domain": "adcb-login-verify.top",
        "verdict": "MALICIOUS",
        "score": 0.91,
        "brand": "ADCB",
        "reasons": [
            "brand typo 'adcb' (distance 1) on a non-official domain",
            "certificate issued 2 minutes ago",
            "94% visual match with adcb.ae/login",
            "login form posts to a foreign host",
        ],
        "cert_issued": NOW,
        "first_seen": NOW,
        "clone": 94,
        "evidence_url": None,
        "gallery_match": "adcb.ae/login",
        "source": "crt.sh",
        "is_case_file": False,
        "age_min": 2,
        "cert_age_min": 2,
        "registrar": "NameSilo, LLC",
        "path": "/login",
        "verdict_note": "Another ADCB login clone, born minutes ago.",
        "scam_type": "fake-banking-login",
        "signals": [
            sig("Brand typo on a non-official domain", 0.55),
            sig("Certificate younger than 24 hours", 0.25),
            sig("Visual clone of the real login page", 0.60),
            sig("Login form posts to a foreign host", 0.30),
        ],
    },
    "report": {
        "id": 8,
        "finding_id": 43,
        "domain": "adcb-login-verify.top",
        "status": "QUEUED",
        "auto": True,
        "filed_at": NOW,
        "filed_age_min": 0,
        "blocked_hits": 0,
        "channel": "web",
        "evidence": None,  # filled below
    },
}
STREAM_DEMO["report"]["evidence"] = STREAM_DEMO["finding"]


# ---- Arabic variants for checker / number / sweep (same rule as findings) ----
for _s in SCANS:
    _key = _s["input"]
    if "adcb-secure-login" in _key:
        _s["reasons_ar"] = AR_TEXT[42]["reasons_ar"][:4]
    elif "adcb.ae/personal" in _key:
        _s["reasons_ar"] = ["يطابق نطاق ADCB الرسمي وشهادته"]
    elif "package is on hold" in _key:
        _s["reasons_ar"] = ["اسم العلامة «aramex» على نطاق غير رسمي",
                            "«رسم تخليص» بسيط قبل التسليم — نمط معروف",
                            "تطابق بصري 89% مع صفحة تتبّع أرامكس"]
    elif "1 million dirhams" in _key:
        _s["reasons_ar"] = ["يدّعي جائزة مليون درهم لا تعلنها أي جهة رسمية",
                            "الرابط «cbuae-grant-1m.award» ليس نطاقًا رسميًا",
                            "يطلب «رسوم معالجة» قبل الجائزة"]
    elif "аmazon" in _key:
        _s["reasons_ar"] = ["حروف شبيهة من أبجدية أخرى (نصوص مختلطة)",
                            "يبدو مطابقًا لـ amazon.ae لكنه موقع مختلف تحته",
                            "صدرت الشهادة قبل 6 ساعات"]

NUMBERS_AR = {
    "+971900123456": (["نطاق أرقام مدفوعة (0900) — تُحتسب بالدقيقة",
                       "نمط معروف: مكالمة فائتة لإغرائك بالاتصال مرة أخرى",
                       "أبلغ عنه 14 شخصًا"], "طُعم رقم مدفوع"),
    "+971569991122": (["الرقم نفسه في قائمة «ADCB Support» المزيفة في الخرائط",
                       "نمط معروف: انتحال «خدمة العملاء» عبر واتساب",
                       "أبلغ عنه 11 شخصًا"], "دعم بنك مزيف"),
    "+971600540000": (["الرقم الرسمي لخدمة عملاء بنك الإمارات دبي الوطني"], "خط بنك رسمي"),
    "+97141234567": (["يطابق نمط مكالمات آلية «دفع مخالفة» معروف",
                      "أبلغ عنه 6 أشخاص هذا الأسبوع"], "مكالمة مخالفات آلية"),
}
for _n in NUMBERS:
    if _n["number"] in NUMBERS_AR:
        _n["reasons_ar"], _n["label_ar"] = NUMBERS_AR[_n["number"]]

SWEEP_AR = {
    "https://emiratesnbd-refund.help/claim": ["اسم العلامة «emiratesnbd» على نطاق غير رسمي",
        "تطابق بصري 94% مع صفحة الاسترجاع الأصلية", "يطلب رقم الآيبان ورمز التحقق"],
    "https://emiratesnbd-refunds.pro/track": ["اسم العلامة على نطاق غير رسمي",
        "طلب «رسم معالجة» لا يتقاضاه أي بنك", "صدرت الشهادة قبل 3 ساعات"],
    "https://enbd-helpdesk.click/refund": ["اسم العلامة على نطاق غير رسمي",
        "يطلب رقم البطاقة كاملًا", "صدرت الشهادة قبل 5 ساعات"],
    "https://adcb-care.support": ["رقم لم ينشره بنك ADCB", "الموقع ليس adcb.ae",
        "خطأ في اسم العلامة على نطاق غير رسمي"],
}
for _run in (SWEEP_WEB, SWEEP_MAPS):
    for _r in _run["results"]:
        if _r["url"] in SWEEP_AR:
            _r["reasons_ar"] = SWEEP_AR[_r["url"]]

# ---- merge the Arabic variants (single source: this table) ----------------
for _f in FINDINGS:
    _ar = AR_TEXT.get(_f["id"])
    if _ar:
        _f["verdict_note_ar"] = _ar["verdict_note_ar"]
        _f["reasons_ar"] = _ar["reasons_ar"]
    _sig_ar = SIGNALS_AR.get(_f["id"])
    if _sig_ar and _f.get("signals"):
        for _s, _label in zip(_f["signals"], _sig_ar):
            _s["label_ar"] = _label

STREAM_DEMO["finding"]["verdict_note_ar"] = STREAM_AR["verdict_note_ar"]
STREAM_DEMO["finding"]["reasons_ar"] = STREAM_AR["reasons_ar"]


def dump(name, data):
    targets = [OUT_ALL] + ([OUT_SHARED] if name in SHARED else [])
    for d in targets:
        d.mkdir(parents=True, exist_ok=True)
        (d / name).write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


dump("feed.json", {"findings": FINDINGS, "count": len(FINDINGS)})
dump("reports.json", {"reports": REPORTS})
dump("status.json", STATUS)
dump("guard_stats.json", GUARD_STATS)
dump("scan.json", {"scans": SCANS})
dump("sweep_web.json", SWEEP_WEB)
dump("sweep_maps.json", SWEEP_MAPS)
dump("numbers.json", {"numbers": NUMBERS})
dump("ai_cases.json", AI_CASES)
dump("takedowns.json", TAKEDOWNS)
dump("stream_demo.json", STREAM_DEMO)
dump("examples.json", EXAMPLES)
dump("offline_rules.json", OFFLINE_RULES)
# individual findings for #/finding/:id deep links offline
for f in FINDINGS:
    dump(f"finding_{f['id']}.json", f)

print("fixtures written:")
for d in (OUT_ALL, OUT_SHARED):
    print(" ", d.relative_to(ROOT), len(list(d.glob("*.json"))), "files")
