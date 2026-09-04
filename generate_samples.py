"""
Test Sample Generator for TruthLens
AI-Based Fake Identity & Document Screening System (SIH26188)

Generates 6 realistic mock ID cards and live portraits for instant testing & judge demonstrations:
1. Genuine Passport (Johnathan Doe, valid ICAO 9303 MRZ, matching live face) -> LOW RISK (VERIFIED)
2. Live Matching Portrait (Johnathan Doe live webcam photo) -> BIOMETRIC MATCH (85%+)
3. Expired & Flagged Visa (Maria Gonzalez, Overstay in Mock DB, Expired date) -> HIGH RISK (REJECTED)
4. Tampered Passport & Spliced Photo (Altered name, spliced photo, invalid MRZ) -> CRITICAL RISK
5. Live Impersonator Portrait (Different person for biometric mismatch test) -> FACE MISMATCH
6. Genuine Aadhaar & PAN Cards (Preserved domestic ID test cases)
"""
import os
import io
import qrcode
import numpy as np
from PIL import Image, ImageDraw, ImageFont, ImageFilter
from app.config import SAMPLE_DOCS_DIR
from app.pipeline.format_validator import generate_verhoeff_check_digit


def get_font(size: int, bold: bool = False):
    """Loads system TrueType font for clear typography."""
    candidates = [
        r"C:\Windows\Fonts\arialbd.ttf" if bold else r"C:\Windows\Fonts\arial.ttf",
        r"C:\Windows\Fonts\calibrib.ttf" if bold else r"C:\Windows\Fonts\calibri.ttf",
        r"C:\Windows\Fonts\segoeuib.ttf" if bold else r"C:\Windows\Fonts\segoeui.ttf",
    ]
    for p in candidates:
        if os.path.exists(p):
            try:
                return ImageFont.truetype(p, size)
            except Exception:
                continue
    return ImageFont.load_default()


def get_ocr_mrz_font(size: int):
    """Loads fixed-width font for ICAO 9303 MRZ lines."""
    candidates = [
        r"C:\Windows\Fonts\consola.ttf",
        r"C:\Windows\Fonts\cour.ttf",
        r"C:\Windows\Fonts\lucon.ttf",
    ]
    for p in candidates:
        if os.path.exists(p):
            try:
                return ImageFont.truetype(p, size)
            except Exception:
                continue
    return get_font(size, bold=True)


def create_mock_avatar(w: int, h: int, seed_color=(198, 145, 110), hair_color=(45, 30, 20), shirt_color=(40, 65, 110)) -> Image.Image:
    """Draws a clean identity portrait avatar with realistic human proportions."""
    img = Image.new("RGB", (w, h), (228, 235, 245))
    draw = ImageDraw.Draw(img)

    # Subtle background gradient
    for y in range(h):
        shade = int(225 + (y / h) * 18)
        draw.line([(0, y), (w, y)], fill=(shade, shade + 5, shade + 15))

    cx = w // 2
    head_w = int(w * 0.28)
    head_h = int(h * 0.32)
    head_cy = int(h * 0.40)

    # Torso / Shoulders
    torso_top = head_cy + head_h - 10
    draw.ellipse([cx - int(w * 0.45), torso_top, cx + int(w * 0.45), h + 50], fill=shirt_color)

    # Neck
    neck_w = int(head_w * 0.45)
    draw.rectangle([cx - neck_w, head_cy, cx + neck_w, torso_top + 15], fill=(seed_color[0] - 15, seed_color[1] - 15, seed_color[2] - 15))

    # Face Oval
    draw.ellipse([cx - head_w, head_cy - head_h, cx + head_w, head_cy + head_h], fill=seed_color)

    # Hair
    draw.chord([cx - head_w - 2, head_cy - head_h - 12, cx + head_w + 2, head_cy], 180, 360, fill=hair_color)

    # Eyes & Eyebrows
    eye_y = head_cy - int(head_h * 0.12)
    eye_offset = int(head_w * 0.45)
    draw.ellipse([cx - eye_offset - 4, eye_y - 3, cx - eye_offset + 4, eye_y + 3], fill=(30, 20, 15))
    draw.ellipse([cx + eye_offset - 4, eye_y - 3, cx + eye_offset + 4, eye_y + 3], fill=(30, 20, 15))
    draw.line([cx - eye_offset - 8, eye_y - 9, cx - eye_offset + 8, eye_y - 9], fill=hair_color, width=2)
    draw.line([cx + eye_offset - 8, eye_y - 9, cx + eye_offset + 8, eye_y - 9], fill=hair_color, width=2)

    # Nose & Mouth
    draw.line([cx, eye_y + 5, cx, eye_y + int(head_h * 0.35)], fill=(seed_color[0] - 25, seed_color[1] - 25, seed_color[2] - 25), width=2)
    mouth_y = eye_y + int(head_h * 0.55)
    draw.line([cx - 10, mouth_y, cx + 10, mouth_y], fill=(160, 80, 70), width=2)

    # Border frame
    draw.rectangle([0, 0, w - 1, h - 1], outline=(140, 160, 185), width=2)
    return img


def generate_qr_image(payload: str, size: int) -> Image.Image:
    """Generates an authentic QR code image."""
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=5, border=1)
    qr.add_data(payload)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    return qr_img.resize((size, size), Image.NEAREST)


def make_genuine_passport():
    """Generates an authentic Genuine US Passport demo document."""
    w, h = 900, 600
    img = Image.new("RGB", (w, h), (242, 246, 252))
    draw = ImageDraw.Draw(img)

    # Top Header Band
    draw.rectangle([0, 0, w, 85], fill=(22, 45, 90))
    f_header = get_font(26, bold=True)
    f_sub = get_font(14, bold=True)
    draw.text((30, 18), "UNITED STATES OF AMERICA", fill=(255, 255, 255), font=f_header)
    draw.text((30, 52), "PASSPORT / PASSEPORT", fill=(210, 225, 250), font=f_sub)

    # Passport Metadata grid
    f_lbl = get_font(12, bold=True)
    f_val = get_font(16, bold=True)

    draw.text((450, 18), "Type", fill=(180, 205, 240), font=f_lbl)
    draw.text((450, 34), "P", fill=(255, 255, 255), font=f_val)
    draw.text((540, 18), "Code", fill=(180, 205, 240), font=f_lbl)
    draw.text((540, 34), "USA", fill=(255, 255, 255), font=f_val)
    draw.text((640, 18), "Passport No.", fill=(180, 205, 240), font=f_lbl)
    draw.text((640, 34), "A89412051", fill=(255, 230, 110), font=f_val)

    # Subject Portrait (Left)
    avatar = create_mock_avatar(190, 245, seed_color=(205, 155, 120), hair_color=(40, 25, 15), shirt_color=(30, 55, 100))
    img.paste(avatar, (45, 120))

    # Fields
    fields = [
        ("Surname", "DOE", (280, 115)),
        ("Given Names", "JOHNATHAN", (280, 165)),
        ("Nationality", "UNITED STATES OF AMERICA", (280, 215)),
        ("Date of Birth", "15/04/1988", (280, 265)),
        ("Sex", "MALE", (540, 265)),
        ("Date of Issue", "20/10/2022", (280, 315)),
        ("Date of Expiry", "20/10/2032", (540, 315)),
        ("Authority", "United States Department of State", (280, 365))
    ]

    for lbl, val, pos in fields:
        draw.text((pos[0], pos[1]), lbl, fill=(100, 115, 135), font=f_lbl)
        draw.text((pos[0], pos[1] + 16), val, fill=(15, 25, 45), font=f_val)

    # Security watermarks & Guilloche background lines
    for line_y in range(110, 420, 24):
        draw.line([(260, line_y), (w - 30, line_y)], fill=(230, 236, 246), width=1)

    # ICAO 9303 Machine Readable Zone (MRZ)
    draw.rectangle([0, 470, w, h], fill=(255, 255, 255))
    draw.line([(0, 470), (w, 470)], fill=(200, 210, 225), width=2)

    f_mrz = get_ocr_mrz_font(21)
    mrz_l1 = "P<USADOE<<JOHNATHAN<<<<<<<<<<<<<<<<<<<<<<<<<"
    mrz_l2 = "A894120512USA8804156M3210204<<<<<<<<<<<<<<<2"
    draw.text((40, 490), mrz_l1, fill=(10, 15, 25), font=f_mrz)
    draw.text((40, 535), mrz_l2, fill=(10, 15, 25), font=f_mrz)


    # Border
    draw.rectangle([0, 0, w - 1, h - 1], outline=(50, 75, 120), width=3)
    out_path = SAMPLE_DOCS_DIR / "demo_passport_genuine.jpg"
    img.save(out_path, quality=94)
    print(f"Generated: {out_path.name}")


def make_matching_live_portrait():
    """Generates matching live webcam/passenger photo for Johnathan Doe."""
    w, h = 400, 480
    avatar = create_mock_avatar(w, h, seed_color=(205, 155, 120), hair_color=(40, 25, 15), shirt_color=(35, 60, 105))
    out_path = SAMPLE_DOCS_DIR / "demo_person_live_match.jpg"
    avatar.save(out_path, quality=92)
    print(f"Generated: {out_path.name}")


def make_impersonating_live_portrait():
    """Generates portrait of a completely different person (impersonation demo)."""
    w, h = 400, 480
    # Female avatar with different skin, hair, and clothing colors
    avatar = create_mock_avatar(w, h, seed_color=(225, 175, 145), hair_color=(120, 40, 25), shirt_color=(160, 45, 65))
    out_path = SAMPLE_DOCS_DIR / "demo_person_live_mismatch.jpg"
    avatar.save(out_path, quality=92)
    print(f"Generated: {out_path.name}")


def make_tampered_passport():
    """Generates tampered passport with spliced photo and altered name (Vikram Mehta)."""
    w, h = 900, 600
    img = Image.new("RGB", (w, h), (242, 246, 252))
    draw = ImageDraw.Draw(img)

    # Top Header Band
    draw.rectangle([0, 0, w, 85], fill=(22, 45, 90))
    f_header = get_font(26, bold=True)
    f_sub = get_font(14, bold=True)
    draw.text((30, 18), "UNITED STATES OF AMERICA", fill=(255, 255, 255), font=f_header)
    draw.text((30, 52), "PASSPORT / PASSEPORT", fill=(210, 225, 250), font=f_sub)

    f_lbl = get_font(12, bold=True)
    f_val = get_font(16, bold=True)

    draw.text((450, 18), "Type", fill=(180, 205, 240), font=f_lbl)
    draw.text((450, 34), "P", fill=(255, 255, 255), font=f_val)
    draw.text((540, 18), "Code", fill=(180, 205, 240), font=f_lbl)
    draw.text((540, 34), "USA", fill=(255, 255, 255), font=f_val)
    draw.text((640, 18), "Passport No.", fill=(180, 205, 240), font=f_lbl)
    draw.text((640, 34), "L898902C3", fill=(255, 230, 110), font=f_val)

    # SPLICED AVATAR: Different person & heavily re-compressed to trigger ELA
    spliced_avatar = create_mock_avatar(190, 245, seed_color=(165, 110, 80), hair_color=(15, 15, 15), shirt_color=(90, 35, 35))
    buf = io.BytesIO()
    spliced_avatar.save(buf, format="JPEG", quality=35)
    buf.seek(0)
    recompressed = Image.open(buf)
    img.paste(recompressed, (45, 120))

    # Altered name: Vikram Mehta (matches Interpol notice in mock DB)
    fields = [
        ("Surname", "MEHTA", (280, 115)),
        ("Given Names", "VIKRAM", (280, 165)),
        ("Nationality", "UNITED STATES OF AMERICA", (280, 215)),
        ("Date of Birth", "12/08/1990", (280, 265)),
        ("Sex", "MALE", (540, 265)),
        ("Date of Issue", "20/10/2022", (280, 315)),
        ("Date of Expiry", "15/09/2030", (540, 315)),
        ("Authority", "United States Department of State", (280, 365))
    ]

    for lbl, val, pos in fields:
        draw.text((pos[0], pos[1]), lbl, fill=(100, 115, 135), font=f_lbl)
        draw.text((pos[0], pos[1] + 16), val, fill=(15, 25, 45), font=f_val)

    # Forged MRZ with deliberate check digit corruption (corrupt checksum)
    draw.rectangle([0, 470, w, h], fill=(255, 255, 255))
    draw.line([(0, 470), (w, 470)], fill=(200, 210, 225), width=2)

    f_mrz = get_ocr_mrz_font(21)
    mrz_l1 = "P<USAMEHTA<<VIKRAM<<<<<<<<<<<<<<<<<<<<<<<<<<"
    # Note corrupted check digit at position 10 ('9' instead of valid '6')
    mrz_l2 = "L898902C39USA9008129M3009151<<<<<<<<<<<<<<00"
    draw.text((40, 490), mrz_l1, fill=(10, 15, 25), font=f_mrz)
    draw.text((40, 535), mrz_l2, fill=(10, 15, 25), font=f_mrz)

    draw.rectangle([0, 0, w - 1, h - 1], outline=(180, 45, 45), width=3)
    out_path = SAMPLE_DOCS_DIR / "demo_passport_tampered.jpg"
    img.save(out_path, quality=94)
    print(f"Generated: {out_path.name}")


def make_expired_visa():
    """Generates an expired Tourist Visa (Maria Gonzalez, V9284710)."""
    w, h = 850, 550
    img = Image.new("RGB", (w, h), (248, 250, 245))
    draw = ImageDraw.Draw(img)

    # Header
    draw.rectangle([0, 0, w, 75], fill=(30, 75, 55))
    f_hdr = get_font(24, bold=True)
    draw.text((30, 15), "SCHENGEN / ENTRY VISA", fill=(255, 255, 255), font=f_hdr)
    draw.text((30, 48), "ETAT FRANCAIS / REPUBLIC OF FRANCE", fill=(210, 235, 220), font=get_font(12, bold=True))

    f_lbl = get_font(12, bold=True)
    f_val = get_font(16, bold=True)

    draw.text((600, 18), "Visa Number", fill=(210, 235, 220), font=f_lbl)
    draw.text((600, 34), "V9284710", fill=(255, 225, 90), font=f_val)

    # Portrait (Right)
    avatar = create_mock_avatar(160, 205, seed_color=(215, 165, 130), hair_color=(25, 20, 15), shirt_color=(80, 45, 95))
    img.paste(avatar, (640, 110))

    fields = [
        ("Valid For", "SCHENGEN STATES", (40, 105)),
        ("Type of Visa", "C (TOURIST)", (320, 105)),
        ("Valid From", "01/01/2023", (40, 165)),
        ("Valid Until (EXPIRED)", "15/01/2024", (320, 165)),
        ("Number of Entries", "MULT", (40, 225)),
        ("Duration of Stay", "90 DAYS", (320, 225)),
        ("Bearer / Name", "MARIA GONZALEZ", (40, 285)),
        ("Remarks", "TOURIST TRANSIT - STRICT COMPLIANCE", (40, 345))
    ]

    for lbl, val, pos in fields:
        draw.text((pos[0], pos[1]), lbl, fill=(85, 105, 95), font=f_lbl)
        color = (180, 30, 30) if "EXPIRED" in lbl else (15, 35, 25)
        draw.text((pos[0], pos[1] + 16), val, fill=color, font=f_val)

    # Border entry stamp (circular red stamp)
    draw.ellipse([460, 250, 590, 380], outline=(175, 40, 35), width=3)
    draw.ellipse([475, 265, 575, 365], outline=(175, 40, 35), width=1)
    draw.text((490, 300), "IMMIGRATION", fill=(175, 40, 35), font=get_font(11, bold=True))
    draw.text((505, 320), "PARIS CDG", fill=(175, 40, 35), font=get_font(10, bold=True))

    # Bottom lines
    draw.rectangle([0, 450, w, h], fill=(255, 255, 255))
    draw.line([(0, 450), (w, 450)], fill=(200, 220, 210), width=2)
    f_mrz = get_ocr_mrz_font(20)
    draw.text((35, 470), "V<FRAGONZALEZ<<MARIA<<<<<<<<<<<<<<<<<<<<<<<", fill=(20, 25, 20), font=f_mrz)
    draw.text((35, 505), "V9284710<8FRA8909121F2401150<<<<<<<<<<<<<<", fill=(20, 25, 20), font=f_mrz)

    draw.rectangle([0, 0, w - 1, h - 1], outline=(30, 75, 55), width=3)
    out_path = SAMPLE_DOCS_DIR / "demo_visa_expired.jpg"
    img.save(out_path, quality=94)
    print(f"Generated: {out_path.name}")


def make_genuine_aadhaar():
    """Generates authentic Aadhaar mock card."""
    w, h = 860, 540
    img = Image.new("RGB", (w, h), (255, 255, 255))
    draw = ImageDraw.Draw(img)

    # Top Tri-color bar
    draw.rectangle([0, 0, w, 12], fill=(255, 120, 0))
    draw.rectangle([0, 12, w, 24], fill=(255, 255, 255))
    draw.rectangle([0, 24, w, 36], fill=(18, 136, 7))

    f_govt = get_font(18, bold=True)
    draw.text((160, 48), "GOVERNMENT OF INDIA", fill=(0, 0, 0), font=f_govt)
    draw.text((160, 74), "Unique Identification Authority of India", fill=(70, 70, 70), font=get_font(13))

    avatar = create_mock_avatar(175, 225, seed_color=(190, 140, 105))
    img.paste(avatar, (45, 130))

    f_lbl = get_font(13, bold=True)
    f_val = get_font(15)

    draw.text((250, 135), "Name:", fill=(80, 80, 80), font=f_lbl)
    draw.text((340, 135), "Aakash Verma", fill=(0, 0, 0), font=f_val)
    draw.text((250, 175), "DOB:", fill=(80, 80, 80), font=f_lbl)
    draw.text((340, 175), "12/05/1992", fill=(0, 0, 0), font=f_val)
    draw.text((250, 215), "Gender:", fill=(80, 80, 80), font=f_lbl)
    draw.text((340, 215), "MALE", fill=(0, 0, 0), font=f_val)

    # 12-digit Aadhaar with valid Verhoeff checksum
    aadhaar_base = "45289134567"
    chk_digit = generate_verhoeff_check_digit(aadhaar_base)
    full_aadhaar = f"{aadhaar_base[:4]} {aadhaar_base[4:8]} {aadhaar_base[8:]}{chk_digit}"

    f_id = get_font(25, bold=True)
    draw.text((250, 280), full_aadhaar, fill=(180, 20, 20), font=f_id)

    # QR Code
    qr_payload = f'<?xml version="1.0"?><PrintLetterBarcodeData uid="{aadhaar_base}{chk_digit}" name="Aakash Verma" gender="M" yob="1992" dob="12/05/1992" />'
    qr_img = generate_qr_image(qr_payload, 180)
    img.paste(qr_img, (620, 130))

    # Bottom bar
    draw.rectangle([0, h - 35, w, h], fill=(180, 20, 20))
    draw.text((320, h - 28), "Mera Aadhaar, Meri Pehchan", fill=(255, 255, 255), font=get_font(14, bold=True))
    draw.rectangle([0, 0, w - 1, h - 1], outline=(180, 180, 180), width=2)

    out_path = SAMPLE_DOCS_DIR / "sample_genuine_aadhaar.jpg"
    img.save(out_path, quality=94)
    print(f"Generated: {out_path.name}")


def make_genuine_pan():
    """Generates authentic PAN card."""
    w, h = 860, 540
    img = Image.new("RGB", (w, h), (235, 245, 255))
    draw = ImageDraw.Draw(img)

    draw.rectangle([0, 0, w, 70], fill=(28, 70, 135))
    draw.text((180, 15), "INCOME TAX DEPARTMENT", fill=(255, 255, 255), font=get_font(20, bold=True))
    draw.text((180, 42), "GOVT. OF INDIA", fill=(220, 235, 255), font=get_font(14))

    avatar = create_mock_avatar(160, 210, seed_color=(210, 160, 125))
    img.paste(avatar, (45, 115))

    f_lbl = get_font(12, bold=True)
    f_val = get_font(15, bold=True)

    draw.text((240, 110), "Permanent Account Number", fill=(70, 90, 120), font=f_lbl)
    draw.text((240, 130), "ABCPS1234F", fill=(15, 30, 60), font=get_font(22, bold=True))
    draw.text((240, 180), "Name", fill=(70, 90, 120), font=f_lbl)
    draw.text((240, 200), "PRIYA SHARMA", fill=(15, 30, 60), font=f_val)
    draw.text((240, 240), "Father's Name", fill=(70, 90, 120), font=f_lbl)
    draw.text((240, 260), "RAMESH SHARMA", fill=(15, 30, 60), font=f_val)
    draw.text((240, 300), "Date of Birth", fill=(70, 90, 120), font=f_lbl)
    draw.text((240, 320), "18/09/1994", fill=(15, 30, 60), font=f_val)

    qr_payload = "PAN:ABCPS1234F^PRIYA SHARMA^RAMESH SHARMA^18/09/1994"
    qr_img = generate_qr_image(qr_payload, 170)
    img.paste(qr_img, (620, 135))

    draw.rectangle([0, 0, w - 1, h - 1], outline=(30, 70, 130), width=2)
    out_path = SAMPLE_DOCS_DIR / "sample_genuine_pan.jpg"
    img.save(out_path, quality=94)
    print(f"Generated: {out_path.name}")


def make_sample_business_card():
    """Generates a realistic commercial visiting / business card (Rajesh Malhotra, Nexus Cloud)."""
    w, h = 850, 500
    img = Image.new("RGB", (w, h), (250, 252, 255))
    draw = ImageDraw.Draw(img)

    # Stylish corporate branding bar (top and left accent)
    draw.rectangle([0, 0, 16, h], fill=(30, 60, 115))
    draw.rectangle([0, 0, w, 8], fill=(0, 150, 214))

    f_comp = get_font(22, bold=True)
    f_tag = get_font(12)
    f_name = get_font(26, bold=True)
    f_title = get_font(14, bold=True)
    f_body = get_font(14)
    f_serv = get_font(12, bold=True)

    # Company Logo & Name
    draw.ellipse([45, 35, 85, 75], fill=(30, 60, 115))
    draw.text((58, 42), "N", fill=(255, 255, 255), font=get_font(24, bold=True))
    draw.text((100, 38), "NEXUS CLOUD TECHNOLOGIES PVT. LTD.", fill=(20, 35, 65), font=f_comp)
    draw.text((100, 68), "Enterprise IT Infrastructure & Cloud Computing", fill=(100, 115, 135), font=f_tag)

    # Divider line
    draw.line([(45, 105), (w - 45, 105)], fill=(220, 228, 240), width=2)

    # Individual details
    draw.text((50, 135), "RAJESH MALHOTRA", fill=(15, 25, 45), font=f_name)
    draw.text((50, 175), "MANAGING DIRECTOR & FOUNDER", fill=(0, 130, 195), font=f_title)

    # Contact details with labels
    contacts = [
        ("Mobile:", "+91 98765 43210"),
        ("Email:", "rajesh.malhotra@nexuscloud.in"),
        ("Website:", "www.nexuscloudtechnologies.com"),
        ("Office:", "Plot 42, Cyber City, Sector 29, Gurugram, Haryana - 122002")
    ]
    y_pos = 225
    for lbl, val in contacts:
        draw.text((50, y_pos), lbl, fill=(110, 125, 145), font=get_font(13, bold=True))
        draw.text((130, y_pos), val, fill=(30, 45, 70), font=f_body)
        y_pos += 32

    # Bottom services strip
    draw.rectangle([0, h - 55, w, h], fill=(238, 244, 252))
    draw.text((50, h - 38), "SERVICES: Cloud Migration  •  AI & Automation  •  Cybersecurity Advisory", fill=(45, 75, 120), font=f_serv)

    # Commercial vCard QR Code (Top Right)
    vcard_payload = (
        "BEGIN:VCARD\n"
        "VERSION:3.0\n"
        "FN:Rajesh Malhotra\n"
        "TITLE:Managing Director & Founder\n"
        "ORG:Nexus Cloud Technologies Pvt. Ltd.\n"
        "TEL:+919876543210\n"
        "EMAIL:rajesh.malhotra@nexuscloud.in\n"
        "URL:https://www.nexuscloudtechnologies.com\n"
        "END:VCARD"
    )
    qr_img = generate_qr_image(vcard_payload, 150)
    img.paste(qr_img, (w - 195, 135))

    # Border frame
    draw.rectangle([0, 0, w - 1, h - 1], outline=(190, 205, 225), width=2)

    out_path = SAMPLE_DOCS_DIR / "sample_commercial_business_card.jpg"
    img.save(out_path, quality=95)
    print(f"Generated: {out_path.name}")


def generate_all_samples():
    """Generates all demonstration assets."""
    SAMPLE_DOCS_DIR.mkdir(parents=True, exist_ok=True)
    print("=" * 60)
    print("TRUTHLENS: GENERATING BORDER SCREENING DEMO ASSETS")
    print("=" * 60)
    make_genuine_passport()
    make_matching_live_portrait()
    make_impersonating_live_portrait()
    make_tampered_passport()
    make_expired_visa()
    make_genuine_aadhaar()
    make_genuine_pan()
    make_sample_business_card()
    print("=" * 60)
    print("All demo assets successfully generated in:", SAMPLE_DOCS_DIR)
    print("=" * 60)


if __name__ == "__main__":
    generate_all_samples()

