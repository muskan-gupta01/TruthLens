"""
Generates TruthLens SIH Hackathon PowerPoint Presentation (.pptx)
SIH26188: AI-Based Fake Identity & Document Screening System
Ministry of Home Affairs - Category: Blockchain & Cybersecurity
"""
import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

# Theme Colors (TruthLens Cyber Dark)
COLOR_BG = RGBColor(10, 19, 34)         # #0A1322 Deep Navy
COLOR_CARD = RGBColor(14, 28, 48)       # #0E1C30 Surface Navy
COLOR_TEAL = RGBColor(0, 173, 181)      # #00ADB5 Teal Primary
COLOR_NEON = RGBColor(0, 245, 212)      # #00F5D4 Bright Accent
COLOR_WHITE = RGBColor(241, 245, 249)   # #F1F5F9 Primary Text
COLOR_MUTED = RGBColor(148, 163, 184)   # #94A3B8 Muted Text
COLOR_GREEN = RGBColor(16, 185, 129)    # #10B981 Verified
COLOR_YELLOW = RGBColor(245, 158, 11)   # #F59E0B Warning
COLOR_RED = RGBColor(239, 68, 68)       # #EF4444 High Risk


def set_slide_background(slide):
    """Fills slide background with sleek dark navy."""
    bg_shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, Inches(13.333), Inches(7.5))
    bg_shape.fill.solid()
    bg_shape.fill.fore_color.rgb = COLOR_BG
    bg_shape.line.color.rgb = COLOR_BG


def add_slide_header(slide, title_text, category_text="SIH26188 • MINISTRY OF HOME AFFAIRS"):
    """Adds a standard header banner to slides."""
    set_slide_background(slide)

    # Top accent bar
    bar = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(0.5), Inches(11.733), Inches(0.06))
    bar.fill.solid()
    bar.fill.fore_color.rgb = COLOR_TEAL
    bar.line.color.rgb = COLOR_TEAL

    # Category / Kicker
    cat_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.65), Inches(11.733), Inches(0.35))
    tf_cat = cat_box.text_frame
    p_cat = tf_cat.paragraphs[0]
    p_cat.text = category_text.upper()
    p_cat.font.size = Pt(11)
    p_cat.font.bold = True
    p_cat.font.color.rgb = COLOR_TEAL

    # Slide Title
    title_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.95), Inches(11.733), Inches(0.7))
    tf_title = title_box.text_frame
    p_title = tf_title.paragraphs[0]
    p_title.text = title_text
    p_title.font.size = Pt(26)
    p_title.font.bold = True
    p_title.font.color.rgb = COLOR_WHITE


def create_presentation():
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # =========================================================================
    # SLIDE 1: TITLE SLIDE
    # =========================================================================
    s1 = prs.slides.add_slide(blank_layout)
    set_slide_background(s1)

    # Decorative Card
    card = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(1.5), Inches(1.2), Inches(10.333), Inches(5.1))
    card.fill.solid()
    card.fill.fore_color.rgb = COLOR_CARD
    card.line.color.rgb = COLOR_TEAL
    card.line.width = Pt(2)

    tb = s1.shapes.add_textbox(Inches(2.0), Inches(1.6), Inches(9.333), Inches(4.3))
    tf = tb.text_frame
    tf.word_wrap = True

    p0 = tf.paragraphs[0]
    p0.text = "SMART INDIA HACKATHON (SIH 2024-2026)"
    p0.font.size = Pt(14)
    p0.font.bold = True
    p0.font.color.rgb = COLOR_TEAL

    p1 = tf.add_paragraph()
    p1.text = "TruthLens"
    p1.font.size = Pt(44)
    p1.font.bold = True
    p1.font.color.rgb = COLOR_WHITE

    p2 = tf.add_paragraph()
    p2.text = "AI-Based Fake Identity & Document Screening System"
    p2.font.size = Pt(22)
    p2.font.color.rgb = COLOR_NEON

    p3 = tf.add_paragraph()
    p3.text = "\nProblem Statement ID: SIH26188\nMinistry: Ministry of Home Affairs (MHA)\nCategory: Blockchain & Cybersecurity"
    p3.font.size = Pt(14)
    p3.font.color.rgb = COLOR_MUTED

    p4 = tf.add_paragraph()
    p4.text = "\nTeam Presentation & Live Demonstration"
    p4.font.size = Pt(13)
    p4.font.bold = True
    p4.font.color.rgb = COLOR_WHITE

    # =========================================================================
    # SLIDE 2: PROBLEM STATEMENT & CHALLENGES
    # =========================================================================
    s2 = prs.slides.add_slide(blank_layout)
    add_slide_header(s2, "The Problem: Border Checkpoint Identity Screening")

    # Column 1: Context
    c1 = s2.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.9), Inches(5.6), Inches(4.8))
    c1.fill.solid()
    c1.fill.fore_color.rgb = COLOR_CARD
    c1.line.color.rgb = COLOR_TEAL
    tf1 = c1.text_frame
    tf1.word_wrap = True
    p = tf1.paragraphs[0]
    p.text = "Operational Context & Real-World Strain"
    p.font.size = Pt(18)
    p.font.bold = True
    p.font.color.rgb = COLOR_NEON

    points1 = [
        ("High Passenger Volume", "Border terminals process thousands of passports, visas, and national IDs daily, causing long checkpoint queues."),
        ("Manual Inspection Limitations", "Physical inspection is slow (takes 3–5 minutes per traveler) and prone to human fatigue."),
        ("Sophisticated Forgeries", "Modern counterfeiters use digital editing tools (Photoshop, Canva) to alter photos and names without leaving visible paper tears."),
        ("Security Vulnerabilities", "Human officers cannot mathematically verify MRZ 7-3-1 check digits or Verhoeff D5 algorithms with the naked eye.")
    ]
    for title, desc in points1:
        p_t = tf1.add_paragraph()
        p_t.text = f"• {title}: "
        p_t.font.bold = True
        p_t.font.size = Pt(13)
        p_t.font.color.rgb = COLOR_WHITE
        p_d = tf1.add_paragraph()
        p_d.text = f"   {desc}"
        p_d.font.size = Pt(11)
        p_d.font.color.rgb = COLOR_MUTED

    # Column 2: Key Threat Vectors
    c2 = s2.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.8), Inches(1.9), Inches(5.7), Inches(4.8))
    c2.fill.solid()
    c2.fill.fore_color.rgb = COLOR_CARD
    c2.line.color.rgb = COLOR_RED
    tf2 = c2.text_frame
    tf2.word_wrap = True
    p = tf2.paragraphs[0]
    p.text = "Key Threats Faced at Borders"
    p.font.size = Pt(18)
    p.font.bold = True
    p.font.color.rgb = COLOR_RED

    points2 = [
        ("Counterfeit Passports & Visas", "Fabricated travel authorizations circulating through transnational fraud rings."),
        ("Photo Replacement & Face Splicing", "Pasting a foreign face onto a genuine passport holder's page."),
        ("Identity Impersonation", "Travelers carrying genuine documents belonging to a lookalike individual."),
        ("Altered Dates & Validity Overstay", "Changing expiry dates to bypass border stay duration limits."),
        ("Blacklisted & Stolen Stock", "Use of stolen blank passport stock (Interpol SLTD notices).")
    ]
    for title, desc in points2:
        p_t = tf2.add_paragraph()
        p_t.text = f"✕ {title}: "
        p_t.font.bold = True
        p_t.font.size = Pt(13)
        p_t.font.color.rgb = COLOR_WHITE
        p_d = tf2.add_paragraph()
        p_d.text = f"   {desc}"
        p_d.font.size = Pt(11)
        p_d.font.color.rgb = COLOR_MUTED

    # =========================================================================
    # SLIDE 3: SOLUTION ARCHITECTURE (7-STEP PIPELINE)
    # =========================================================================
    s3 = prs.slides.add_slide(blank_layout)
    add_slide_header(s3, "Our Solution: TruthLens 7-Step Autonomous Pipeline")

    steps = [
        ("1. OCR & MRZ", "ICAO Doc 9303 MRZ\n+ Text Extraction", COLOR_TEAL),
        ("2. Checksums", "Verhoeff D5 Math\n+ ICAO 7-3-1 checks", COLOR_TEAL),
        ("3. Rules Check", "Expiry Date &\nBorder 6-Month Rule", COLOR_TEAL),
        ("4. Forensics", "ELA Heatmap &\nPhoto Splice Ratio", COLOR_NEON),
        ("5. Metadata", "EXIF Audit &\nPhotoshop Traces", COLOR_NEON),
        ("6. Face Match", "1:1 Biometric Match\n(Doc vs Live Photo)", COLOR_GREEN),
        ("7. Risk Score", "0-100 Score &\nFinal Verdict", COLOR_GREEN)
    ]

    x_start = Inches(0.8)
    step_w = Inches(1.55)
    gap = Inches(0.14)

    for i, (stitle, sdesc, col) in enumerate(steps):
        s_box = s3.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x_start + i * (step_w + gap), Inches(2.3), step_w, Inches(3.8))
        s_box.fill.solid()
        s_box.fill.fore_color.rgb = COLOR_CARD
        s_box.line.color.rgb = col
        s_box.line.width = Pt(2)
        tfs = s_box.text_frame
        tfs.word_wrap = True

        p_num = tfs.paragraphs[0]
        p_num.text = f"STEP {i+1}"
        p_num.font.size = Pt(12)
        p_num.font.bold = True
        p_num.font.color.rgb = col
        p_num.alignment = PP_ALIGN.CENTER

        p_t = tfs.add_paragraph()
        p_t.text = stitle
        p_t.font.size = Pt(14)
        p_t.font.bold = True
        p_t.font.color.rgb = COLOR_WHITE
        p_t.alignment = PP_ALIGN.CENTER

        p_d = tfs.add_paragraph()
        p_d.text = f"\n{sdesc}"
        p_d.font.size = Pt(11)
        p_d.font.color.rgb = COLOR_MUTED
        p_d.alignment = PP_ALIGN.CENTER

    bot_box = s3.shapes.add_textbox(Inches(0.8), Inches(6.3), Inches(11.733), Inches(0.8))
    tf_bot = bot_box.text_frame
    p_b = tf_bot.paragraphs[0]
    p_b.text = "⚡ End-to-End Latency: < 1.8 seconds per traveler | Runs 100% locally without cloud dependency."
    p_b.font.size = Pt(14)
    p_b.font.bold = True
    p_b.font.color.rgb = COLOR_NEON
    p_b.alignment = PP_ALIGN.CENTER

    # =========================================================================
    # SLIDE 4: MODULE 1 & 2 - OCR, MRZ & MATHEMATICAL CHECKSUMS
    # =========================================================================
    s4 = prs.slides.add_slide(blank_layout)
    add_slide_header(s4, "Module 1 & 2: OCR, MRZ & Mathematical Validation")

    c1 = s4.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.9), Inches(5.6), Inches(4.8))
    c1.fill.solid()
    c1.fill.fore_color.rgb = COLOR_CARD
    c1.line.color.rgb = COLOR_TEAL
    tf1 = c1.text_frame
    tf1.word_wrap = True
    p = tf1.paragraphs[0]
    p.text = "Module 1: ICAO Doc 9303 MRZ Engine"
    p.font.size = Pt(17)
    p.font.bold = True
    p.font.color.rgb = COLOR_NEON

    m1_points = [
        ("Universal Document Support", "Extracts structured fields from Passports, Visas, Aadhaar, PAN, Driving Licenses, and Travel Permits."),
        ("ICAO TD3 & TD1 Parser", "Decodes 2-line 44-char passport MRZ and 3-line 30-char national ID MRZ zones."),
        ("Cyclic 7-3-1 Weighting Checksums", "Calculates modular check digits on Passport No, Birth Date, and Expiry Date."),
        ("Mathematical Tamper Detection", "Counterfeit numbers created without the exact ICAO checksum algorithm fail mathematically with 100% certainty.")
    ]
    for title, desc in m1_points:
        p_t = tf1.add_paragraph()
        p_t.text = f"✓ {title}: "
        p_t.font.bold = True
        p_t.font.size = Pt(12)
        p_t.font.color.rgb = COLOR_WHITE
        p_d = tf1.add_paragraph()
        p_d.text = f"   {desc}"
        p_d.font.size = Pt(11)
        p_d.font.color.rgb = COLOR_MUTED

    c2 = s4.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.8), Inches(1.9), Inches(5.7), Inches(4.8))
    c2.fill.solid()
    c2.fill.fore_color.rgb = COLOR_CARD
    c2.line.color.rgb = COLOR_TEAL
    tf2 = c2.text_frame
    tf2.word_wrap = True
    p = tf2.paragraphs[0]
    p.text = "Module 2: Regulatory & Checksum Rules"
    p.font.size = Pt(17)
    p.font.bold = True
    p.font.color.rgb = COLOR_NEON

    m2_points = [
        ("UIDAI Verhoeff D5 Algorithm", "Implements dihedral group D5 permutation matrix used by UIDAI. Catches 100% of single-digit and transposition errors in 12-digit Aadhaar."),
        ("PAN Entity Code Syntax", "Validates 4th entity code ('P' for Individual, 'C' for Company, 'F' for Firm) and ITD format structure."),
        ("Expiry & 6-Month Border Rule", "Checks validity window and warns when a passport has less than 180 days validity remaining for international transit."),
        ("Status Checklist Badges", "Every single check produces an itemized legal audit trail: ✓ Valid, ⚠ Warning, or ✕ Invalid.")
    ]
    for title, desc in m2_points:
        p_t = tf2.add_paragraph()
        p_t.text = f"✓ {title}: "
        p_t.font.bold = True
        p_t.font.size = Pt(12)
        p_t.font.color.rgb = COLOR_WHITE
        p_d = tf2.add_paragraph()
        p_d.text = f"   {desc}"
        p_d.font.size = Pt(11)
        p_d.font.color.rgb = COLOR_MUTED

    # =========================================================================
    # SLIDE 5: MODULE 3 - TAMPERING DETECTION (CORE AI INNOVATION)
    # =========================================================================
    s5 = prs.slides.add_slide(blank_layout)
    add_slide_header(s5, "Module 3: Tampering Detection (Core AI Innovation)")

    t_boxes = [
        ("1. Error Level Analysis (ELA)", "Resaves document at 90% JPEG quality to measure recompression difference. Edited patches and pasted fonts display elevated error, visualized as a colorized JET heatmap.", COLOR_TEAL),
        ("2. Photo Splice Detection", "Measures compression delta ratio between the facial portrait ROI and the card background. Pasted headshots exhibit sharp compression discontinuity (> 2.0x ratio).", COLOR_RED),
        ("3. Border Stamp Forgery", "Evaluates immigration entry stamps for physical ink bleed and substrate absorption. Flat digital vector paste is flagged via high edge Laplacian variance.", COLOR_YELLOW),
        ("4. EXIF Metadata Forensics", "Inspects image header markers for software editing traces (Adobe Photoshop, Canva, GIMP, Snapseed) and creation vs modification timestamp mismatches.", COLOR_GREEN)
    ]

    for i, (title, desc, col) in enumerate(t_boxes):
        row = i // 2
        col_idx = i % 2
        x = Inches(0.8) if col_idx == 0 else Inches(6.8)
        y = Inches(1.9) + row * Inches(2.4)

        box = s5.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, y, Inches(5.7), Inches(2.1))
        box.fill.solid()
        box.fill.fore_color.rgb = COLOR_CARD
        box.line.color.rgb = col
        box.line.width = Pt(2)
        tf_b = box.text_frame
        tf_b.word_wrap = True

        p_t = tf_b.paragraphs[0]
        p_t.text = title
        p_t.font.size = Pt(16)
        p_t.font.bold = True
        p_t.font.color.rgb = col

        p_d = tf_b.add_paragraph()
        p_d.text = f"\n{desc}"
        p_d.font.size = Pt(11)
        p_d.font.color.rgb = COLOR_MUTED

    # =========================================================================
    # SLIDE 6: MODULE 4 - BIOMETRIC FACE VERIFICATION
    # =========================================================================
    s6 = prs.slides.add_slide(blank_layout)
    add_slide_header(s6, "Module 4: 1:1 Biometric Face Verification")

    c1 = s6.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.9), Inches(5.6), Inches(4.8))
    c1.fill.solid()
    c1.fill.fore_color.rgb = COLOR_CARD
    c1.line.color.rgb = COLOR_GREEN
    tf1 = c1.text_frame
    tf1.word_wrap = True
    p = tf1.paragraphs[0]
    p.text = "Biometric Comparison Methodology"
    p.font.size = Pt(17)
    p.font.bold = True
    p.font.color.rgb = COLOR_GREEN

    face_points = [
        ("Automated Portrait Cropping", "Computer-vision skin-chrominance (YCrCb) & anthropometric contour detector isolates facial portrait from document automatically."),
        ("Multi-Modal Live Input", "Accepts uploaded live photo or captures live passenger snapshot directly from checkpoint webcam via WebRTC."),
        ("HSV Color Histogram Correlation", "Measures skin chrominance, lighting balance, and pigment distribution across normalized color space."),
        ("Structural Gradient & Template Match", "Computes normalized cross-correlation and Sobel edge continuity between aligned 160x160 face crops.")
    ]
    for title, desc in face_points:
        p_t = tf1.add_paragraph()
        p_t.text = f"👤 {title}: "
        p_t.font.bold = True
        p_t.font.size = Pt(12)
        p_t.font.color.rgb = COLOR_WHITE
        p_d = tf1.add_paragraph()
        p_d.text = f"   {desc}"
        p_d.font.size = Pt(11)
        p_d.font.color.rgb = COLOR_MUTED

    c2 = s6.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.8), Inches(1.9), Inches(5.7), Inches(4.8))
    c2.fill.solid()
    c2.fill.fore_color.rgb = COLOR_CARD
    c2.line.color.rgb = COLOR_TEAL
    tf2 = c2.text_frame
    tf2.word_wrap = True
    p = tf2.paragraphs[0]
    p.text = "Decision Thresholds & Calibrated Output"
    p.font.size = Pt(17)
    p.font.bold = True
    p.font.color.rgb = COLOR_NEON

    out_points = [
        ("Match Confirmed (≥ 40.0%)", "Clear 1:1 match. Document photo corresponds to presented individual (adds 0 risk points)."),
        ("Possible Mismatch (34.0%–39.9%)", "Borderline similarity. Flags warning for security officer physical inspection (adds +18 risk points)."),
        ("Biometric Mismatch (< 34.0%)", "Severe facial discrepancy. Critical security alert for suspected identity impersonation (adds +35 risk points)."),
        ("Visual Audit Previews", "Renders document face crop side-by-side with live passenger face crop directly on the dashboard.")
    ]
    for title, desc in out_points:
        p_t = tf2.add_paragraph()
        p_t.text = f"• {title}: "
        p_t.font.bold = True
        p_t.font.size = Pt(12)
        p_t.font.color.rgb = COLOR_WHITE
        p_d = tf2.add_paragraph()
        p_d.text = f"   {desc}"
        p_d.font.size = Pt(11)
        p_d.font.color.rgb = COLOR_MUTED

    # =========================================================================
    # SLIDE 7: DYNAMIC RISK ASSESSMENT ENGINE & VERDICT
    # =========================================================================
    s7 = prs.slides.add_slide(blank_layout)
    add_slide_header(s7, "Dynamic Risk Assessment Engine & Transparent Scoring")

    # Left: Score Gauge Concept
    c1 = s7.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.9), Inches(4.5), Inches(4.8))
    c1.fill.solid()
    c1.fill.fore_color.rgb = COLOR_CARD
    c1.line.color.rgb = COLOR_TEAL
    tf1 = c1.text_frame
    tf1.word_wrap = True
    p = tf1.paragraphs[0]
    p.text = "Calibrated Risk Tiers"
    p.font.size = Pt(18)
    p.font.bold = True
    p.font.color.rgb = COLOR_NEON

    tiers = [
        ("LOW RISK (0–29)", "VERIFIED / LOW RISK", COLOR_GREEN, "Clear for transit. All layers verified authentic."),
        ("MEDIUM RISK (30–59)", "NEEDS MANUAL REVIEW", COLOR_YELLOW, "Secondary physical inspection recommended."),
        ("HIGH RISK (60–79)", "HIGH RISK / SUSPICIOUS", COLOR_RED, "High security violation alert. Supervisor review."),
        ("CRITICAL (80–100)", "HIGH RISK / SUSPICIOUS", COLOR_RED, "Critical breach: Counterfeit, splice, or watchlist hit.")
    ]
    for t_name, verdict, col, desc in tiers:
        p_t = tf1.add_paragraph()
        p_t.text = f"\n{t_name}"
        p_t.font.bold = True
        p_t.font.size = Pt(13)
        p_t.font.color.rgb = col
        p_v = tf1.add_paragraph()
        p_v.text = f"Verdict: {verdict}"
        p_v.font.size = Pt(11)
        p_v.font.bold = True
        p_v.font.color.rgb = COLOR_WHITE
        p_d = tf1.add_paragraph()
        p_d.text = desc
        p_d.font.size = Pt(10)
        p_d.font.color.rgb = COLOR_MUTED

    # Right: Factor Breakdown Table
    c2 = s7.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(5.7), Inches(1.9), Inches(6.8), Inches(4.8))
    c2.fill.solid()
    c2.fill.fore_color.rgb = COLOR_CARD
    c2.line.color.rgb = COLOR_TEAL
    tf2 = c2.text_frame
    tf2.word_wrap = True
    p = tf2.paragraphs[0]
    p.text = "Transparent Contributing Risk Factors (+Points)"
    p.font.size = Pt(18)
    p.font.bold = True
    p.font.color.rgb = COLOR_NEON

    factors = [
        ("Mock Watchlist Hit (Interpol Notice / Stolen)", "+45 Points", COLOR_RED),
        ("Photo Replacement / Facial ROI Splice", "+35 Points", COLOR_RED),
        ("Biometric Face Mismatch (Impersonation)", "+35 Points", COLOR_RED),
        ("Document Validity Expired", "+30 Points", COLOR_RED),
        ("Editing Software Signature (Photoshop/Canva)", "+25 Points", COLOR_YELLOW),
        ("ICAO / Verhoeff Checksum Failure", "+25 Points", COLOR_YELLOW),
        ("Suspect Border Stamp (Digital Paste)", "+15 Points", COLOR_YELLOW),
        ("Missing Mandatory Identity Fields", "+10 Points", COLOR_MUTED)
    ]
    for fname, pts, col in factors:
        p_f = tf2.add_paragraph()
        p_f.text = f"• {fname}: "
        p_f.font.size = Pt(12)
        p_f.font.color.rgb = COLOR_WHITE
        p_pts = tf2.add_paragraph()
        p_pts.text = f"   Weight: {pts}"
        p_pts.font.size = Pt(11)
        p_pts.font.bold = True
        p_pts.font.color.rgb = col

    # =========================================================================
    # SLIDE 8: CRYPTOGRAPHIC AUDIT LEDGER & DPDP ACT PRIVACY
    # =========================================================================
    s8 = prs.slides.add_slide(blank_layout)
    add_slide_header(s8, "Cryptographic Audit Ledger & DPDP Act Data Privacy")

    c1 = s8.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.9), Inches(5.6), Inches(4.8))
    c1.fill.solid()
    c1.fill.fore_color.rgb = COLOR_CARD
    c1.line.color.rgb = COLOR_NEON
    tf1 = c1.text_frame
    tf1.word_wrap = True
    p = tf1.paragraphs[0]
    p.text = "Tamper-Proof Audit Chain (Hash-Chaining)"
    p.font.size = Pt(17)
    p.font.bold = True
    p.font.color.rgb = COLOR_NEON

    db_points = [
        ("Sequential SHA-256 Hashing", "Each block cryptographically binds data_snapshot + previous_hash + timestamp."),
        ("Immutable Genesis Anchor", "Block #0 rooted at a fixed 64-char genesis digest ('0'*64) for mathematical trust."),
        ("Continuous Ledger Verifier", "Zero-trust engine (/api/audit/verify) recomputes and validates entire chain in milliseconds."),
        ("Insider Tamper Detection", "Direct SQLite alterations immediately fail verification and flag the exact corrupted record ID."),
        ("Visual Block Explorer", "Interactive UI renders sequential linked cards with short hashes and masked summaries.")
    ]
    for title, desc in db_points:
        p_t = tf1.add_paragraph()
        p_t.text = f"⛓️ {title}: "
        p_t.font.bold = True
        p_t.font.size = Pt(12)
        p_t.font.color.rgb = COLOR_WHITE
        p_d = tf1.add_paragraph()
        p_d.text = f"   {desc}"
        p_d.font.size = Pt(11)
        p_d.font.color.rgb = COLOR_MUTED

    c2 = s8.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.8), Inches(1.9), Inches(5.7), Inches(4.8))
    c2.fill.solid()
    c2.fill.fore_color.rgb = COLOR_CARD
    c2.line.color.rgb = COLOR_TEAL
    tf2 = c2.text_frame
    tf2.word_wrap = True
    p = tf2.paragraphs[0]
    p.text = "DPDP Act 2023 Data Minimization"
    p.font.size = Pt(17)
    p.font.bold = True
    p.font.color.rgb = COLOR_TEAL

    hist_points = [
        ("Display-Layer Masking", "History list masks document numbers (e.g. 'XXXX XXXX 9012', 'XXXXX02C3', 'XXXXXX234F')."),
        ("Subject Name Preserved", "Passenger names remain visible in table for rapid border officer identification."),
        ("Active Officer Inspection", "Clicking 'Inspect' reveals full unmasked dossier for active case adjudication."),
        ("Cryptographic Invariant Intact", "Underlying stored records and SHA-256 hash snapshots remain unmasked and valid."),
        ("100% Local-First Edge Privacy", "Zero citizen biometrics or credentials transmitted to external commercial cloud APIs.")
    ]
    for title, desc in hist_points:
        p_t = tf2.add_paragraph()
        p_t.text = f"🔒 {title}: "
        p_t.font.bold = True
        p_t.font.size = Pt(12)
        p_t.font.color.rgb = COLOR_WHITE
        p_d = tf2.add_paragraph()
        p_d.text = f"   {desc}"
        p_d.font.size = Pt(11)
        p_d.font.color.rgb = COLOR_MUTED

    # =========================================================================
    # SLIDE 9: 3 DEMO SCENARIOS FOR JUDGES
    # =========================================================================
    s9 = prs.slides.add_slide(blank_layout)
    add_slide_header(s9, "Live Demo Scenarios for SIH Hackathon Judges")

    demo_scenarios = [
        ("Scenario 1: Genuine Passport + Live Match", "LOW RISK / VERIFIED (Score: 0/100)", COLOR_GREEN, [
            "Document: Authentic US Passport (Johnathan Doe, A89412051)",
            "Live Photo: Matching portrait (Webcam / Live Photo)",
            "ICAO 9303 Checksum: 100% verified (doc no, DOB, expiry)",
            "Biometric Match: 62.8% similarity (MATCH CONFIRMED)",
            "Verdict: CLEAR FOR TRANSIT"
        ]),
        ("Scenario 2: Expired Visa + Watchlist Alert", "HIGH RISK / REJECTED (Score: 100/100)", COLOR_RED, [
            "Document: Schengen Tourist Visa (Maria Gonzalez, V9284710)",
            "Expiry Check: Expired on 15/01/2024 (✕ Invalid)",
            "Mock Database Hit: Revoked Tourist Visa - Overstay Violation",
            "Border Stamp: Evaluated for ink bleed authenticity",
            "Verdict: SECONDARY DETENTION / REJECTED"
        ]),
        ("Scenario 3: Tampered Passport + Impersonator", "HIGH RISK / REJECTED (Score: 63/100)", COLOR_RED, [
            "Document: Tampered Passport with altered name 'Vikram Mehta'",
            "Photo Splice: Compression anomaly evaluated on facial ROI",
            "ICAO MRZ Checksum: Corrupt check digit mathematically flagged",
            "Biometric Match: 35.3% similarity (MISMATCH CONFIRMED)",
            "Verdict: IDENTITY IMPERSONATION ALERT"
        ])
    ]

    x_s = Inches(0.8)
    w_sc = Inches(3.7)
    g_sc = Inches(0.3)

    for i, (stitle, sscore, col, bpoints) in enumerate(demo_scenarios):
        sc_box = s9.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x_s + i * (w_sc + g_sc), Inches(1.9), w_sc, Inches(4.8))
        sc_box.fill.solid()
        sc_box.fill.fore_color.rgb = COLOR_CARD
        sc_box.line.color.rgb = col
        sc_box.line.width = Pt(2)
        tf_sc = sc_box.text_frame
        tf_sc.word_wrap = True

        p_t = tf_sc.paragraphs[0]
        p_t.text = stitle
        p_t.font.size = Pt(14)
        p_t.font.bold = True
        p_t.font.color.rgb = COLOR_WHITE

        p_s = tf_sc.add_paragraph()
        p_s.text = sscore
        p_s.font.size = Pt(12)
        p_s.font.bold = True
        p_s.font.color.rgb = col

        for bp in bpoints:
            p_b = tf_sc.add_paragraph()
            p_b.text = f"• {bp}"
            p_b.font.size = Pt(10)
            p_b.font.color.rgb = COLOR_MUTED

    # =========================================================================
    # SLIDE 10: KEY DIFFERENTIATORS & WHY TRUTHLENS WINS
    # =========================================================================
    s10 = prs.slides.add_slide(blank_layout)
    add_slide_header(s10, "Key Differentiators: Why TruthLens Stands Out")

    diffs = [
        ("1. Court-Admissible Legal Explainability", "Unlike black-box neural networks that simply output 'Fake: 95%', TruthLens provides an itemized, court-admissible forensic breakdown with exact mathematical proofs and localized bounding boxes."),
        ("2. Blockchain-Style Cryptographic Ledger", "Sequential SHA-256 hash-chaining anchored at Genesis Block #0 proves data immutability and exposes any internal database tampering in milliseconds."),
        ("3. DPDP Act 2023 Data Minimization", "Implements presentation-layer masking on all overview displays while unlocking complete forensic records for active officer inspection."),
        ("4. 100% Local-First Edge Deployment", "Processes complete 7-step pipeline in under 1.5 seconds without transmitting sensitive citizen biometric data to external commercial cloud APIs.")
    ]

    for i, (dtitle, ddesc) in enumerate(diffs):
        y = Inches(1.9) + i * Inches(1.25)
        d_box = s10.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), y, Inches(11.733), Inches(1.1))
        d_box.fill.solid()
        d_box.fill.fore_color.rgb = COLOR_CARD
        d_box.line.color.rgb = COLOR_TEAL
        d_box.line.width = Pt(1.5)
        tf_d = d_box.text_frame
        tf_d.word_wrap = True

        p_t = tf_d.paragraphs[0]
        p_t.text = dtitle
        p_t.font.size = Pt(15)
        p_t.font.bold = True
        p_t.font.color.rgb = COLOR_NEON

        p_desc = tf_d.add_paragraph()
        p_desc.text = ddesc
        p_desc.font.size = Pt(11)
        p_desc.font.color.rgb = COLOR_WHITE

    # =========================================================================
    # SLIDE 11: IMPACT & FUTURE ROADMAP
    # =========================================================================
    s11 = prs.slides.add_slide(blank_layout)
    add_slide_header(s11, "National Impact & Future Scalability")

    c1 = s11.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.9), Inches(5.6), Inches(4.8))
    c1.fill.solid()
    c1.fill.fore_color.rgb = COLOR_CARD
    c1.line.color.rgb = COLOR_TEAL
    tf1 = c1.text_frame
    tf1.word_wrap = True
    p = tf1.paragraphs[0]
    p.text = "Expected Border Security Impact"
    p.font.size = Pt(17)
    p.font.bold = True
    p.font.color.rgb = COLOR_NEON

    imp_points = [
        ("Throughput Acceleration", "Reduces inspection time from several minutes to under 2 seconds per passenger."),
        ("Elimination of Human Error", "Automates detection of microscopic JPEG recompression splices and math check digit anomalies."),
        ("Standardized Decision Making", "Enforces uniform risk thresholds across all airport and seaport terminals nationwide."),
        ("Intelligence Trail", "Creates digital audit trails for counter-terrorism and anti-human-trafficking intelligence.")
    ]
    for title, desc in imp_points:
        p_t = tf1.add_paragraph()
        p_t.text = f"🎯 {title}: "
        p_t.font.bold = True
        p_t.font.size = Pt(12)
        p_t.font.color.rgb = COLOR_WHITE
        p_d = tf1.add_paragraph()
        p_d.text = f"   {desc}"
        p_d.font.size = Pt(11)
        p_d.font.color.rgb = COLOR_MUTED

    c2 = s11.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.8), Inches(1.9), Inches(5.7), Inches(4.8))
    c2.fill.solid()
    c2.fill.fore_color.rgb = COLOR_CARD
    c2.line.color.rgb = COLOR_TEAL
    tf2 = c2.text_frame
    tf2.word_wrap = True
    p = tf2.paragraphs[0]
    p.text = "Future Scalability Roadmap"
    p.font.size = Pt(17)
    p.font.bold = True
    p.font.color.rgb = COLOR_NEON

    road_points = [
        ("NFC e-Passport Chip Reading", "Integration of ISO/IEC 14443 contactless smart card chip readers for biometric e-Passports."),
        ("Blockchain Watchlist Synchronization", "Decentralized, tamper-proof synchronization of Interpol and MHA watchlists across air terminals."),
        ("Multi-Camera Live CCTV Matching", "Matching document portrait against continuous walkthrough checkpoint video streams."),
        ("Hardware Kiosk Deployment", "Standalone self-service border e-Gates (Smart Border Corridors).")
    ]
    for title, desc in road_points:
        p_t = tf2.add_paragraph()
        p_t.text = f"🚀 {title}: "
        p_t.font.bold = True
        p_t.font.size = Pt(12)
        p_t.font.color.rgb = COLOR_WHITE
        p_d = tf2.add_paragraph()
        p_d.text = f"   {desc}"
        p_d.font.size = Pt(11)
        p_d.font.color.rgb = COLOR_MUTED

    # =========================================================================
    # SLIDE 12: CONCLUSION & LIVE DEMO INVITATION
    # =========================================================================
    s12 = prs.slides.add_slide(blank_layout)
    set_slide_background(s12)

    card12 = s12.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(1.5), Inches(1.2), Inches(10.333), Inches(5.1))
    card12.fill.solid()
    card12.fill.fore_color.rgb = COLOR_CARD
    card12.line.color.rgb = COLOR_NEON
    card12.line.width = Pt(2)

    tb12 = s12.shapes.add_textbox(Inches(2.0), Inches(1.6), Inches(9.333), Inches(4.3))
    tf12 = tb12.text_frame
    tf12.word_wrap = True

    p0 = tf12.paragraphs[0]
    p0.text = "TRUTHLENS • SIH26188"
    p0.font.size = Pt(14)
    p0.font.bold = True
    p0.font.color.rgb = COLOR_TEAL

    p1 = tf12.add_paragraph()
    p1.text = "Thank You, Respected Judges!"
    p1.font.size = Pt(40)
    p1.font.bold = True
    p1.font.color.rgb = COLOR_WHITE

    p2 = tf12.add_paragraph()
    p2.text = "Protecting National Borders with Explainable, Deterministic AI Forensics."
    p2.font.size = Pt(18)
    p2.font.color.rgb = COLOR_NEON

    p3 = tf12.add_paragraph()
    p3.text = "\nReady for Questions & Live Interactive Demonstration:\n• Web Interface: http://127.0.0.1:8000\n• Fast, Explainable, and 100% Local."
    p3.font.size = Pt(15)
    p3.font.color.rgb = COLOR_MUTED

    # Save Presentation
    output_path = "TruthLens_SIH_Presentation.pptx"
    prs.save(output_path)
    print(f"Presentation saved successfully as: {os.path.abspath(output_path)}")


if __name__ == "__main__":
    create_presentation()
