# TruthLens — 3-Minute Live Jury Demo Script
**SIH26188 | Ministry of Home Affairs | Category: Blockchain & Cybersecurity**

This step-by-step script is optimized for a strict **3-minute live evaluation**. Follow the exact clicks and read or adapt the 1-2 sentence spoken lines.

---

### ⏱️ Timeline Overview

| Phase | Time | Action Performed | What it Demonstrates |
| :--- | :--- | :--- | :--- |
| **Intro** | 0:00 – 0:20 | Open Dashboard & Introduce System | High-throughput border e-Gate concept |
| **Demo A** | 0:20 – 1:05 | Scenario 1 (Genuine Passport + Match) | Sub-second clearance, ICAO checksum, SFace biometrics |
| **Demo B** | 1:05 – 1:55 | Scenario 3 (Tampered Passport + Mismatch) | ELA photo splice localization & biometric impersonation |
| **Demo C** | 1:55 – 2:35 | Tab 8 (Screening History) $\rightarrow$ Inspect | DPDP Act 2023 data masking & authorized unmasked dossier |
| **Demo D** | 2:35 – 3:00 | Tab 10 (Audit Integrity) $\rightarrow$ Verify | Cryptographic SHA-256 hash-chain zero-trust audit |

---

### 📋 Pre-Demo Checklist (Do Before Judges Arrive)

1. Ensure the server is running (`python run.py`).
2. Open Chrome/Edge at: [http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard)
3. Ensure you are logged in as an officer (`officer@truthlens.gov.in` / `TruthLens@2025` or `admin@truthlens.gov.in` / `Admin@123`).
4. Start with the browser on **Tab 1 ("Live Border Screening")**.

---

### 🎬 Step-by-Step Live Demo Execution

#### 1. Introduction (0:00 – 0:20)
- **Action:** Point to the dashboard header and the 7-step pipeline breadcrumb.
- **Spoken Line (Say Out Loud):**
  > *"Respected judges, TruthLens is an explainable AI screening system built for border checkpoints and airport e-Gates. It replaces slow, error-prone manual inspection with a 4-layer forensic defense and a blockchain-style audit ledger that clears or flags travelers in under 1.5 seconds."*

---

#### 2. Demo A: Genuine Document Fast Clearance (0:20 – 1:05)
- **Action 1:** In the **"⚡ Quick Demonstration Scenarios"** panel on Tab 1, click **Scenario 1: Genuine Passport + Live Match**.
  *(Notice the sample document and live matching passenger portrait populate automatically)*.
- **Action 2:** Click the large blue button: **Run Border Screening**.
- **Spoken Line (Say Out Loud):**
  > *"First, we test an authentic US Passport with a matching live passenger. In less than 1.5 seconds, the system verifies all cyclic 7-3-1 ICAO check digits, confirms a 62.8% deep facial biometric match using SFace, and awards a clean score of 0 out of 100 — Clear for Transit."*
- **Action 3:** Briefly point to the green **"VERIFIED / LOW RISK"** banner and the extracted OCR table. Click **"Print Certificate"** to show the official border transit certificate modal, then close it.

---

#### 3. Demo B: Digital Photo Splicing & Impersonator Caught (1:05 – 1:55)
- **Action 1:** Click **Scenario 2: Tampered Passport + Impersonation**.
  *(Notice the tampered document and mismatched passenger photo populate)*.
- **Action 2:** Click **Run Border Screening**.
- **Spoken Line (Say Out Loud):**
  > *"Now, watch what happens when a transnational fraudster attempts to cross with a tampered passport where the portrait was digitally spliced and a look-alike passenger is standing at the gate."*
- **Action 3:** Scroll down to the Master Dossier or click **Tab 2 (OCR & Forensics)**:
  - Point to the **Error Level Analysis (ELA) Heatmap**: show the glowing red forensic box directly highlighting the spliced photo (`ALERT: SPLICED PHOTO`).
- **Action 4:** Click **Tab 4 (Facial Biometrics)**:
  - Point to the red **35.3% Biometric Mismatch alert**, catching the impersonator.
- **Spoken Line (Say Out Loud):**
  > *"Notice how TruthLens isn't guessing: our Error Level Analysis localized the microscopic recompression difference on the headshot with a forensic bounding box, and our SFace neural network caught the face mismatch at 35.3%, driving the risk score to 63 — High Risk."*

---

#### 4. Demo C: DPDP Act 2023 Data Masking & Officer Case Inspection (1:55 – 2:35)
- **Action 1:** In the top navigation bar, click **Tab 8: "Screening History"**.
- **Spoken Line (Say Out Loud):**
  > *"For government deployment, data privacy is paramount under the DPDP Act 2023. Notice that in this screening history table, sensitive document numbers are automatically masked as 'XXXX XXXX 9012' or 'XXXXX02C3', while traveler names remain visible for officer identification."*
- **Action 2:** Click the **"Inspect"** button on the latest record.
- **Spoken Line (Say Out Loud):**
  > *"When an officer clicks 'Inspect' to actively adjudicate a case, TruthLens securely reveals the full unmasked document number and complete forensic signals in the Master Dossier."*

---

#### 5. Demo D: Blockchain-Style Cryptographic Audit Ledger (2:35 – 3:00)
- **Action 1:** In the top navigation bar, click **Tab 10: "Audit Integrity"**.
- **Action 2:** Click the blue button: **"🔍 Verify Chain Integrity"**.
- **Action 3:** Point to the glowing green verification banner and the linked block cards below.
- **Spoken Line (Say Out Loud):**
  > *"Finally, every completed screening is cryptographically signed and chained using sequential SHA-256 hashing anchored at Genesis Block #0. Clicking 'Verify' recomputes every block digest from genesis. This green banner proves 100% mathematical integrity — guaranteeing that no corrupt insider has altered any screening record or decision in the database. Thank you!"*

---

### 💡 Pro Tips for a Flawless Live Demo

1. **Keep the Pace:** Do not wait for long explanations. Click the button, and while it executes, speak the corresponding line.
2. **Tab Shortcuts:** If a judge asks to see biometrics or forensics in detail, jump directly to **Tab 2 (OCR & Forensics)**, **Tab 3 (Security Features)**, or **Tab 4 (Facial Biometrics)**.
3. **If Asked About Indian National IDs:** Click **Scenario 4 (Genuine Aadhaar)** or **Scenario 5 (Genuine PAN)** to demonstrate Verhoeff $D_5$ checksums and Income Tax Department format rules.
4. **If Asked About Internet Outages:** Reiterate that TruthLens runs **100% locally on localhost** with zero external cloud API calls.
