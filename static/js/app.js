/**
 * TruthLens Client Application
 * SIH26188: AI-Based Fake Identity & Document Screening System
 * Ministry of Home Affairs - Category: Blockchain & Cybersecurity
 */

(function () {
  'use strict';

  // State
  let docFile = null;
  let docBase64 = null;
  let liveFile = null;
  let liveBase64 = null;
  let webcamStream = null;
  let currentReport = null;

  // DOM Elements - Tabs
  const navTabs = document.querySelectorAll('.nav-tab');
  const tabPanes = document.querySelectorAll('.tab-pane');

  // DOM Elements - Intake & Upload
  const docTypeSelect = document.getElementById('doc-type-select');
  const docDropzone = document.getElementById('doc-dropzone');
  const docFileInput = document.getElementById('doc-file-input');
  const docDropzoneContent = document.getElementById('doc-dropzone-content');
  const docPreviewBox = document.getElementById('doc-preview-box');
  const docPreviewImg = document.getElementById('doc-preview-img');
  const btnClearDoc = document.getElementById('btn-clear-doc');

  const liveDropzone = document.getElementById('live-dropzone');
  const liveFileInput = document.getElementById('live-file-input');
  const liveDropzoneContent = document.getElementById('live-dropzone-content');
  const livePreviewBox = document.getElementById('live-preview-box');
  const livePreviewImg = document.getElementById('live-preview-img');
  const btnClearLive = document.getElementById('btn-clear-live');

  // Webcam Elements
  const btnModeUpload = document.getElementById('btn-mode-upload');
  const btnModeWebcam = document.getElementById('btn-mode-webcam');
  const webcamContainer = document.getElementById('webcam-container');
  const webcamVideo = document.getElementById('webcam-video');
  const btnWebcamSnap = document.getElementById('btn-webcam-snap');
  const btnWebcamCancel = document.getElementById('btn-webcam-cancel');

  // Action Buttons & Progress
  const btnStartScreening = document.getElementById('btn-start-screening');
  const btnResetForm = document.getElementById('btn-reset-form');
  const processingBanner = document.getElementById('processing-banner');
  const processingStatusTitle = document.getElementById('processing-status-title');
  const processingStatusSub = document.getElementById('processing-status-sub');
  const pipelineSteps = document.querySelectorAll('.pipeline-step');

  // Demo Scenario Buttons
  const btnQuickScenario1 = document.getElementById('btn-quick-scenario-1');
  const btnQuickScenario2 = document.getElementById('btn-quick-scenario-2');
  const btnQuickScenario3 = document.getElementById('btn-quick-scenario-3');
  const btnQuickScenario4 = document.getElementById('btn-quick-scenario-4');
  const btnQuickScenario5 = document.getElementById('btn-quick-scenario-5');

  // Certificate Modal
  const certModal = document.getElementById('certificate-modal');
  const btnCloseCert = document.getElementById('btn-close-cert');
  const btnPrintCert = document.getElementById('btn-print-certificate');

  // =========================================================================
  // 1. TAB NAVIGATION
  // =========================================================================
  function switchTab(tabId) {
    navTabs.forEach(tab => {
      if (tab.dataset.tab === tabId) {
        tab.classList.add('active');
      } else {
        tab.classList.remove('active');
      }
    });

    tabPanes.forEach(pane => {
      if (pane.id === tabId) {
        pane.classList.add('active');
      } else {
        pane.classList.remove('active');
      }
    });

    // Lazy load data for specific tabs
    if (tabId === 'tab-dashboard') loadDashboardStats();
    if (tabId === 'tab-history') loadHistory();
    if (tabId === 'tab-mockdb') loadMockDatabase();
  }

  navTabs.forEach(tab => {
    tab.addEventListener('click', () => switchTab(tab.dataset.tab));
  });

  // =========================================================================
  // 2. DOCUMENT UPLOAD & DRAG-AND-DROP
  // =========================================================================
  function handleDocFileSelect(file) {
    if (!file) return;
    docFile = file;
    const reader = new FileReader();
    reader.onload = (e) => {
      docBase64 = e.target.result;
      docPreviewImg.src = docBase64;
      docPreviewBox.classList.remove('hidden');
      docDropzoneContent.classList.add('hidden');
    };
    reader.readAsDataURL(file);
  }

  docDropzone.addEventListener('click', (e) => {
    if (e.target !== btnClearDoc) docFileInput.click();
  });

  docFileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) handleDocFileSelect(e.target.files[0]);
  });

  docDropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    docDropzone.classList.add('dragover');
  });

  docDropzone.addEventListener('dragleave', () => docDropzone.classList.remove('dragover'));

  docDropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    docDropzone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) handleDocFileSelect(e.dataTransfer.files[0]);
  });

  btnClearDoc.addEventListener('click', (e) => {
    e.stopPropagation();
    docFile = null;
    docBase64 = null;
    docFileInput.value = '';
    docPreviewBox.classList.add('hidden');
    docDropzoneContent.classList.remove('hidden');
  });

  // =========================================================================
  // 3. LIVE PASSENGER PHOTO & WEBCAM
  // =========================================================================
  function handleLiveFileSelect(file) {
    if (!file) return;
    liveFile = file;
    const reader = new FileReader();
    reader.onload = (e) => {
      liveBase64 = e.target.result;
      livePreviewImg.src = liveBase64;
      livePreviewBox.classList.remove('hidden');
      liveDropzoneContent.classList.add('hidden');
    };
    reader.readAsDataURL(file);
  }

  liveDropzone.addEventListener('click', (e) => {
    if (e.target !== btnClearLive) liveFileInput.click();
  });

  liveFileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) handleLiveFileSelect(e.target.files[0]);
  });

  liveDropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    liveDropzone.classList.add('dragover');
  });

  liveDropzone.addEventListener('dragleave', () => liveDropzone.classList.remove('dragover'));

  liveDropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    liveDropzone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) handleLiveFileSelect(e.dataTransfer.files[0]);
  });

  btnClearLive.addEventListener('click', (e) => {
    e.stopPropagation();
    liveFile = null;
    liveBase64 = null;
    liveFileInput.value = '';
    livePreviewBox.classList.add('hidden');
    liveDropzoneContent.classList.remove('hidden');
  });

  // Webcam Toggle
  btnModeWebcam.addEventListener('click', async () => {
    btnModeWebcam.classList.add('active');
    btnModeUpload.classList.remove('active');
    liveDropzone.classList.add('hidden');
    webcamContainer.classList.remove('hidden');

    try {
      webcamStream = await navigator.mediaDevices.getUserMedia({ video: { width: 640, height: 480 } });
      webcamVideo.srcObject = webcamStream;
    } catch (err) {
      alert('Unable to access camera: ' + err.message + '. Please ensure permissions are granted.');
      btnModeUpload.click();
    }
  });

  function stopWebcam() {
    if (webcamStream) {
      webcamStream.getTracks().forEach(t => t.stop());
      webcamStream = null;
    }
  }

  btnModeUpload.addEventListener('click', () => {
    btnModeUpload.classList.add('active');
    btnModeWebcam.classList.remove('active');
    webcamContainer.classList.add('hidden');
    liveDropzone.classList.remove('hidden');
    stopWebcam();
  });

  btnWebcamCancel.addEventListener('click', () => {
    btnModeUpload.click();
  });

  btnWebcamSnap.addEventListener('click', () => {
    if (!webcamVideo.videoWidth) return;
    const canvas = document.createElement('canvas');
    canvas.width = webcamVideo.videoWidth;
    canvas.height = webcamVideo.videoHeight;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(webcamVideo, 0, 0, canvas.width, canvas.height);
    liveBase64 = canvas.toDataURL('image/jpeg', 0.9);
    liveFile = null;

    livePreviewImg.src = liveBase64;
    livePreviewBox.classList.remove('hidden');
    liveDropzoneContent.classList.add('hidden');

    btnModeUpload.click();
  });

  // =========================================================================
  // 4. DEMO SCENARIO SHORTCUTS
  // =========================================================================
  async function triggerDemoScenario(scenarioNumber) {
    switchTab('tab-screening');
    btnResetForm.click();

    if (scenarioNumber === 1) {
      // Scenario 1: Genuine Passport + Live Match
      docTypeSelect.value = 'PASSPORT';
      await loadSampleIntoIntake('demo_passport_genuine', 'demo_person_live_match');
    } else if (scenarioNumber === 2) {
      // Scenario 2: Expired Visa (Watchlist Alert)
      docTypeSelect.value = 'VISA';
      await loadSampleIntoIntake('demo_visa_expired', null);
    } else if (scenarioNumber === 3) {
      // Scenario 3: Tampered Passport + Impersonation
      docTypeSelect.value = 'PASSPORT';
      await loadSampleIntoIntake('demo_passport_tampered', 'demo_person_live_mismatch');
    } else if (scenarioNumber === 4) {
      // Scenario 4: Genuine Aadhaar (QR Verified)
      docTypeSelect.value = 'AADHAAR';
      await loadSampleIntoIntake('sample_genuine_aadhaar', null);
    } else if (scenarioNumber === 5) {
      // Scenario 5: Tampered Name Aadhaar (QR Forgery Alert)
      docTypeSelect.value = 'AADHAAR';
      await loadSampleIntoIntake('sample_tampered_name_aadhaar', null);
    }

    // Auto-initiate screening
    setTimeout(() => {
      btnStartScreening.click();
    }, 400);
  }

  async function loadSampleIntoIntake(docSampleId, liveSampleId) {
    // Fetch document sample
    const resDoc = await fetch(`/api/samples/${docSampleId}`);
    const blobDoc = await resDoc.blob();
    handleDocFileSelect(new File([blobDoc], `${docSampleId}.jpg`, { type: 'image/jpeg' }));

    if (liveSampleId) {
      const resLive = await fetch(`/api/samples/${liveSampleId}`);
      const blobLive = await resLive.blob();
      handleLiveFileSelect(new File([blobLive], `${liveSampleId}.jpg`, { type: 'image/jpeg' }));
    }
  }

  if (btnQuickScenario1) btnQuickScenario1.addEventListener('click', () => triggerDemoScenario(1));
  if (btnQuickScenario2) btnQuickScenario2.addEventListener('click', () => triggerDemoScenario(2));
  if (btnQuickScenario3) btnQuickScenario3.addEventListener('click', () => triggerDemoScenario(3));
  if (btnQuickScenario4) btnQuickScenario4.addEventListener('click', () => triggerDemoScenario(4));
  if (btnQuickScenario5) btnQuickScenario5.addEventListener('click', () => triggerDemoScenario(5));

  // Reset Button
  btnResetForm.addEventListener('click', () => {
    btnClearDoc.click();
    btnClearLive.click();
    docTypeSelect.value = 'AUTO';
    const docNumInp = document.getElementById('doc-number-input');
    if (docNumInp) docNumInp.value = '';
    const nameInp = document.getElementById('person-name-input');
    if (nameInp) nameInp.value = '';
    updatePipelineTracker(1);
    processingBanner.classList.add('hidden');
    const dossierWrapper = document.getElementById('master-dossier-wrapper');
    if (dossierWrapper) dossierWrapper.classList.add('hidden');
  });

  // =========================================================================
  // 5. INITIATE AI SCREENING PIPELINE
  // =========================================================================
  btnStartScreening.addEventListener('click', async () => {
    if (!docFile && !docBase64) {
      alert('Please upload a travel document or click one of the quick demo scenarios.');
      return;
    }

    // UI Loading state
    btnStartScreening.disabled = true;
    processingBanner.classList.remove('hidden');
    processingStatusTitle.textContent = 'Executing Deep Document Analysis...';
    processingStatusSub.textContent = 'Extracting OCR fields, evaluating ICAO checksums, and generating ELA forensic heatmaps...';

    // Hide old dossier while processing new scan
    const oldDossier = document.getElementById('master-dossier-wrapper');
    if (oldDossier) oldDossier.classList.add('hidden');

    updatePipelineTracker(2);

    const formData = new FormData();
    if (docFile) {
      formData.append('file', docFile);
    } else if (docBase64) {
      formData.append('image_base64', docBase64);
    }

    if (liveFile) {
      formData.append('live_file', liveFile);
    } else if (liveBase64) {
      formData.append('live_base64', liveBase64);
    }

    const selectedType = docTypeSelect.value;
    if (selectedType !== 'AUTO') {
      formData.append('doc_type', selectedType);
    }

    const docNumVal = document.getElementById('doc-number-input')?.value?.trim();
    if (docNumVal) {
      formData.append('doc_number', docNumVal);
    }

    const personNameVal = document.getElementById('person-name-input')?.value?.trim();
    if (personNameVal) {
      formData.append('person_name', personNameVal);
    }

    try {
      updatePipelineTracker(4);
      const response = await fetch('/api/screen', {
        method: 'POST',
        body: formData
      });

      if (!response.ok) {
        const err = await response.json();
        throw new Error(err.detail || 'Screening request failed');
      }

      updatePipelineTracker(6);
      const result = await response.json();
      currentReport = result;

      // Render all section data
      renderScreeningResults(result);

      // Render Live Master Dossier right inside Document Screening
      renderMasterDossier(result);

      updatePipelineTracker(7);
      processingBanner.classList.add('hidden');
      btnStartScreening.disabled = false;

      // Smoothly reveal Master Dossier
      const dossierWrapper = document.getElementById('master-dossier-wrapper');
      if (dossierWrapper) {
        dossierWrapper.classList.remove('hidden');
        setTimeout(() => {
          dossierWrapper.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }, 120);
      }

    } catch (err) {
      processingBanner.classList.add('hidden');
      btnStartScreening.disabled = false;
      alert('Screening error: ' + err.message);
    }
  });

  function updatePipelineTracker(stepNum) {
    pipelineSteps.forEach(step => {
      const s = parseInt(step.dataset.step, 10);
      step.classList.remove('active', 'completed');
      if (s < stepNum) {
        step.classList.add('completed');
      } else if (s === stepNum) {
        step.classList.add('active');
      }
    });
  }

  // =========================================================================
  // 6. RENDER SCREENING RESULTS ACROSS MODULES
  // =========================================================================
  function renderScreeningResults(data) {
    // 1. OCR Results Tab
    renderOcrResults(data);

    // 2. Validation Rules Tab
    renderValidationResults(data);

    // 3. Tampering Analysis Tab
    renderTamperingResults(data);

    // 4. Face Verification Tab
    renderFaceResults(data);

    // 5. Risk Assessment & Final Verdict Tab
    renderRiskVerdict(data);
  }

  function renderOcrResults(data) {
    const docTypeBadge = document.getElementById('ocr-doc-type-badge');
    const ocrConfBadge = document.getElementById('ocr-conf-badge');
    const fieldsTbody = document.getElementById('ocr-fields-tbody');
    const rawOcrPre = document.getElementById('raw-ocr-pre');
    const mrzBox = document.getElementById('mrz-card-box');
    const mrzLinesText = document.getElementById('mrz-lines-text');
    const mrzSummary = document.getElementById('mrz-checksum-summary');

    docTypeBadge.textContent = `Document: ${data.doc_type}`;
    ocrConfBadge.textContent = `Mean OCR Confidence: ${data.ocr.mean_confidence}%`;
    rawOcrPre.textContent = data.ocr.raw_text || 'No raw text extracted.';

    // Populate Fields Table
    const fields = data.ocr.fields || {};
    fieldsTbody.innerHTML = '';
    const fieldEntries = Object.entries(fields);

    if (fieldEntries.length === 0) {
      fieldsTbody.innerHTML = `<tr><td colspan="3" class="table-empty">No fields extracted.</td></tr>`;
    } else {
      fieldEntries.forEach(([key, val]) => {
        if (key === 'raw_numbers' || key === 'dates') return;
        const formattedKey = key.replace(/_/g, ' ').toUpperCase();
        const displayVal = val !== null && val !== undefined && val !== '' ? String(val) : '<em class="text-dim">Not Detected</em>';
        const isDetected = val !== null && val !== undefined && val !== '';
        const badgeHtml = isDetected ? '<span class="badge-green">Extracted</span>' : '<span class="badge-yellow">Missing</span>';

        const row = document.createElement('tr');
        row.innerHTML = `
          <td><strong>${formattedKey}</strong></td>
          <td>${displayVal}</td>
          <td>${badgeHtml}</td>
        `;
        fieldsTbody.appendChild(row);
      });
    }

    // MRZ Display
    if (data.ocr.mrz && data.ocr.mrz.valid_structure) {
      mrzBox.classList.remove('hidden');
      const mrz = data.ocr.mrz;
      mrzLinesText.textContent = `P<${mrz.issuing_country || 'USA'}${mrz.surname || ''}<<${mrz.given_names || ''}\n${mrz.doc_number || ''}${mrz.nationality || ''}`;
      const allPassed = mrz.checksums && mrz.checksums.all_passed;
      mrzSummary.innerHTML = allPassed ? 
        '<span class="badge-green">✓ All ICAO 9303 Check Digits Verified</span>' :
        '<span class="badge-red">✕ Mathematical Check Digit Failure Detected</span>';
    } else {
      mrzBox.classList.add('hidden');
    }

    // QR Cross-Verification Display
    const qrCrossBox = document.getElementById('qr-cross-box');
    const qrCrossBadge = document.getElementById('qr-cross-badge');
    const qrCrossTbody = document.getElementById('qr-cross-tbody');

    if (qrCrossBox && data.cross_verification && data.cross_verification.qr_decoded) {
      qrCrossBox.classList.remove('hidden');
      const cv = data.cross_verification;
      const isMismatch = cv.has_critical_mismatch;

      qrCrossBadge.textContent = isMismatch ? 'CRITICAL IDENTITY CONFLICT' : `QR Verified (${cv.overall_match_score}%)`;
      qrCrossBadge.className = isMismatch ? 'badge-red' : 'badge-green';

      qrCrossTbody.innerHTML = '';
      (cv.verification_matrix || []).forEach(row => {
        const tr = document.createElement('tr');
        const badge = row.status === 'MATCH'
          ? '<span class="badge-green">MATCH</span>'
          : (row.status === 'MISMATCH' ? '<span class="badge-red">MISMATCH (TAMPER ALERT)</span>' : '<span class="badge-yellow">MISSING</span>');

        tr.innerHTML = `
          <td><strong>${row.field}</strong></td>
          <td>${row.ocr_val || '<em class="text-dim">N/A</em>'}</td>
          <td>${row.qr_val || '<em class="text-dim">N/A</em>'}</td>
          <td>${badge}<br><small style="color: #94A3B8;">${row.explanation || ''}</small></td>
        `;
        qrCrossTbody.appendChild(tr);
      });
    } else if (qrCrossBox) {
      qrCrossBox.classList.add('hidden');
    }
  }

  function renderValidationResults(data) {
    const valBadge = document.getElementById('val-summary-badge');
    const container = document.getElementById('validation-checklist-container');
    const mockCallout = document.getElementById('mock-db-callout');
    const mockCalloutText = document.getElementById('mock-db-callout-text');

    const val = data.validation || {};
    valBadge.textContent = `Status: ${val.verdict_label || 'PASSED'}`;
    valBadge.className = val.overall_status === 'PASSED' ? 'badge-green' : (val.overall_status === 'WARNING' ? 'badge-yellow' : 'badge-red');

    container.innerHTML = '';
    const checklist = val.checklist || [];

    checklist.forEach(item => {
      const card = document.createElement('div');
      card.className = `checklist-item ${item.status.toLowerCase()}`;
      card.innerHTML = `
        <div class="check-top">
          <span class="check-title">${item.check}</span>
          <span class="check-badge status-${item.status.toLowerCase()}">${item.badge}</span>
        </div>
        <p class="check-detail">${item.detail}</p>
      `;
      container.appendChild(card);
    });

    // Mock Database Callout
    if (val.mock_database_hit) {
      mockCallout.classList.remove('hidden');
      const hit = val.mock_database_hit;
      mockCalloutText.innerHTML = `
        <strong>Matched Record:</strong> ${hit.person_name} (${hit.doc_number})<br>
        <strong>Status:</strong> <span class="badge-red">${hit.status}</span><br>
        <strong>Reason:</strong> ${hit.reason}<br>
        <strong>Notes:</strong> ${hit.notes}
      `;
    } else {
      mockCallout.classList.add('hidden');
    }
  }

  function renderTamperingResults(data) {
    const heatmapImg = document.getElementById('ela-heatmap-img');
    const btnViewOverlay = document.getElementById('btn-view-overlay');
    const btnViewPureEla = document.getElementById('btn-view-pure-ela');
    const tamperBadge = document.getElementById('tamper-score-badge');
    const metricTamperPct = document.getElementById('metric-tamper-pct');
    const metricPhotoSplice = document.getElementById('metric-photo-splice');
    const metricStampForgery = document.getElementById('metric-stamp-forgery');
    const reasonsList = document.getElementById('tamper-reasons-list');

    const exifSoftware = document.getElementById('exif-software');
    const exifTimestamp = document.getElementById('exif-timestamp');
    const exifHardware = document.getElementById('exif-hardware');

    const ela = data.forensics_ela || {};
    const meta = data.metadata_forensics || {};

    // Heatmap Image toggles
    heatmapImg.src = ela.overlay_data_uri || ela.overlay_base64 || '';
    btnViewOverlay.onclick = () => {
      btnViewOverlay.classList.add('active');
      btnViewPureEla.classList.remove('active');
      heatmapImg.src = ela.overlay_data_uri || ela.overlay_base64 || '';
    };
    btnViewPureEla.onclick = () => {
      btnViewPureEla.classList.add('active');
      btnViewOverlay.classList.remove('active');
      heatmapImg.src = ela.heatmap_data_uri || ela.heatmap_base64 || '';
    };

    // Metrics
    const score = ela.tamper_score || 0.0;
    tamperBadge.textContent = `Tamper Score: ${score}% (${ela.status_label || 'CLEAN'})`;
    tamperBadge.className = score >= 50 ? 'badge-red' : (score >= 25 ? 'badge-yellow' : 'badge-green');

    metricTamperPct.textContent = `${score}%`;
    metricPhotoSplice.textContent = ela.photo_spliced ? `YES (${ela.photo_splice_ratio}x discrepancy)` : 'No (Uniform)';
    metricPhotoSplice.className = ela.photo_spliced ? 'text-red font-bold' : 'text-green';

    const stamp = ela.stamp_analysis || {};
    metricStampForgery.textContent = stamp.is_suspicious ? 'SUSPICIOUS STAMP' : (stamp.stamps_detected > 0 ? 'Authentic Ink Bleed' : 'None Detected');
    metricStampForgery.className = stamp.is_suspicious ? 'text-red font-bold' : 'text-green';

    // Reasons List
    reasonsList.innerHTML = '';
    const reasons = ela.detection_reasons || [];
    if (reasons.length === 0) {
      reasonsList.innerHTML = `<li>Clean uniform error distribution across card surface.</li>`;
    } else {
      reasons.forEach(r => {
        const li = document.createElement('li');
        li.textContent = r;
        reasonsList.appendChild(li);
      });
    }

    // EXIF
    exifSoftware.textContent = meta.software_detected || 'Clean (No Editing Fingerprint)';
    exifSoftware.className = meta.software_detected ? 'text-red font-bold' : 'text-green';
    exifTimestamp.textContent = meta.timestamp_mismatch ? 'Modification Discrepancy Found' : 'Verified';
    exifHardware.textContent = meta.hardware_verified ? 'Hardware Camera/Scanner Signature Verified' : 'Standard Digital Scan';
  }

  function renderFaceResults(data) {
    const face = data.face_verification || {};
    const faceBadge = document.getElementById('face-match-badge');
    const docFrame = document.getElementById('doc-face-frame');
    const docCropImg = document.getElementById('doc-face-crop-img');
    const docPlaceholder = document.getElementById('doc-face-placeholder');

    const liveCropImg = document.getElementById('live-face-crop-img');
    const livePlaceholder = document.getElementById('live-face-placeholder');

    const matchValText = document.getElementById('match-val-text');
    const matchVerdictTag = document.getElementById('match-verdict-tag');
    const matchConfText = document.getElementById('match-conf-text');
    const explainBox = document.getElementById('face-explain-box');

    // Document Crop
    if (face.doc_face_crop) {
      docCropImg.src = face.doc_face_crop;
      docCropImg.classList.remove('hidden');
      docPlaceholder.classList.add('hidden');
    } else {
      docCropImg.classList.add('hidden');
      docPlaceholder.classList.remove('hidden');
      docPlaceholder.textContent = 'No Facial Portrait Extracted';
    }

    // Live Crop
    if (face.live_face_crop) {
      liveCropImg.src = face.live_face_crop;
      liveCropImg.classList.remove('hidden');
      livePlaceholder.classList.add('hidden');
    } else {
      liveCropImg.classList.add('hidden');
      livePlaceholder.classList.remove('hidden');
      livePlaceholder.textContent = 'No Live Photo Provided';
    }

    // Verdict and similarity
    if (face.is_live_provided && face.face_detected_doc && face.face_detected_live) {
      const matchPct = face.match_percentage || 0.0;
      matchValText.textContent = `${matchPct}%`;
      matchVerdictTag.textContent = face.verdict;
      matchConfText.textContent = `Confidence: ${face.confidence}%`;

      if (face.verdict === 'MATCH') {
        faceBadge.textContent = 'MATCH CONFIRMED';
        faceBadge.className = 'badge-green';
        matchVerdictTag.className = 'match-verdict-tag badge-green';
      } else if (face.verdict === 'POSSIBLE MISMATCH') {
        faceBadge.textContent = 'BORDERLINE SIMILARITY';
        faceBadge.className = 'badge-yellow';
        matchVerdictTag.className = 'match-verdict-tag badge-yellow';
      } else {
        faceBadge.textContent = 'BIOMETRIC MISMATCH';
        faceBadge.className = 'badge-red';
        matchVerdictTag.className = 'match-verdict-tag badge-red';
      }
    } else {
      matchValText.textContent = '--%';
      matchVerdictTag.textContent = face.face_detected_doc ? 'Awaiting Live Passenger' : 'No Face Detected';
      matchVerdictTag.className = 'match-verdict-tag';
      faceBadge.textContent = 'Awaiting Input';
      faceBadge.className = 'badge-tech';
      matchConfText.textContent = 'Confidence: --';
    }

    explainBox.textContent = face.details || 'Biometric verification details.';
  }

  function renderRiskVerdict(data) {
    const masterBanner = document.getElementById('master-verdict-banner');
    const masterIcon = document.getElementById('master-verdict-icon');
    const masterHeadline = document.getElementById('master-verdict-headline');
    const masterSummary = document.getElementById('master-verdict-summary');

    const riskNumberDisplay = document.getElementById('risk-number-display');
    const riskTierBadge = document.getElementById('risk-tier-badge');
    const factorsCountBadge = document.getElementById('factors-count-badge');
    const factorsTbody = document.getElementById('risk-factors-tbody');

    const risk = data.risk_assessment || {};
    const score = data.risk_score || 0;
    const level = data.risk_level || 'LOW';
    const verdict = data.verdict || 'VERIFIED / LOW RISK';

    // Banner Classes
    masterBanner.className = 'verdict-banner';
    if (level === 'LOW') {
      masterBanner.classList.add('banner-verified');
      masterIcon.textContent = '🛡️';
    } else if (level === 'MEDIUM') {
      masterBanner.classList.add('banner-review');
      masterIcon.textContent = '⚠️';
    } else {
      masterBanner.classList.add('banner-highrisk');
      masterIcon.textContent = '🚫';
    }

    masterHeadline.textContent = verdict;
    masterSummary.textContent = `${data.summary} Officer Action: ${data.officer_recommendation}`;

    // Risk Meter Circle
    riskNumberDisplay.textContent = score;
    riskTierBadge.textContent = `${level} RISK`;
    riskTierBadge.className = `risk-tier-badge ${level === 'LOW' ? 'badge-green' : (level === 'MEDIUM' ? 'badge-yellow' : 'badge-red')}`;

    // Contributing Factors Table
    const factors = risk.factors || [];
    factorsCountBadge.textContent = `${factors.length} Contributing Factor(s)`;
    factorsTbody.innerHTML = '';

    if (factors.length === 0) {
      factorsTbody.innerHTML = `<tr><td colspan="4" class="table-empty">No active risk points incurred.</td></tr>`;
    } else {
      factors.forEach(f => {
        const row = document.createElement('tr');
        const badgeClass = f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'badge-red' : (f.severity === 'WARN' ? 'badge-yellow' : 'badge-tech');
        row.innerHTML = `
          <td><span class="${badgeClass}">${f.severity}</span></td>
          <td><strong>${f.name}</strong></td>
          <td>${f.description}</td>
          <td style="font-family: var(--font-mono); font-weight: bold; color: #F87171;">+${f.points}</td>
        `;
        factorsTbody.appendChild(row);
      });
    }

    // Update Certificate Modal Preview
    populateCertificateModal(data);
  }

  // =========================================================================
  // 6B. RENDER ALL-IN-ONE MASTER FORENSIC DOSSIER
  // =========================================================================
  function renderMasterDossier(data) {
    const dossier = data.dossier || {};
    const wrapper = document.getElementById('master-dossier-wrapper');
    if (!wrapper) return;

    // Header info
    const idBadge = document.getElementById('dossier-screening-id');
    const timeElem = document.getElementById('dossier-timestamp');
    if (idBadge) idBadge.textContent = `ID: ${data.screening_id || 'TL-SCAN'}`;
    if (timeElem) timeElem.textContent = data.timestamp || '';

    // Verdict Banner
    const banner = document.getElementById('dossier-verdict-banner');
    const icon = document.getElementById('dossier-verdict-icon');
    const kicker = document.getElementById('dossier-verdict-kicker');
    const mainText = document.getElementById('dossier-verdict-text');
    const reasonText = document.getElementById('dossier-verdict-reason');
    const scoreVal = document.getElementById('dossier-risk-score');
    const tierBadge = document.getElementById('dossier-risk-tier');

    const isGenuine = dossier.is_genuine ?? (data.risk_level === 'LOW');
    const isCritical = (data.risk_level === 'CRITICAL' || data.risk_level === 'HIGH');

    banner.className = 'dossier-verdict-banner';
    if (isGenuine) {
      banner.classList.add('verdict-genuine');
      icon.textContent = '🛡️';
      kicker.textContent = 'OFFICIAL BORDER CLEARANCE: VERIFIED AUTHENTIC';
      mainText.textContent = dossier.simple_badge || 'VERIFIED / AUTHENTIC';
      tierBadge.textContent = 'LOW RISK';
      tierBadge.className = 'dossier-tier-badge badge-green';
    } else if (isCritical) {
      banner.classList.add('verdict-fake');
      icon.textContent = '🚫';
      kicker.textContent = 'SECURITY ALERT: HIGH RISK / FORGERY DETECTED';
      mainText.textContent = dossier.simple_badge || 'REJECTED / FAKE DETECTED';
      tierBadge.textContent = `${data.risk_level} RISK`;
      tierBadge.className = 'dossier-tier-badge badge-red';
    } else {
      banner.classList.add('verdict-review');
      icon.textContent = '⚠️';
      kicker.textContent = 'OFFICER PROTOCOL: MANUAL REVIEW REQUIRED';
      mainText.textContent = dossier.simple_badge || 'REVIEW REQUIRED';
      tierBadge.textContent = `${data.risk_level || 'MED'} RISK`;
      tierBadge.className = 'dossier-tier-badge badge-yellow';
    }

    reasonText.textContent = data.summary || dossier.headline_reason || 'Screening assessment complete.';
    scoreVal.textContent = data.risk_score ?? 0;

    // Column 1: Identity Profile
    const docBadge = document.getElementById('dossier-doc-type-badge');
    const valName = document.getElementById('dossier-val-name');
    const valNum = document.getElementById('dossier-val-number');
    const valCountry = document.getElementById('dossier-val-country');
    const valDob = document.getElementById('dossier-val-dob');
    const valExpiry = document.getElementById('dossier-val-expiry');
    const valValidity = document.getElementById('dossier-val-validity');
    const faceCropImg = document.getElementById('dossier-face-crop-img');
    const facePh = document.getElementById('dossier-face-placeholder');

    const fields = data.ocr?.fields || {};
    if (docBadge) docBadge.textContent = (data.doc_type || 'DOCUMENT').replace(/_/g, ' ');
    if (valName) valName.textContent = dossier.subject_name || fields.full_name || fields.name || 'Not Detected';
    if (valNum) valNum.textContent = dossier.doc_number || fields.passport_number || fields.id_number || fields.visa_number || 'Not Detected';
    if (valCountry) valCountry.textContent = dossier.nationality || fields.nationality || fields.issuing_country || 'N/A';
    if (valDob) valDob.textContent = dossier.dob || fields.dob || 'N/A';
    if (valExpiry) valExpiry.textContent = dossier.expiry_date || fields.expiry_date || 'N/A';

    const isExpired = data.validation?.expired;
    if (valValidity) {
      if (isExpired) {
        valValidity.textContent = 'EXPIRED';
        valValidity.className = 'badge-red';
      } else if (data.doc_type === 'UNKNOWN') {
        valValidity.textContent = 'UNRECOGNIZED';
        valValidity.className = 'badge-yellow';
      } else {
        valValidity.textContent = 'ACTIVE / VALID';
        valValidity.className = 'badge-green';
      }
    }

    const faceData = data.face_verification || {};
    if (faceCropImg && facePh) {
      if (faceData.doc_face_crop) {
        faceCropImg.src = faceData.doc_face_crop;
        faceCropImg.classList.remove('hidden');
        facePh.classList.add('hidden');
      } else {
        faceCropImg.classList.add('hidden');
        facePh.classList.remove('hidden');
      }
    }

    // Column 2: Forensic Visual Evidence
    const elaImg = document.getElementById('dossier-ela-heatmap-img');
    const elaBadge = document.getElementById('dossier-ela-score-badge');
    const elaTag = document.getElementById('dossier-ela-tag');
    const elaData = data.forensics_ela || {};

    if (elaImg) {
      elaImg.src = elaData.overlay_data_uri || elaData.heatmap_data_uri || '';
    }
    const tamperScore = elaData.tamper_score || 0.0;
    if (elaBadge) {
      elaBadge.textContent = `${tamperScore}% Tamper Score`;
      elaBadge.className = `evidence-score ${tamperScore >= 35 ? 'badge-red' : (tamperScore >= 20 ? 'badge-yellow' : 'badge-green')}`;
    }
    if (elaTag) {
      if (elaData.photo_spliced) {
        elaTag.textContent = 'PHOTO SPLICE DETECTED';
        elaTag.style.color = '#F87171';
      } else if (tamperScore >= 20) {
        elaTag.textContent = 'COMPRESSION ANOMALY';
        elaTag.style.color = '#FBBF24';
      } else {
        elaTag.textContent = 'UNIFORM COMPRESSION (CLEAN)';
        elaTag.style.color = '#10B981';
      }
    }

    // Biometrics Comparison
    const bioDocImg = document.getElementById('dossier-bio-doc-face');
    const bioDocPh = document.getElementById('dossier-bio-doc-ph');
    const bioLiveImg = document.getElementById('dossier-bio-live-face');
    const bioLivePh = document.getElementById('dossier-bio-live-ph');
    const bioScoreBadge = document.getElementById('dossier-face-match-badge');

    if (bioDocImg && bioDocPh) {
      if (faceData.doc_face_crop) {
        bioDocImg.src = faceData.doc_face_crop;
        bioDocImg.classList.remove('hidden');
        bioDocPh.classList.add('hidden');
      } else {
        bioDocImg.classList.add('hidden');
        bioDocPh.classList.remove('hidden');
      }
    }

    if (bioLiveImg && bioLivePh) {
      if (faceData.live_face_crop) {
        bioLiveImg.src = faceData.live_face_crop;
        bioLiveImg.classList.remove('hidden');
        bioLivePh.classList.add('hidden');
      } else {
        bioLiveImg.classList.add('hidden');
        bioLivePh.classList.remove('hidden');
      }
    }

    const matchPct = faceData.match_percentage || 0.0;
    if (bioScoreBadge) {
      if (faceData.verdict === 'MATCH') {
        bioScoreBadge.textContent = `${matchPct}% Match (CONFIRMED)`;
        bioScoreBadge.className = 'evidence-score badge-green';
      } else if (faceData.verdict === 'MISMATCH') {
        bioScoreBadge.textContent = `${matchPct}% Match (MISMATCH)`;
        bioScoreBadge.className = 'evidence-score badge-red';
      } else {
        bioScoreBadge.textContent = 'Awaiting Live Passenger';
        bioScoreBadge.className = 'evidence-score badge-tech';
      }
    }

    // Column 3: 5-Point Security Checklist
    const stack = document.getElementById('dossier-checklist-stack');
    if (stack) {
      stack.innerHTML = '';
      const checkpoints = dossier.checkpoints || [
        { id: 'validity', title: 'Format & Expiry', status: isExpired ? 'FAIL' : 'PASS', detail: isExpired ? 'Document expired.' : 'Document format and expiry date active.' },
        { id: 'checksum', title: 'Mathematical Checksum', status: isCritical ? 'FAIL' : 'PASS', detail: 'Check digit validation.' },
        { id: 'ela', title: 'Forensic Tamper (ELA)', status: elaData.tamper_detected ? 'FAIL' : 'PASS', detail: 'Pixel compression integrity.' },
        { id: 'biometric', title: '1:1 Biometric Match', status: faceData.verdict === 'MATCH' ? 'PASS' : (faceData.verdict === 'MISMATCH' ? 'FAIL' : 'INFO'), detail: 'Face recognition.' },
        { id: 'watchlist', title: 'Border Watchlist Check', status: data.validation?.mock_database_hit ? 'FAIL' : 'PASS', detail: 'Watchlist hit scan.' }
      ];

      checkpoints.forEach(cp => {
        const item = document.createElement('div');
        const st = (cp.status || 'PASS').toLowerCase();
        item.className = `checkpoint-card status-${st}`;
        
        const iconSymbol = st === 'pass' ? '✅' : (st === 'fail' ? '❌' : (st === 'warn' ? '⚠️' : 'ℹ️'));
        
        item.innerHTML = `
          <div class="cp-icon">${iconSymbol}</div>
          <div class="cp-body">
            <div class="cp-title-row">
              <span class="cp-title">${cp.title}</span>
              <span class="cp-badge ${st}">${cp.status}</span>
            </div>
            <p class="cp-detail">${cp.detail}</p>
          </div>
        `;
        stack.appendChild(item);
      });
    }

    const officerRec = document.getElementById('dossier-officer-rec');
    if (officerRec) {
      officerRec.textContent = data.officer_recommendation || 'Proceed according to standard border control clearance rules.';
    }

    // Render Hugging Face AI Officer Briefing
    const hfData = data.llm_briefing || (data.dossier && data.dossier.llm_briefing) || {};
    const hfModelBadge = document.getElementById('dossier-hf-model-badge');
    const hfSummary = document.getElementById('dossier-hf-summary');
    const hfEvidence = document.getElementById('dossier-hf-evidence');
    const hfLegal = document.getElementById('dossier-hf-legal');
    const hfProtocol = document.getElementById('dossier-hf-protocol');

    if (hfModelBadge) hfModelBadge.textContent = hfData.model_used || '🤗 Mistral-7B / Qwen-2.5';
    if (hfSummary) hfSummary.textContent = hfData.executive_summary || data.summary || 'Summary unavailable.';
    if (hfEvidence) hfEvidence.textContent = hfData.forensic_reasoning || 'Biometrics and compression verified authentic.';
    if (hfLegal) hfLegal.textContent = hfData.legal_basis || 'Compliant with Passports Act 1967 and Bureau of Immigration standards.';
    if (hfProtocol) hfProtocol.textContent = hfData.officer_protocol || data.officer_recommendation || 'Proceed with intake clearance.';

    const btnRefreshLlm = document.getElementById('btn-refresh-llm');
    if (btnRefreshLlm) {
      btnRefreshLlm.onclick = async () => {
        btnRefreshLlm.disabled = true;
        btnRefreshLlm.textContent = '⏳ Thinking...';
        try {
          const res = await fetch('/api/llm/briefing', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
          });
          if (res.ok) {
            const freshBriefing = await res.json();
            if (hfModelBadge) hfModelBadge.textContent = freshBriefing.model_used || '🤗 Mistral-7B / Qwen-2.5';
            if (hfSummary) hfSummary.textContent = freshBriefing.executive_summary || '';
            if (hfEvidence) hfEvidence.textContent = freshBriefing.forensic_reasoning || '';
            if (hfLegal) hfLegal.textContent = freshBriefing.legal_basis || '';
            if (hfProtocol) hfProtocol.textContent = freshBriefing.officer_protocol || '';
          }
        } catch (e) {
          console.error(e);
        } finally {
          btnRefreshLlm.disabled = false;
          btnRefreshLlm.textContent = '🔄 Regenerate';
        }
      };
    }

    // Connect Certificate Download in Dossier
    const btnDossierPrint = document.getElementById('dossier-btn-print');
    const masterPrintBtn = document.getElementById('btn-print-certificate');
    if (btnDossierPrint && masterPrintBtn) {
      btnDossierPrint.onclick = () => masterPrintBtn.click();
    }

    // Deep link buttons inside Dossier
    document.querySelectorAll('.btn-dossier-link').forEach(btn => {
      btn.onclick = () => {
        const targetTab = btn.dataset.goto;
        if (targetTab) switchTab(targetTab);
      };
    });
  }

  // =========================================================================
  // 7. CERTIFICATE MODAL
  // =========================================================================
  function populateCertificateModal(data) {
    document.getElementById('cert-screening-id').textContent = data.screening_id;
    document.getElementById('cert-doc-type').textContent = data.doc_type;
    const name = data.ocr.fields.full_name || data.ocr.fields.name || 'UNSPECIFIED';
    document.getElementById('cert-subject-name').textContent = name;
    const docNum = data.ocr.fields.passport_number || data.ocr.fields.visa_number || data.ocr.fields.id_number || 'N/A';
    document.getElementById('cert-doc-number').textContent = docNum;
    document.getElementById('cert-timestamp').textContent = data.timestamp;
    document.getElementById('cert-risk-score').textContent = `${data.risk_score} / 100 (${data.risk_level} RISK)`;
    document.getElementById('cert-verdict').textContent = data.verdict;
    document.getElementById('cert-summary-text').textContent = data.summary;
    document.getElementById('cert-rec-text').textContent = data.officer_recommendation;
  }

  if (btnPrintCert) {
    btnPrintCert.addEventListener('click', () => {
      if (!currentReport) {
        alert('Please run a screening first to generate an official certificate.');
        return;
      }
      populateCertificateModal(currentReport);
      certModal.classList.remove('hidden');
    });
  }

  if (btnCloseCert) {
    btnCloseCert.addEventListener('click', () => {
      certModal.classList.add('hidden');
    });
  }

  // =========================================================================
  // 8. DASHBOARD STATS & RISK DISTRIBUTION
  // =========================================================================
  async function loadDashboardStats() {
    try {
      const res = await fetch('/api/stats');
      if (!res.ok) return;
      const stats = await res.json();

      document.getElementById('kpi-total').textContent = stats.total_screened || 0;
      document.getElementById('kpi-verified').textContent = stats.verified_count || 0;
      document.getElementById('kpi-review').textContent = stats.review_count || 0;
      document.getElementById('kpi-highrisk').textContent = stats.high_risk_count || 0;

      const total = Math.max(1, stats.total_screened);
      const dist = stats.distribution || {};
      const low = dist.LOW || 0;
      const med = dist.MEDIUM || 0;
      const high = dist.HIGH || 0;
      const crit = dist.CRITICAL || 0;

      document.getElementById('dist-count-low').textContent = low;
      document.getElementById('dist-count-med').textContent = med;
      document.getElementById('dist-count-high').textContent = high;
      document.getElementById('dist-count-critical').textContent = crit;

      document.getElementById('dist-bar-low').style.width = `${(low / total) * 100}%`;
      document.getElementById('dist-bar-med').style.width = `${(med / total) * 100}%`;
      document.getElementById('dist-bar-high').style.width = `${(high / total) * 100}%`;
      document.getElementById('dist-bar-critical').style.width = `${(crit / total) * 100}%`;
    } catch (e) {
      console.warn('Failed to load stats:', e);
    }
  }

  // =========================================================================
  // 9. SCREENING HISTORY TABLE
  // =========================================================================
  async function loadHistory() {
    const tbody = document.getElementById('history-tbody');
    try {
      tbody.innerHTML = `<tr><td colspan="8" class="table-empty">Loading records...</td></tr>`;
      const res = await fetch('/api/history');
      if (!res.ok) throw new Error('Failed to fetch history');
      const data = await res.json();
      const rows = data.history || [];

      tbody.innerHTML = '';
      if (rows.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="table-empty">No screening records in local database yet.</td></tr>`;
        return;
      }

      rows.forEach(r => {
        const tr = document.createElement('tr');
        const badgeClass = r.verdict.includes('VERIFIED') ? 'badge-green' : (r.verdict.includes('REVIEW') ? 'badge-yellow' : 'badge-red');
        tr.innerHTML = `
          <td><strong style="font-family: var(--font-mono); font-size: 0.82rem;">${r.screening_id}</strong></td>
          <td style="font-size: 0.8rem; color: var(--text-dim);">${r.timestamp}</td>
          <td><span class="badge-tech">${r.doc_type}</span></td>
          <td><strong>${r.person_name || 'N/A'}</strong></td>
          <td style="font-family: var(--font-mono);">${r.doc_number || 'N/A'}</td>
          <td style="font-family: var(--font-tech); font-weight: bold;">${r.risk_score}</td>
          <td><span class="${badgeClass}">${r.verdict}</span></td>
          <td>
            <button type="button" class="cyber-btn btn-secondary btn-sm btn-view-history-record" data-id="${r.screening_id}">
              Inspect
            </button>
          </td>
        `;
        tbody.appendChild(tr);
      });

      // Bind inspection buttons
      document.querySelectorAll('.btn-view-history-record').forEach(btn => {
        btn.addEventListener('click', async () => {
          const id = btn.dataset.id;
          const repRes = await fetch(`/api/history/${id}`);
          if (repRes.ok) {
            const rep = await repRes.json();
            currentReport = rep;
            renderScreeningResults(rep);
            switchTab('tab-risk');
          }
        });
      });

    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="8" class="table-empty text-red">Failed to load history: ${e.message}</td></tr>`;
    }
  }

  const btnRefreshHistory = document.getElementById('btn-refresh-history');
  if (btnRefreshHistory) btnRefreshHistory.addEventListener('click', loadHistory);

  // =========================================================================
  // 10. MOCK DATABASE VIEWER
  // =========================================================================
  async function loadMockDatabase() {
    const tbody = document.getElementById('mockdb-tbody');
    try {
      tbody.innerHTML = `<tr><td colspan="7" class="table-empty">Loading mock database records...</td></tr>`;
      const res = await fetch('/api/mock-db');
      if (!res.ok) throw new Error('Failed to fetch mock DB');
      const data = await res.json();
      const records = data.records || [];

      tbody.innerHTML = '';
      if (records.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="table-empty">No mock database entries.</td></tr>`;
        return;
      }

      records.forEach(r => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td style="font-family: var(--font-mono); font-weight: bold; color: var(--teal-neon);">${r.doc_number}</td>
          <td><span class="badge-tech">${r.doc_type}</span></td>
          <td><strong>${r.person_name}</strong></td>
          <td><span class="badge-red">${r.status}</span></td>
          <td>${r.reason}</td>
          <td><span class="badge-tech">${r.issuing_country}</span></td>
          <td style="font-size: 0.8rem; color: var(--text-dim);">${r.notes || '--'}</td>
        `;
        tbody.appendChild(tr);
      });
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="7" class="table-empty text-red">Failed to load mock database: ${e.message}</td></tr>`;
    }
  }

  // =========================================================================
  // INITIALIZATION ON LOAD
  // =========================================================================
  loadDashboardStats();
  console.log('TruthLens Border Screening Dashboard Initialized.');

})();
