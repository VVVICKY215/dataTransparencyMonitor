document.addEventListener('DOMContentLoaded', () => {
  const elements = {
    currentDomain: document.getElementById('current-domain'),
    siteType: document.getElementById('site-type'),
    riskCircle: document.getElementById('risk-circle'),
    riskScore: document.getElementById('risk-score'),
    riskLabel: document.getElementById('risk-label'),
    riskSummary: document.getElementById('risk-summary'),
    riskNote: document.getElementById('risk-note'),
    evidenceBadge: document.getElementById('evidence-badge'),
    valueIdentity: document.getElementById('value-identity'),
    valueSharing: document.getElementById('value-sharing'),
    valueTrackers: document.getElementById('value-trackers'),
    valueHidden: document.getElementById('value-hidden'),
    detailIdentityStatus: document.getElementById('detail-identity-status'),
    detailCookieSync: document.getElementById('detail-cookie-sync'),
    detailCookieConfidence: document.getElementById('detail-cookie-confidence'),
    syncDomains: document.getElementById('sync-domains'),
    trackerList: document.getElementById('tracker-list'),
    detailCname: document.getElementById('detail-cname'),
    cnameDomains: document.getElementById('cname-domains'),
    toggleScore: document.getElementById('toggle-score'),
    barCapability: document.getElementById('bar-capability'),
    barSensitivity: document.getElementById('bar-sensitivity'),
    barFrequency: document.getElementById('bar-frequency'),
    barContext: document.getElementById('bar-context'),
    valCapability: document.getElementById('val-capability'),
    valSensitivity: document.getElementById('val-sensitivity'),
    valFrequency: document.getElementById('val-frequency'),
    valContext: document.getElementById('val-context')
  };

  const riskConfig = {
    low: { label: 'Estimated Low Risk', className: 'low' },
    medium: { label: 'Estimated Medium Risk', className: 'medium' },
    high: { label: 'Estimated High Risk', className: 'high' }
  };

  const siteTypeLabels = {
    CRITICAL: { label: 'Health', className: 'critical' },
    HIGH: { label: 'Finance', className: 'high' },
    MEDIUM: { label: 'Shopping', className: 'medium' },
    LOW: { label: 'News', className: 'low' },
    MINIMAL: { label: 'Tools', className: 'minimal' },
    DEFAULT: { label: '', className: '' }
  };

  init();

  function init() {
    setupFindingToggles();
    setupScoreToggle();
    loadTabData();
  }

  function setupFindingToggles() {
    document.querySelectorAll('.finding-header').forEach(header => {
      header.addEventListener('click', () => {
        const item = header.closest('.finding-item');
        item.classList.toggle('open');
      });
    });
  }

  function setupScoreToggle() {
    elements.toggleScore.addEventListener('click', () => {
      const section = elements.toggleScore.closest('.collapsible');
      section.classList.toggle('open');
    });
  }

  function loadTabData() {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      if (!tabs || !tabs[0]) {
        showError('Cannot access this page.');
        return;
      }

      const tab = tabs[0];
      const url = tab.url || '';

      if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('about:') || url.startsWith('edge://')) {
        showError('Browser pages cannot be analyzed.');
        return;
      }

      try {
        elements.currentDomain.textContent = new URL(url).hostname;
      } catch (error) {
        elements.currentDomain.textContent = 'Unknown';
      }

      chrome.runtime.sendMessage({ type: 'GET_TAB_DATA', tabId: tab.id }, response => {
        if (chrome.runtime.lastError) {
          showError('Connection error.');
          return;
        }

        if (response && response.success && response.data) {
          updateUI(response.data);
        } else {
          showNoData();
        }
      });
    });
  }

  function updateUI(data) {
    const evidence = getEvidenceSummary(data);
    updateRiskDisplay(data, evidence);
    updateSiteType(data.sensitivity);
    updateFindings(data, evidence);
    updateScoreBreakdown(data);
  }

  function getEvidenceSummary(data) {
    const trackers = data.thirdPartyRequests || [];
    const knownTrackers = trackers.filter(tracker => tracker.isKnownTracker).length;
    const fingerprintSignals = countFingerprintSignals(data.fingerprinting);
    const cookieSignal = getCookieStatus(data.cookieSync);
    const cnameDetected = Boolean(data.cnameCloaking?.detected);

    let score = 0;
    if (knownTrackers > 0) score += Math.min(knownTrackers * 6, 24);
    if (fingerprintSignals > 0) score += Math.min(fingerprintSignals * 12, 36);
    if (cookieSignal === 'suspected') score += 20;
    if (cookieSignal === 'confirmed') score += 35;
    if (cnameDetected) score += 25;

    if (score >= 60) {
      return {
        level: 'high',
        label: 'Strong evidence',
        note: 'Multiple independent signals support this estimate.'
      };
    }

    if (score >= 30) {
      return {
        level: 'medium',
        label: 'Moderate evidence',
        note: 'Several signals suggest tracking activity on this page.'
      };
    }

    return {
      level: 'low',
      label: 'Limited evidence',
      note: 'The estimate is based on limited observable signals so far.'
    };
  }

  function updateRiskDisplay(data, evidence) {
    const level = data.riskLevel || 'low';
    const score = data.riskScore || 0;
    const config = riskConfig[level] || riskConfig.low;

    elements.riskCircle.className = `risk-circle ${config.className}`;
    elements.riskScore.textContent = score;
    elements.riskLabel.textContent = config.label;
    elements.riskLabel.className = `risk-label ${config.className}`;
    elements.evidenceBadge.textContent = evidence.label;
    elements.evidenceBadge.className = `evidence-badge ${evidence.level}`;
    elements.riskSummary.textContent = generateSummary(data);
    elements.riskNote.textContent = evidence.note;
  }

  function generateSummary(data) {
    const level = data.riskLevel || 'low';
    const trackerCount = data.thirdPartyRequests?.length || 0;
    const fingerprintCount = countFingerprintSignals(data.fingerprinting);
    const cookieStatus = getCookieStatus(data.cookieSync);

    if (trackerCount === 0 && fingerprintCount === 0 && cookieStatus === 'none') {
      return 'We did not observe strong tracking signals on this page.';
    }

    if (level === 'high') {
      if (cookieStatus === 'confirmed' && fingerprintCount > 0) {
        return 'Observed signals suggest device identification and cross-company data sharing.';
      }

      if (fingerprintCount > 0) {
        return 'Observed signals suggest that this page may be identifying your device.';
      }

      return 'Observed signals suggest substantial tracking activity on this page.';
    }

    if (level === 'medium') {
      if (cookieStatus === 'suspected') {
        return 'Some redirect patterns suggest possible data sharing between tracking services.';
      }

      return 'Observed signals suggest moderate tracking activity on this page.';
    }

    return 'Only limited tracking signals were observed on this page.';
  }

  function updateSiteType(sensitivity) {
    if (!sensitivity || sensitivity.level === 'DEFAULT') {
      elements.siteType.textContent = '';
      elements.siteType.className = 'site-type';
      return;
    }

    const config = siteTypeLabels[sensitivity.level] || siteTypeLabels.DEFAULT;
    elements.siteType.textContent = config.label;
    elements.siteType.className = `site-type ${config.className}`;
  }

  function updateFindings(data, evidence) {
    const fp = data.fingerprinting || {};
    const fingerprintCount = countFingerprintSignals(fp);
    const cookieStatus = getCookieStatus(data.cookieSync);
    const cookieConfidence = getCookieConfidence(data.cookieSync);
    const trackers = data.thirdPartyRequests || [];
    const knownTrackers = trackers.filter(tracker => tracker.isKnownTracker);

    if (fingerprintCount >= 2) {
      setFindingState(elements.valueIdentity, 'Detected', 'positive');
      elements.detailIdentityStatus.textContent = 'Strong';
      elements.detailIdentityStatus.className = 'detail-value detected';
    } else if (fingerprintCount === 1) {
      setFindingState(elements.valueIdentity, 'Suspected', 'warning');
      elements.detailIdentityStatus.textContent = 'Moderate';
      elements.detailIdentityStatus.className = 'detail-value warning';
    } else {
      setFindingState(elements.valueIdentity, 'Not detected', 'negative');
      elements.detailIdentityStatus.textContent = 'Limited';
      elements.detailIdentityStatus.className = 'detail-value';
    }

    updateFpItem(elements.fpCanvas || document.getElementById('fp-canvas'), fp.canvas);
    updateFpItem(elements.fpWebgl || document.getElementById('fp-webgl'), fp.webgl);
    updateFpItem(elements.fpAudio || document.getElementById('fp-audio'), fp.audio);
    updateFpItem(elements.fpFont || document.getElementById('fp-font'), fp.font);

    if (cookieStatus === 'confirmed') {
      setFindingState(elements.valueSharing, 'Confirmed', 'positive');
      elements.detailCookieSync.textContent = 'Confirmed';
      elements.detailCookieSync.className = 'detail-value detected';
    } else if (cookieStatus === 'suspected') {
      setFindingState(elements.valueSharing, 'Suspected', 'warning');
      elements.detailCookieSync.textContent = 'Suspected';
      elements.detailCookieSync.className = 'detail-value warning';
    } else {
      setFindingState(elements.valueSharing, 'Not detected', 'negative');
      elements.detailCookieSync.textContent = 'Not detected';
      elements.detailCookieSync.className = 'detail-value';
    }

    elements.detailCookieConfidence.textContent = cookieConfidence;
    elements.detailCookieConfidence.className = cookieStatus === 'confirmed' ? 'detail-value detected' : cookieStatus === 'suspected' ? 'detail-value warning' : 'detail-value';
    elements.syncDomains.textContent = formatDomainList(data.cookieSync?.involvedDomains || []);

    if (trackers.length === 0) {
      setFindingState(elements.valueTrackers, 'None', 'negative');
    } else if (knownTrackers.length > 0) {
      setFindingState(elements.valueTrackers, `${knownTrackers.length} known`, 'positive');
    } else {
      setFindingState(elements.valueTrackers, `${trackers.length} third-party`, 'neutral');
    }

    updateTrackerList(trackers);

    if (data.cnameCloaking?.detected) {
      setFindingState(elements.valueHidden, 'Detected', 'positive');
      elements.detailCname.textContent = `Detected (${data.cnameCloaking.domains.length} domain${data.cnameCloaking.domains.length > 1 ? 's' : ''})`;
      elements.detailCname.className = 'detail-value detected';
      elements.cnameDomains.textContent = formatDomainList(data.cnameCloaking.domains);
    } else {
      setFindingState(elements.valueHidden, 'Not detected', 'negative');
      elements.detailCname.textContent = 'Not detected';
      elements.detailCname.className = 'detail-value';
      elements.cnameDomains.textContent = '';
    }
  }

  function setFindingState(element, text, className) {
    element.textContent = text;
    element.className = `finding-value ${className}`;
  }

  function updateFpItem(element, detected) {
    element.className = detected ? 'fp-item detected' : 'fp-item';
  }

  function updateTrackerList(trackers) {
    const sorted = [...trackers]
      .filter(tracker => tracker.isKnownTracker)
      .sort((a, b) => (b.count || 1) - (a.count || 1))
      .slice(0, 6);

    if (sorted.length === 0) {
      if (trackers.length === 0) {
        elements.trackerList.innerHTML = '<li class="tracker-item">No trackers detected</li>';
      } else {
        elements.trackerList.innerHTML = '<li class="tracker-item">No known trackers, but third-party requests were observed.</li>';
      }
      return;
    }

    const categoryLabels = {
      advertising: { label: 'Ads', className: 'ads' },
      analytics: { label: 'Analytics', className: 'analytics' },
      social: { label: 'Social', className: 'social' },
      fingerprinting: { label: 'FP', className: 'fp' },
      cnameCloaking: { label: 'CNAME', className: 'cname' }
    };

    elements.trackerList.innerHTML = sorted.map(tracker => {
      const category = categoryLabels[tracker.trackerCategory] || null;
      const badge = category ? `<span class="tracker-badge ${category.className}">${category.label}</span>` : '';
      return `<li class="tracker-item"><span class="tracker-domain">${tracker.domain}</span>${badge}</li>`;
    }).join('');
  }

  function updateScoreBreakdown(data) {
    const fp = data.fingerprinting || {};
    const trackers = data.thirdPartyRequests || [];
    const sensitivity = data.sensitivity?.score || 30;

    let capabilityRaw = 0;
    if (fp.canvas) capabilityRaw += 25;
    if (fp.webgl) capabilityRaw += 25;
    if (fp.audio) capabilityRaw += 20;
    if (fp.font) capabilityRaw += 15;
    if (data.cookieSync?.detected) capabilityRaw += 20;
    if (data.cnameCloaking?.detected) capabilityRaw += 25;
    capabilityRaw += Math.min(trackers.filter(tracker => tracker.isKnownTracker).length * 5, 30);
    capabilityRaw += Math.min(trackers.filter(tracker => tracker.isHighRisk).length * 10, 20);
    capabilityRaw = Math.min(capabilityRaw, 100);

    const sensitivityWeighted = Math.round(sensitivity * 0.25);
    const frequencyWeighted = Math.round(Math.min(trackers.length * 5, 100) * 0.15);

    let contextRaw = Math.min(trackers.length * 3, 50);
    const categories = new Set(trackers.filter(tracker => tracker.trackerCategory).map(tracker => tracker.trackerCategory));
    if (categories.has('advertising')) contextRaw += 15;
    if (categories.has('analytics')) contextRaw += 10;
    if (categories.has('social')) contextRaw += 10;
    if (categories.has('fingerprinting')) contextRaw += 20;
    contextRaw = Math.min(contextRaw, 100);

    updateBar('capability', Math.round(capabilityRaw * 0.35), 35);
    updateBar('sensitivity', sensitivityWeighted, 25);
    updateBar('frequency', frequencyWeighted, 15);
    updateBar('context', Math.round(contextRaw * 0.25), 25);
  }

  function updateBar(name, value, max) {
    const bar = elements[`bar${capitalize(name)}`];
    const valueElement = elements[`val${capitalize(name)}`];
    const percentage = (value / max) * 100;

    bar.style.width = `${percentage}%`;
    if (percentage >= 70) {
      bar.className = 'breakdown-fill high';
    } else if (percentage >= 40) {
      bar.className = 'breakdown-fill medium';
    } else {
      bar.className = 'breakdown-fill low';
    }

    valueElement.textContent = `${value}/${max}`;
  }

  function getCookieStatus(cookieSync) {
    if (!cookieSync) return 'none';
    if (cookieSync.detected) return 'confirmed';

    const maxConfidence = Math.max(cookieSync.confidence || 0, ...((cookieSync.chains || []).map(chain => chain.confidence || 0)));
    return maxConfidence >= 25 ? 'suspected' : 'none';
  }

  function getCookieConfidence(cookieSync) {
    const maxConfidence = Math.max(cookieSync?.confidence || 0, ...((cookieSync?.chains || []).map(chain => chain.confidence || 0)));
    if (maxConfidence >= 60) return 'High';
    if (maxConfidence >= 25) return 'Medium';
    return 'Low';
  }

  function countFingerprintSignals(fp = {}) {
    return ['canvas', 'webgl', 'audio', 'font'].filter(key => Boolean(fp[key])).length;
  }

  function formatDomainList(domains) {
    if (!domains || domains.length === 0) return '';
    return domains.slice(0, 3).join(', ');
  }

  function capitalize(value) {
    return value.charAt(0).toUpperCase() + value.slice(1);
  }

  function showError(message) {
    elements.currentDomain.textContent = 'Error';
    elements.riskScore.textContent = '--';
    elements.riskLabel.textContent = 'Unavailable';
    elements.riskLabel.className = 'risk-label';
    elements.riskSummary.textContent = message;
    elements.riskNote.textContent = 'The page could not be analyzed.';
    elements.evidenceBadge.textContent = 'No data';
    elements.evidenceBadge.className = 'evidence-badge low';
    elements.riskCircle.className = 'risk-circle';
  }

  function showNoData() {
    elements.riskScore.textContent = '--';
    elements.riskLabel.textContent = 'Analyzing...';
    elements.riskLabel.className = 'risk-label';
    elements.riskSummary.textContent = 'Refresh the page to collect signals.';
    elements.riskNote.textContent = 'The extension needs observable page activity before it can estimate risk.';
    elements.evidenceBadge.textContent = 'Collecting evidence';
    elements.evidenceBadge.className = 'evidence-badge low';
  }
});
