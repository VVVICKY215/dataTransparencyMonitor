document.addEventListener('DOMContentLoaded', () => {
  const elements = {
    currentDomain: document.getElementById('current-domain'),
    siteType: document.getElementById('site-type'),
    riskCircle: document.getElementById('risk-circle'),
    riskScore: document.getElementById('risk-score'),
    riskLabel: document.getElementById('risk-label'),
    riskSummary: document.getElementById('risk-summary'),
    riskNote: document.getElementById('risk-note'),
    valueIdentity: document.getElementById('value-identity'),
    valueSharing: document.getElementById('value-sharing'),
    valueTrackers: document.getElementById('value-trackers'),
    valueHidden: document.getElementById('value-hidden'),
    syncDomains: document.getElementById('sync-domains'),
    trackerList: document.getElementById('tracker-list'),
    detailCookieSync: document.getElementById('detail-cookie-sync'),
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
    HIGH: { label: 'Sensitive', className: 'high' },
    MEDIUM: { label: 'Personal', className: 'medium' },
    LOW: { label: 'Media', className: 'low' },
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
    document.querySelectorAll('.finding-header').forEach((header) => {
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
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
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

      chrome.runtime.sendMessage({ type: 'GET_TAB_DATA', tabId: tab.id }, (response) => {
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
    updateRiskDisplay(data);
    updateSiteType(data.sensitivity);
    updateFindings(data);
    updateScoreBreakdown(data);
  }

  function updateRiskDisplay(data) {
    const level = data.riskLevel || 'low';
    const score = data.riskScore || 0;
    const config = riskConfig[level] || riskConfig.low;

    elements.riskCircle.className = `risk-circle ${config.className}`;
    elements.riskScore.textContent = score;
    elements.riskLabel.textContent = config.label;
    elements.riskLabel.className = `risk-label ${config.className}`;
    elements.riskSummary.textContent = data.summary || 'Checking this website...';
    elements.riskNote.textContent = data.note || 'This score is based on observed page activity.';
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

  function updateFindings(data) {
    const findings = data.findings || {};
    const fp = data.fingerprinting || {};
    const trackers = data.thirdPartyRequests || [];

    setFindingState(
      elements.valueIdentity,
      findings.deviceIdentification?.status === 'detected' ? 'Detected' : 'Not detected',
      findings.deviceIdentification?.status === 'detected' ? 'positive' : 'negative'
    );

    updateFpItem(document.getElementById('fp-canvas'), fp.canvas);
    updateFpItem(document.getElementById('fp-webgl'), fp.webgl);
    updateFpItem(document.getElementById('fp-audio'), fp.audio);
    updateFpItem(document.getElementById('fp-font'), fp.font);

    setFindingState(
      elements.valueSharing,
      findings.dataSharing?.status === 'detected' ? 'Detected' : 'Not detected',
      findings.dataSharing?.status === 'detected' ? 'positive' : 'negative'
    );
    elements.detailCookieSync.textContent = findings.dataSharing?.status === 'detected' ? 'Detected' : 'Not detected';
    elements.detailCookieSync.className = findings.dataSharing?.status === 'detected' ? 'detail-value detected' : 'detail-value';
    elements.syncDomains.textContent = formatDomainList(data.cookieSync?.involvedDomains || []);

    const trackerLabel = findings.trackers?.label || 'None';
    const trackerClass = findings.trackers?.status === 'found' ? 'positive' : 'negative';
    setFindingState(elements.valueTrackers, trackerLabel, trackerClass);
    updateTrackerList(trackers);

    setFindingState(
      elements.valueHidden,
      findings.hiddenTracking?.status === 'detected' ? 'Detected' : 'Not detected',
      findings.hiddenTracking?.status === 'detected' ? 'positive' : 'negative'
    );
    elements.detailCname.textContent = data.cnameCloaking?.detected
      ? `Detected (${data.cnameCloaking.domains.length} domain${data.cnameCloaking.domains.length > 1 ? 's' : ''})`
      : 'Not detected';
    elements.detailCname.className = data.cnameCloaking?.detected ? 'detail-value detected' : 'detail-value';
    elements.cnameDomains.textContent = formatDomainList(data.cnameCloaking?.domains || []);
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
      .filter((tracker) => tracker.isKnownTracker)
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

    elements.trackerList.innerHTML = sorted.map((tracker) => {
      const category = categoryLabels[tracker.trackerCategory] || null;
      const badge = category ? `<span class="tracker-badge ${category.className}">${category.label}</span>` : '';
      return `<li class="tracker-item"><span class="tracker-domain">${tracker.domain}</span>${badge}</li>`;
    }).join('');
  }

  function updateScoreBreakdown(data) {
    const c = data.scoreComponents || { capability: 0, sensitivity: 0, frequency: 0, context: 0 };
    updateBar('capability', c.capability, 35);
    updateBar('sensitivity', c.sensitivity, 25);
    updateBar('frequency', c.frequency, 15);
    updateBar('context', c.context, 25);
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
    elements.riskCircle.className = 'risk-circle';
  }

  function showNoData() {
    elements.riskScore.textContent = '--';
    elements.riskLabel.textContent = 'Analyzing...';
    elements.riskLabel.className = 'risk-label';
    elements.riskSummary.textContent = 'Refresh the page to collect signals.';
    elements.riskNote.textContent = 'The extension needs observable page activity before it can estimate risk.';
  }
});
