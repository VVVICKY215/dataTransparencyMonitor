/**
 * Data Transparency Monitor - Popup Script
 * Design: Integrated Expandable Items
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements
  const elements = {
    // Header
    currentDomain: document.getElementById('current-domain'),
    siteType: document.getElementById('site-type'),
    
    // Risk Card
    riskCircle: document.getElementById('risk-circle'),
    riskScore: document.getElementById('risk-score'),
    riskLabel: document.getElementById('risk-label'),
    riskSummary: document.getElementById('risk-summary'),
    
    // Findings - Values
    valueIdentity: document.getElementById('value-identity'),
    valueSharing: document.getElementById('value-sharing'),
    valueTrackers: document.getElementById('value-trackers'),
    valueHidden: document.getElementById('value-hidden'),
    
    // Findings - Details
    fpCanvas: document.getElementById('fp-canvas'),
    fpWebgl: document.getElementById('fp-webgl'),
    fpAudio: document.getElementById('fp-audio'),
    fpFont: document.getElementById('fp-font'),
    detailCookieSync: document.getElementById('detail-cookie-sync'),
    syncDomains: document.getElementById('sync-domains'),
    trackerList: document.getElementById('tracker-list'),
    detailCname: document.getElementById('detail-cname'),
    cnameDomains: document.getElementById('cname-domains'),
    
    // Score Breakdown
    toggleScore: document.getElementById('toggle-score'),
    contentScore: document.getElementById('content-score'),
    barCapability: document.getElementById('bar-capability'),
    barSensitivity: document.getElementById('bar-sensitivity'),
    barFrequency: document.getElementById('bar-frequency'),
    barContext: document.getElementById('bar-context'),
    valCapability: document.getElementById('val-capability'),
    valSensitivity: document.getElementById('val-sensitivity'),
    valFrequency: document.getElementById('val-frequency'),
    valContext: document.getElementById('val-context')
  };
  
  // Config
  const riskConfig = {
    low: { label: 'Low Risk', summary: 'Light tracking. Basic analytics only.', className: 'low' },
    medium: { label: 'Medium Risk', summary: 'Moderate tracking detected.', className: 'medium' },
    high: { label: 'High Risk', summary: 'Heavy tracking detected.', className: 'high' }
  };
  
  const siteTypeLabels = {
    CRITICAL: { label: 'Health', className: 'critical' },
    HIGH: { label: 'Finance', className: 'high' },
    MEDIUM: { label: 'Shopping', className: 'medium' },
    LOW: { label: 'News', className: 'low' },
    MINIMAL: { label: 'Tools', className: 'minimal' },
    DEFAULT: { label: '', className: '' }
  };
  
  // Initialize
  init();
  
  function init() {
    setupFindingToggles();
    setupScoreToggle();
    loadTabData();
  }
  
  // ============================================
  // Toggle Handlers
  // ============================================
  
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
  
  // ============================================
  // Data Loading
  // ============================================
  
  function loadTabData() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs || !tabs[0]) {
        showError('Cannot access this page');
        return;
      }
      
      const tab = tabs[0];
      const url = tab.url || '';
      
      if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || 
          url.startsWith('about:') || url.startsWith('edge://')) {
        showError('Cannot analyze browser pages');
        return;
      }
      
      try {
        elements.currentDomain.textContent = new URL(url).hostname;
      } catch (e) {
        elements.currentDomain.textContent = 'Unknown';
      }
      
      chrome.runtime.sendMessage(
        { type: 'GET_TAB_DATA', tabId: tab.id },
        (response) => {
          if (chrome.runtime.lastError) {
            showError('Connection error');
            return;
          }
          
          if (response && response.success && response.data) {
            updateUI(response.data);
          } else {
            showNoData();
          }
        }
      );
    });
  }
  
  // ============================================
  // UI Updates
  // ============================================
  
  function updateUI(data) {
    updateRiskDisplay(data);
    updateSiteType(data.sensitivity);
    updateFindings(data);
    updateScoreBreakdown(data);
  }
  
  function updateRiskDisplay(data) {
    const level = data.riskLevel || 'low';
    const score = data.riskScore || 0;
    const config = riskConfig[level];
    
    elements.riskCircle.className = 'risk-circle ' + config.className;
    elements.riskScore.textContent = score;
    elements.riskLabel.textContent = config.label;
    elements.riskLabel.className = 'risk-label ' + config.className;
    elements.riskSummary.textContent = generateSummary(data);
  }
  
  function generateSummary(data) {
    const level = data.riskLevel || 'low';
    const trackerCount = data.thirdPartyRequests?.length || 0;
    const hasFingerprinting = data.fingerprinting && 
      (data.fingerprinting.canvas || data.fingerprinting.webgl || 
       data.fingerprinting.audio || data.fingerprinting.font);
    const hasCookieSync = data.cookieSync?.detected;
    
    if (trackerCount === 0 && !hasFingerprinting) {
      return 'This site respects your privacy.';
    }
    
    if (level === 'high') {
      if (hasFingerprinting && hasCookieSync) {
        return 'Your device is identified and data is shared across companies.';
      }
      if (hasFingerprinting) {
        return 'Your device can be uniquely identified.';
      }
      return 'Heavy tracking. Multiple trackers watching.';
    }
    
    if (level === 'medium') {
      return 'Moderate tracking detected on this site.';
    }
    
    return 'Light tracking. Basic analytics only.';
  }
  
  function updateSiteType(sensitivity) {
    if (!sensitivity || sensitivity.level === 'DEFAULT') {
      elements.siteType.textContent = '';
      elements.siteType.className = 'site-type';
      return;
    }
    
    const config = siteTypeLabels[sensitivity.level] || siteTypeLabels.DEFAULT;
    elements.siteType.textContent = config.label;
    elements.siteType.className = 'site-type ' + config.className;
  }
  
  function updateFindings(data) {
    // === Device Identification ===
    const fp = data.fingerprinting || {};
    const hasFingerprinting = fp.canvas || fp.webgl || fp.audio || fp.font;
    
    if (hasFingerprinting) {
      elements.valueIdentity.textContent = 'Yes';
      elements.valueIdentity.className = 'finding-value positive';
    } else {
      elements.valueIdentity.textContent = 'No';
      elements.valueIdentity.className = 'finding-value negative';
    }
    
    // Fingerprinting details
    updateFpItem('fp-canvas', 'Canvas', fp.canvas);
    updateFpItem('fp-webgl', 'WebGL', fp.webgl);
    updateFpItem('fp-audio', 'Audio', fp.audio);
    updateFpItem('fp-font', 'Font', fp.font);
    
    // === Data Sharing ===
    if (data.cookieSync?.detected) {
      const domains = data.cookieSync.involvedDomains?.length || 0;
      elements.valueSharing.textContent = domains > 0 ? `${domains} companies` : 'Yes';
      elements.valueSharing.className = 'finding-value positive';
      
      elements.detailCookieSync.textContent = `Detected (${domains} domains)`;
      elements.detailCookieSync.className = 'detail-value detected';
      
      if (data.cookieSync.involvedDomains && data.cookieSync.involvedDomains.length > 0) {
        elements.syncDomains.textContent = data.cookieSync.involvedDomains.slice(0, 3).join(', ');
      }
    } else {
      elements.valueSharing.textContent = 'No';
      elements.valueSharing.className = 'finding-value negative';
      elements.detailCookieSync.textContent = 'Not detected';
      elements.detailCookieSync.className = 'detail-value';
      elements.syncDomains.textContent = '';
    }
    
    // === Trackers ===
    const trackers = data.thirdPartyRequests || [];
    const knownTrackers = trackers.filter(r => r.isKnownTracker);
    
    if (trackers.length === 0) {
      elements.valueTrackers.textContent = 'None';
      elements.valueTrackers.className = 'finding-value negative';
    } else if (knownTrackers.length > 0) {
      elements.valueTrackers.textContent = `${knownTrackers.length} found`;
      elements.valueTrackers.className = 'finding-value positive';
    } else {
      elements.valueTrackers.textContent = `${trackers.length} found`;
      elements.valueTrackers.className = 'finding-value neutral';
    }
    
    updateTrackerList(trackers);
    
    // === Hidden Tracking ===
    if (data.cnameCloaking?.detected) {
      const domains = data.cnameCloaking.domains?.length || 0;
      elements.valueHidden.textContent = 'Yes';
      elements.valueHidden.className = 'finding-value positive';
      
      elements.detailCname.textContent = `Detected (${domains} domain${domains > 1 ? 's' : ''})`;
      elements.detailCname.className = 'detail-value detected';
      
      if (data.cnameCloaking.domains && data.cnameCloaking.domains.length > 0) {
        elements.cnameDomains.textContent = data.cnameCloaking.domains.slice(0, 3).join(', ');
      }
    } else {
      elements.valueHidden.textContent = 'No';
      elements.valueHidden.className = 'finding-value negative';
      elements.detailCname.textContent = 'Not detected';
      elements.detailCname.className = 'detail-value';
      elements.cnameDomains.textContent = '';
    }
  }
  
  function updateFpItem(id, label, detected) {
    const element = document.getElementById(id);
    if (detected) {
      element.textContent = `● ${label}`;
      element.className = 'fp-item detected';
    } else {
      element.textContent = `○ ${label}`;
      element.className = 'fp-item';
    }
  }
  
  function updateTrackerList(trackers) {
    const sorted = [...trackers]
      .filter(t => t.isKnownTracker)
      .sort((a, b) => (b.count || 1) - (a.count || 1))
      .slice(0, 6);
    
    if (sorted.length === 0) {
      if (trackers.length === 0) {
        elements.trackerList.innerHTML = '<li class="tracker-item">No trackers detected</li>';
      } else {
        elements.trackerList.innerHTML = '<li class="tracker-item">No known trackers (unknown third-parties present)</li>';
      }
      return;
    }
    
    const categoryLabels = {
      'advertising': { label: 'Ads', className: 'ads' },
      'analytics': { label: 'Analytics', className: 'analytics' },
      'social': { label: 'Social', className: 'social' },
      'fingerprinting': { label: 'FP', className: 'fp' },
      'cnameCloaking': { label: 'CNAME', className: 'cname' }
    };
    
    elements.trackerList.innerHTML = sorted.map(tracker => {
      const category = categoryLabels[tracker.trackerCategory] || null;
      const badge = category 
        ? `<span class="tracker-badge ${category.className}">${category.label}</span>` 
        : '';
      return `<li class="tracker-item"><span class="tracker-domain">${tracker.domain}</span>${badge}</li>`;
    }).join('');
  }
  
  function updateScoreBreakdown(data) {
    const fp = data.fingerprinting || {};
    const trackers = data.thirdPartyRequests || [];
    const sensitivity = data.sensitivity?.score || 30;
    
    // Capability
    let capabilityRaw = 0;
    if (fp.canvas) capabilityRaw += 25;
    if (fp.webgl) capabilityRaw += 25;
    if (fp.audio) capabilityRaw += 20;
    if (fp.font) capabilityRaw += 15;
    if (data.cookieSync?.detected) capabilityRaw += 20;
    if (data.cnameCloaking?.detected) capabilityRaw += 25;
    const knownTrackers = trackers.filter(r => r.isKnownTracker).length;
    const highRiskTrackers = trackers.filter(r => r.isHighRisk).length;
    capabilityRaw += Math.min(knownTrackers * 5, 30);
    capabilityRaw += Math.min(highRiskTrackers * 10, 20);
    capabilityRaw = Math.min(capabilityRaw, 100);
    const capabilityWeighted = Math.round(capabilityRaw * 0.35);
    
    // Sensitivity
    const sensitivityWeighted = Math.round(sensitivity * 0.25);
    
    // Frequency
    const frequencyRaw = Math.min(trackers.length * 5, 100);
    const frequencyWeighted = Math.round(frequencyRaw * 0.15);
    
    // Context
    let contextRaw = Math.min(trackers.length * 3, 50);
    const categories = new Set(trackers.filter(r => r.trackerCategory).map(r => r.trackerCategory));
    if (categories.has('advertising')) contextRaw += 15;
    if (categories.has('analytics')) contextRaw += 10;
    if (categories.has('social')) contextRaw += 10;
    if (categories.has('fingerprinting')) contextRaw += 20;
    contextRaw = Math.min(contextRaw, 100);
    const contextWeighted = Math.round(contextRaw * 0.25);
    
    // Update bars
    updateBar('capability', capabilityWeighted, 35);
    updateBar('sensitivity', sensitivityWeighted, 25);
    updateBar('frequency', frequencyWeighted, 15);
    updateBar('context', contextWeighted, 25);
  }
  
  function updateBar(name, value, max) {
    const bar = elements[`bar${capitalize(name)}`];
    const val = elements[`val${capitalize(name)}`];
    
    const percentage = (value / max) * 100;
    bar.style.width = percentage + '%';
    
    if (percentage >= 70) {
      bar.className = 'breakdown-fill high';
    } else if (percentage >= 40) {
      bar.className = 'breakdown-fill medium';
    } else {
      bar.className = 'breakdown-fill low';
    }
    
    val.textContent = `${value}/${max}`;
  }
  
  function capitalize(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
  }
  
  // ============================================
  // Error States
  // ============================================
  
  function showError(message) {
    elements.currentDomain.textContent = 'Error';
    elements.riskScore.textContent = '--';
    elements.riskLabel.textContent = 'Unavailable';
    elements.riskSummary.textContent = message;
    elements.riskCircle.className = 'risk-circle';
  }
  
  function showNoData() {
    elements.riskScore.textContent = '--';
    elements.riskLabel.textContent = 'Analyzing...';
    elements.riskSummary.textContent = 'Refresh the page to analyze.';
  }
});
