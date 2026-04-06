import { checkTracker, isCnameCloaking } from '../data/trackers.js';
import { calculateSensitivity } from '../data/sensitivity.js';
import {
  analyzeRedirect,
  analyzeCookieSyncChain,
  shouldRecordRedirect
} from '../data/cookie-sync.js';

const STORAGE_KEY = 'dtmTabData';
const tabData = {};

function extractDomain(url) {
  try {
    return new URL(url).hostname;
  } catch (error) {
    return null;
  }
}

function isThirdParty(requestDomain, pageDomain) {
  if (!requestDomain || !pageDomain) return false;

  const getBaseDomain = (domain) => {
    const parts = domain.toLowerCase().split('.');
    if (parts.length <= 2) return domain.toLowerCase();
    return parts.slice(-2).join('.');
  };

  return getBaseDomain(requestDomain) !== getBaseDomain(pageDomain);
}

function createEmptyTabState(url) {
  const domain = extractDomain(url);
  const sensitivityResult = calculateSensitivity(url, domain);

  return {
    url,
    domain,
    thirdPartyRequests: [],
    fingerprinting: {
      canvas: false,
      webgl: false,
      audio: false,
      font: false
    },
    cookieSync: {
      detected: false,
      chains: [],
      confidence: 0,
      involvedDomains: [],
      trackingParams: []
    },
    cnameCloaking: {
      detected: false,
      domains: []
    },
    sensitivity: {
      score: sensitivityResult.score,
      level: sensitivityResult.level,
      reason: sensitivityResult.reason,
      category: sensitivityResult.category
    },
    riskScore: 0,
    riskLevel: 'low',
    timestamp: Date.now()
  };
}

function serializeTabState(data) {
  return {
    ...data,
    thirdPartyRequests: data.thirdPartyRequests.map((request) => ({
      ...request,
      types: Array.from(request.types || [])
    }))
  };
}

function hydrateTabState(data) {
  return {
    ...data,
    thirdPartyRequests: (data.thirdPartyRequests || []).map((request) => ({
      ...request,
      types: new Set(request.types || [])
    }))
  };
}

async function persistTabData() {
  const serialized = {};
  for (const [tabId, data] of Object.entries(tabData)) {
    serialized[tabId] = serializeTabState(data);
  }
  await chrome.storage.session.set({ [STORAGE_KEY]: serialized });
}

async function restoreTabData() {
  const stored = await chrome.storage.session.get(STORAGE_KEY);
  const savedState = stored[STORAGE_KEY] || {};

  for (const [tabId, data] of Object.entries(savedState)) {
    tabData[tabId] = hydrateTabState(data);
  }
}

async function initTabData(tabId, url) {
  tabData[tabId] = createEmptyTabState(url);
  await persistTabData();
}

function updateRiskScore(tabId) {
  const data = tabData[tabId];
  if (!data) return;

  let capabilityScore = 0;
  if (data.fingerprinting.canvas) capabilityScore += 25;
  if (data.fingerprinting.webgl) capabilityScore += 25;
  if (data.fingerprinting.audio) capabilityScore += 20;
  if (data.fingerprinting.font) capabilityScore += 15;
  if (data.cookieSync.detected) capabilityScore += 20;
  if (data.cnameCloaking.detected) capabilityScore += 25;

  const knownTrackers = data.thirdPartyRequests.filter((request) => request.isKnownTracker);
  const highRiskTrackers = data.thirdPartyRequests.filter((request) => request.isHighRisk);
  capabilityScore += Math.min(knownTrackers.length * 5, 30);
  capabilityScore += Math.min(highRiskTrackers.length * 10, 20);
  capabilityScore = Math.min(capabilityScore, 100);

  const sensitivityScore = data.sensitivity ? data.sensitivity.score : 30;
  const frequencyScore = Math.min(data.thirdPartyRequests.length * 5, 100);

  let contextScore = Math.min(data.thirdPartyRequests.length * 3, 50);
  const trackerCategories = new Set(
    data.thirdPartyRequests
      .filter((request) => request.trackerCategory)
      .map((request) => request.trackerCategory)
  );

  if (trackerCategories.has('advertising')) contextScore += 15;
  if (trackerCategories.has('analytics')) contextScore += 10;
  if (trackerCategories.has('social')) contextScore += 10;
  if (trackerCategories.has('fingerprinting')) contextScore += 20;
  contextScore = Math.min(contextScore, 100);

  const score = (
    capabilityScore * 0.35 +
    sensitivityScore * 0.25 +
    frequencyScore * 0.15 +
    contextScore * 0.25
  );

  data.riskScore = Math.round(score);
  if (score < 33) {
    data.riskLevel = 'low';
  } else if (score < 66) {
    data.riskLevel = 'medium';
  } else {
    data.riskLevel = 'high';
  }

  updateBadge(tabId, data.riskLevel);
}

function updateBadge(tabId, riskLevel) {
  const colors = {
    low: '#4CAF50',
    medium: '#FF9800',
    high: '#F44336'
  };

  const texts = {
    low: 'L',
    medium: 'M',
    high: 'H'
  };

  chrome.action.setBadgeBackgroundColor({ color: colors[riskLevel], tabId });
  chrome.action.setBadgeText({ text: texts[riskLevel], tabId });
}

function buildFindingStatuses(data) {
  const fingerprintDetected = Object.values(data.fingerprinting || {}).some(Boolean);
  const knownTrackers = (data.thirdPartyRequests || []).filter((request) => request.isKnownTracker);
  const trackerCount = knownTrackers.length || (data.thirdPartyRequests || []).length;

  return {
    deviceIdentification: {
      status: fingerprintDetected ? 'detected' : 'not_detected'
    },
    dataSharing: {
      status: data.cookieSync?.detected ? 'detected' : 'not_detected'
    },
    trackers: {
      status: trackerCount > 0 ? 'found' : 'none',
      count: trackerCount,
      label: trackerCount > 0 ? `${trackerCount} found` : 'None'
    },
    hiddenTracking: {
      status: data.cnameCloaking?.detected ? 'detected' : 'not_detected'
    }
  };
}

function buildSummary(data, findings) {
  if (
    findings.trackers.status === 'none' &&
    findings.deviceIdentification.status === 'not_detected' &&
    findings.dataSharing.status === 'not_detected' &&
    findings.hiddenTracking.status === 'not_detected'
  ) {
    return 'We did not observe strong tracking signals on this page.';
  }

  if (data.riskLevel === 'high') {
    if (
      findings.deviceIdentification.status === 'detected' &&
      findings.dataSharing.status === 'detected'
    ) {
      return 'Observed signals suggest device identification and cross-company data sharing.';
    }

    if (findings.deviceIdentification.status === 'detected') {
      return 'Observed signals suggest that this page may be identifying your device.';
    }

    return 'Observed signals suggest substantial tracking activity on this page.';
  }

  if (data.riskLevel === 'medium') {
    if (findings.dataSharing.status === 'detected') {
      return 'Observed signals suggest data sharing between tracking services.';
    }

    return 'Observed signals suggest moderate tracking activity on this page.';
  }

  return 'Only limited tracking signals were observed on this page.';
}

function buildResponseData(data) {
  const findings = buildFindingStatuses(data);

  return {
    url: data.url,
    domain: data.domain,
    thirdPartyRequests: data.thirdPartyRequests.map((request) => ({
      domain: request.domain,
      url: request.url,
      count: request.count,
      types: Array.from(request.types || []),
      timestamp: request.timestamp,
      isKnownTracker: request.isKnownTracker || false,
      trackerCategory: request.trackerCategory || null,
      isHighRisk: request.isHighRisk || false,
      isCnameCloaking: request.isCnameCloaking || false
    })),
    fingerprinting: { ...data.fingerprinting },
    cookieSync: {
      detected: data.cookieSync.detected,
      chains: data.cookieSync.chains.map((chain) => ({
        fromDomain: chain.fromDomain,
        toDomain: chain.toDomain,
        confidence: chain.analysis ? chain.analysis.confidence : 0
      })),
      confidence: data.cookieSync.confidence || 0,
      involvedDomains: data.cookieSync.involvedDomains || [],
      trackingParams: data.cookieSync.trackingParams || []
    },
    cnameCloaking: {
      detected: data.cnameCloaking.detected,
      domains: [...data.cnameCloaking.domains]
    },
    sensitivity: data.sensitivity ? { ...data.sensitivity } : null,
    findings,
    summary: buildSummary(data, findings),
    note: 'This score is based on observed page activity.',
    riskScore: data.riskScore,
    riskLevel: data.riskLevel,
    timestamp: data.timestamp
  };
}

async function processRequest(tabId, requestUrl, type) {
  const data = tabData[tabId];
  if (!data) return;

  const requestDomain = extractDomain(requestUrl);
  if (!isThirdParty(requestDomain, data.domain)) return;

  const trackerInfo = checkTracker(requestDomain);
  const cnameMatch = isCnameCloaking(requestDomain);

  if (cnameMatch && !data.cnameCloaking.domains.includes(requestDomain)) {
    data.cnameCloaking.detected = true;
    data.cnameCloaking.domains.push(requestDomain);
  }

  const existingRequest = data.thirdPartyRequests.find((request) => request.domain === requestDomain);
  if (existingRequest) {
    existingRequest.count += 1;
    existingRequest.types.add(type);
  } else {
    data.thirdPartyRequests.push({
      domain: requestDomain,
      url: requestUrl,
      count: 1,
      types: new Set([type]),
      timestamp: Date.now(),
      isKnownTracker: Boolean(trackerInfo),
      trackerCategory: trackerInfo?.category || null,
      isHighRisk: trackerInfo?.isHighRisk || false,
      isCnameCloaking: cnameMatch
    });
  }

  updateRiskScore(tabId);
  await persistTabData();
}

async function handleRedirect(tabId, url, redirectUrl) {
  const data = tabData[tabId];
  if (!data) return;

  const fromDomain = extractDomain(url);
  const toDomain = extractDomain(redirectUrl);
  if (!shouldRecordRedirect(fromDomain, toDomain, url, redirectUrl)) return;

  const redirectInfo = {
    fromDomain,
    toDomain,
    url,
    redirectUrl,
    timestamp: Date.now()
  };

  redirectInfo.analysis = analyzeRedirect(redirectInfo);
  data.cookieSync.chains.push(redirectInfo);

  const chainAnalysis = analyzeCookieSyncChain(data.cookieSync.chains);
  data.cookieSync.detected = chainAnalysis.detected;
  data.cookieSync.confidence = chainAnalysis.confidence;
  data.cookieSync.involvedDomains = chainAnalysis.involvedDomains;
  data.cookieSync.trackingParams = chainAnalysis.trackingParamsFound;

  updateRiskScore(tabId);
  await persistTabData();
}

async function handleFingerprintDetection(tabId, detection) {
  const data = tabData[tabId];
  if (!data) return;

  if (detection.type in data.fingerprinting) {
    data.fingerprinting[detection.type] = true;
    updateRiskScore(tabId);
    await persistTabData();
  }
}

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    const { tabId, url, type } = details;
    if (tabId < 0) return;

    if (!tabData[tabId]) {
      chrome.tabs.get(tabId, async (tab) => {
        if (chrome.runtime.lastError || !tab?.url) return;
        await initTabData(tabId, tab.url);
        await processRequest(tabId, url, type);
      });
      return;
    }

    processRequest(tabId, url, type);
  },
  { urls: ['<all_urls>'] }
);

chrome.webRequest.onBeforeRedirect.addListener(
  (details) => {
    const { tabId, url, redirectUrl } = details;
    if (tabId < 0 || !tabData[tabId]) return;
    handleRedirect(tabId, url, redirectUrl);
  },
  { urls: ['<all_urls>'] }
);

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading' && tab.url) {
    initTabData(tabId, tab.url).then(() => updateBadge(tabId, 'low'));
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabData[tabId];
  persistTabData();
});

chrome.tabs.onActivated.addListener(({ tabId }) => {
  if (tabData[tabId]) {
    updateBadge(tabId, tabData[tabId].riskLevel);
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender.tab?.id || message.tabId;

  switch (message.type) {
    case 'FINGERPRINT_DETECTED':
      if (typeof tabId === 'number' && tabId >= 0) {
        handleFingerprintDetection(tabId, message.data).then(() => {
          sendResponse({ success: true });
        });
      } else {
        sendResponse({ success: false });
      }
      break;
    case 'GET_TAB_DATA':
      if (typeof tabId === 'number' && tabData[tabId]) {
        sendResponse({ success: true, data: buildResponseData(tabData[tabId]) });
      } else {
        sendResponse({ success: false, data: null });
      }
      break;
    default:
      sendResponse({ success: false, error: 'Unknown message type' });
  }

  return true;
});

async function bootstrap() {
  await restoreTabData();
  const tabs = await chrome.tabs.query({});

  for (const tab of tabs) {
    if (tab.id && tab.url && !tabData[tab.id]) {
      tabData[tab.id] = createEmptyTabState(tab.url);
    }
  }

  await persistTabData();
}

bootstrap();
