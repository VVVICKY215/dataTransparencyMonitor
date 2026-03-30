/**
 * Data Transparency Monitor - Background Service Worker
 * 
 * 职责：
 * 1. 监听网络请求，检测第三方追踪
 * 2. 接收来自content script的fingerprinting检测结果
 * 3. 计算风险评分
 * 4. 更新扩展图标状态
 */

// 导入tracker数据库
import { 
  checkTracker, 
  isCnameCloaking, 
  HIGH_RISK_TRACKERS,
  getTrackerStats 
} from '../data/trackers.js';

// 导入敏感度计算模块
import {
  calculateSensitivity,
  getSensitivityLevel
} from '../data/sensitivity.js';

// 导入 Cookie Syncing 检测模块
import {
  analyzeRedirect,
  analyzeCookieSyncChain,
  shouldRecordRedirect,
  KNOWN_SYNC_DOMAINS
} from '../data/cookie-sync.js';

// ============================================
// 数据存储结构
// ============================================

/**
 * 每个标签页的追踪数据结构
 * tabData[tabId] = {
 *   url: string,
 *   domain: string,
 *   thirdPartyRequests: Array,
 *   fingerprinting: {
 *     canvas: boolean,
 *     webgl: boolean,
 *     audio: boolean,
 *     font: boolean
 *   },
 *   cookieSync: {
 *     detected: boolean,
 *     chains: Array
 *   },
 *   cnameCloaking: {
 *     detected: boolean,
 *     domains: Array
 *   },
 *   riskScore: number,
 *   riskLevel: 'low' | 'medium' | 'high',
 *   timestamp: number
 * }
 */
const tabData = {};

// ============================================
// 工具函数
// ============================================

/**
 * 从URL中提取域名
 */
function extractDomain(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname;
  } catch (e) {
    return null;
  }
}

/**
 * 检查是否是第三方请求
 */
function isThirdParty(requestDomain, pageDomain) {
  if (!requestDomain || !pageDomain) return false;
  
  // 提取根域名（简化版，后续可以用public suffix list优化）
  const getBaseDomain = (domain) => {
    const parts = domain.split('.');
    if (parts.length <= 2) return domain;
    return parts.slice(-2).join('.');
  };
  
  return getBaseDomain(requestDomain) !== getBaseDomain(pageDomain);
}

/**
 * 初始化标签页数据
 */
function initTabData(tabId, url) {
  const domain = extractDomain(url);
  
  // 计算网站敏感度
  const sensitivityResult = calculateSensitivity(url, domain);
  
  tabData[tabId] = {
    url: url,
    domain: domain,
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
    // 新增：敏感度信息
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
  console.log(`[DTM] Initialized tab ${tabId}: ${domain} (sensitivity: ${sensitivityResult.score} - ${sensitivityResult.level})`);
}

// ============================================
// 网络请求监听
// ============================================

/**
 * 监听所有网络请求
 */
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    const { tabId, url, type, initiator } = details;
    
    // 忽略扩展自身的请求和无效tabId
    if (tabId < 0) return;
    
    // 如果tab数据不存在，先初始化
    if (!tabData[tabId]) {
      // 尝试获取tab信息
      chrome.tabs.get(tabId, (tab) => {
        if (chrome.runtime.lastError || !tab) return;
        initTabData(tabId, tab.url);
        processRequest(tabId, url, type, initiator);
      });
    } else {
      processRequest(tabId, url, type, initiator);
    }
  },
  { urls: ["<all_urls>"] }
);

/**
 * 处理单个请求
 */
function processRequest(tabId, requestUrl, type, initiator) {
  const data = tabData[tabId];
  if (!data) return;
  
  const requestDomain = extractDomain(requestUrl);
  
  // 检测第三方请求
  if (isThirdParty(requestDomain, data.domain)) {
    // 检查是否是已知tracker
    const trackerInfo = checkTracker(requestDomain);
    
    // 检查是否是CNAME cloaking
    const isCname = isCnameCloaking(requestDomain);
    if (isCname && !data.cnameCloaking.detected) {
      data.cnameCloaking.detected = true;
      data.cnameCloaking.domains.push(requestDomain);
      console.log(`[DTM] CNAME cloaking detected on tab ${tabId}: ${requestDomain}`);
    }
    
    // 记录第三方请求
    const existingRequest = data.thirdPartyRequests.find(r => r.domain === requestDomain);
    if (existingRequest) {
      existingRequest.count++;
      existingRequest.types.add(type);
    } else {
      data.thirdPartyRequests.push({
        domain: requestDomain,
        url: requestUrl,
        count: 1,
        types: new Set([type]),
        timestamp: Date.now(),
        // 新增：tracker信息
        isKnownTracker: !!trackerInfo,
        trackerCategory: trackerInfo?.category || null,
        isHighRisk: trackerInfo?.isHighRisk || false,
        isCnameCloaking: isCname
      });
      
      if (trackerInfo) {
        console.log(`[DTM] Known tracker detected: ${requestDomain} (${trackerInfo.category})`);
      }
    }
    
    // 更新风险评分
    updateRiskScore(tabId);
  }
}

/**
 * 监听重定向（用于检测cookie syncing）
 * 改进版：使用更精确的检测算法
 */
chrome.webRequest.onBeforeRedirect.addListener(
  (details) => {
    const { tabId, url, redirectUrl } = details;
    if (tabId < 0 || !tabData[tabId]) return;
    
    const data = tabData[tabId];
    const fromDomain = extractDomain(url);
    const toDomain = extractDomain(redirectUrl);
    
    // 使用新的检测逻辑：只记录有追踪特征的重定向
    if (shouldRecordRedirect(fromDomain, toDomain, url, redirectUrl)) {
      const redirectInfo = {
        fromDomain: fromDomain,
        toDomain: toDomain,
        url: url,
        redirectUrl: redirectUrl,
        timestamp: Date.now()
      };
      
      // 分析这个重定向
      const analysis = analyzeRedirect(redirectInfo);
      redirectInfo.analysis = analysis;
      
      data.cookieSync.chains.push(redirectInfo);
      
      console.log(`[DTM] Redirect recorded: ${fromDomain} → ${toDomain} (confidence: ${analysis.confidence})`);
      
      // 重新分析整个重定向链
      const chainAnalysis = analyzeCookieSyncChain(data.cookieSync.chains);
      
      if (chainAnalysis.detected && !data.cookieSync.detected) {
        data.cookieSync.detected = true;
        data.cookieSync.confidence = chainAnalysis.confidence;
        data.cookieSync.involvedDomains = chainAnalysis.involvedDomains;
        data.cookieSync.trackingParams = chainAnalysis.trackingParamsFound;
        
        console.log(`[DTM] Cookie syncing CONFIRMED on tab ${tabId}:`, {
          confidence: chainAnalysis.confidence,
          domains: chainAnalysis.involvedDomains,
          params: chainAnalysis.trackingParamsFound,
          reasons: chainAnalysis.reasons
        });
        
        updateRiskScore(tabId);
      }
    }
  },
  { urls: ["<all_urls>"] }
);

// ============================================
// 标签页生命周期管理
// ============================================

/**
 * 标签页更新时重置数据
 */
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading' && tab.url) {
    initTabData(tabId, tab.url);
    updateBadge(tabId, 'low');
  }
});

/**
 * 标签页关闭时清理数据
 */
chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabData[tabId];
  console.log(`[DTM] Cleaned up tab ${tabId}`);
});

/**
 * 标签页激活时更新badge
 */
chrome.tabs.onActivated.addListener(({ tabId }) => {
  if (tabData[tabId]) {
    updateBadge(tabId, tabData[tabId].riskLevel);
  }
});

// ============================================
// 风险评分计算
// ============================================

/**
 * 更新风险评分
 */
function updateRiskScore(tabId) {
  const data = tabData[tabId];
  if (!data) return;
  
  let score = 0;
  
  // 1. Tracker Capability (权重: 0.35)
  let capabilityScore = 0;
  
  // Fingerprinting (最高风险)
  if (data.fingerprinting.canvas) capabilityScore += 25;
  if (data.fingerprinting.webgl) capabilityScore += 25;
  if (data.fingerprinting.audio) capabilityScore += 20;
  if (data.fingerprinting.font) capabilityScore += 15;
  
  // Cookie syncing
  if (data.cookieSync.detected) capabilityScore += 20;
  
  // CNAME cloaking
  if (data.cnameCloaking.detected) capabilityScore += 25;
  
  // 新增：已知tracker加分
  const knownTrackers = data.thirdPartyRequests.filter(r => r.isKnownTracker);
  const highRiskTrackers = data.thirdPartyRequests.filter(r => r.isHighRisk);
  
  // 每个已知tracker +5分，上限30分
  capabilityScore += Math.min(knownTrackers.length * 5, 30);
  
  // 每个高风险tracker额外+10分，上限20分
  capabilityScore += Math.min(highRiskTrackers.length * 10, 20);
  
  capabilityScore = Math.min(capabilityScore, 100);
  
  // 2. Data Sensitivity (权重: 0.25) - 动态计算！
  // 使用预先计算的敏感度分数
  let sensitivityScore = data.sensitivity ? data.sensitivity.score : 30;
  
  // 3. Tracking Frequency (权重: 0.15)
  const thirdPartyCount = data.thirdPartyRequests.length;
  let frequencyScore = Math.min(thirdPartyCount * 5, 100);
  
  // 4. Context (权重: 0.25) - 基于第三方数量和类型
  let contextScore = 0;
  
  // 基础分：第三方数量
  contextScore += Math.min(thirdPartyCount * 3, 50);
  
  // 新增：根据tracker类别加分
  const trackerCategories = new Set(
    data.thirdPartyRequests
      .filter(r => r.trackerCategory)
      .map(r => r.trackerCategory)
  );
  
  // 如果有广告tracker
  if (trackerCategories.has('advertising')) contextScore += 15;
  // 如果有分析tracker
  if (trackerCategories.has('analytics')) contextScore += 10;
  // 如果有社交tracker
  if (trackerCategories.has('social')) contextScore += 10;
  // 如果有fingerprinting专用tracker
  if (trackerCategories.has('fingerprinting')) contextScore += 20;
  
  contextScore = Math.min(contextScore, 100);
  
  // 加权计算
  score = (
    capabilityScore * 0.35 +
    sensitivityScore * 0.25 +
    frequencyScore * 0.15 +
    contextScore * 0.25
  );
  
  data.riskScore = Math.round(score);
  
  // 确定风险等级
  if (score < 33) {
    data.riskLevel = 'low';
  } else if (score < 66) {
    data.riskLevel = 'medium';
  } else {
    data.riskLevel = 'high';
  }
  
  // 更新badge
  updateBadge(tabId, data.riskLevel);
  
  console.log(`[DTM] Tab ${tabId} risk score: ${data.riskScore} (${data.riskLevel}) - ` +
              `capability:${capabilityScore}, sensitivity:${sensitivityScore}, ` +
              `frequency:${frequencyScore}, context:${contextScore}`);
}

// ============================================
// Badge 更新
// ============================================

/**
 * 更新扩展图标badge
 */
function updateBadge(tabId, riskLevel) {
  const colors = {
    low: '#4CAF50',      // 绿色
    medium: '#FF9800',   // 橙色
    high: '#F44336'      // 红色
  };
  
  const texts = {
    low: 'L',
    medium: 'M',
    high: 'H'
  };
  
  chrome.action.setBadgeBackgroundColor({
    color: colors[riskLevel],
    tabId: tabId
  });
  
  chrome.action.setBadgeText({
    text: texts[riskLevel],
    tabId: tabId
  });
}

// ============================================
// 消息处理（与content script通信）
// ============================================

/**
 * 接收来自content script和popup的消息
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // 如果是来自content script，使用sender.tab.id
  // 如果是来自popup，使用message.tabId
  const tabId = sender.tab?.id || message.tabId;
  
  console.log('[DTM] Message received:', message.type, 'tabId:', tabId);
  
  switch (message.type) {
    case 'FINGERPRINT_DETECTED':
      if (tabId && tabId >= 0) {
        handleFingerprintDetection(tabId, message.data);
      }
      sendResponse({ success: true });
      break;
      
    case 'GET_TAB_DATA':
      console.log('[DTM] GET_TAB_DATA for tab:', tabId, 'data exists:', !!tabData[tabId]);
      if (tabId && tabData[tabId]) {
        // 创建数据的深拷贝，并转换Set为Array
        const dataCopy = {
          url: tabData[tabId].url,
          domain: tabData[tabId].domain,
          thirdPartyRequests: tabData[tabId].thirdPartyRequests.map(r => ({
            domain: r.domain,
            url: r.url,
            count: r.count,
            types: Array.from(r.types || []),
            timestamp: r.timestamp,
            // 新增字段
            isKnownTracker: r.isKnownTracker || false,
            trackerCategory: r.trackerCategory || null,
            isHighRisk: r.isHighRisk || false,
            isCnameCloaking: r.isCnameCloaking || false
          })),
          fingerprinting: { ...tabData[tabId].fingerprinting },
          cookieSync: {
            detected: tabData[tabId].cookieSync.detected,
            chains: tabData[tabId].cookieSync.chains.map(c => ({
              fromDomain: c.fromDomain || c.from,
              toDomain: c.toDomain || c.to,
              confidence: c.analysis ? c.analysis.confidence : 0
            })),
            confidence: tabData[tabId].cookieSync.confidence || 0,
            involvedDomains: tabData[tabId].cookieSync.involvedDomains || [],
            trackingParams: tabData[tabId].cookieSync.trackingParams || []
          },
          cnameCloaking: {
            detected: tabData[tabId].cnameCloaking.detected,
            domains: [...tabData[tabId].cnameCloaking.domains]
          },
          // 新增：敏感度信息
          sensitivity: tabData[tabId].sensitivity ? { ...tabData[tabId].sensitivity } : null,
          riskScore: tabData[tabId].riskScore,
          riskLevel: tabData[tabId].riskLevel,
          timestamp: tabData[tabId].timestamp
        };
        console.log('[DTM] Sending data:', dataCopy);
        sendResponse({ success: true, data: dataCopy });
      } else {
        console.log('[DTM] No data for tab:', tabId);
        sendResponse({ success: false, data: null });
      }
      break;
      
    default:
      sendResponse({ success: false, error: 'Unknown message type' });
  }
  
  return true; // 保持消息通道开放
});

/**
 * 处理fingerprinting检测结果
 */
function handleFingerprintDetection(tabId, detection) {
  if (!tabData[tabId]) return;
  
  const { type, details } = detection;
  
  if (type in tabData[tabId].fingerprinting) {
    tabData[tabId].fingerprinting[type] = true;
    console.log(`[DTM] Fingerprinting detected on tab ${tabId}: ${type}`, details);
    updateRiskScore(tabId);
  }
}

// ============================================
// 初始化
// ============================================

console.log('[DTM] Data Transparency Monitor initialized');

// 启动时为所有已打开的标签页初始化
chrome.tabs.query({}, (tabs) => {
  tabs.forEach((tab) => {
    if (tab.id && tab.url) {
      initTabData(tab.id, tab.url);
    }
  });
});
