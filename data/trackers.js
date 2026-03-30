/**
 * Data Transparency Monitor - Known Tracker List
 * 
 * 数据来源:
 * - EasyPrivacy (https://easylist.to/)
 * - Disconnect (https://disconnect.me/trackerprotection)
 * - 学术研究论文中的常见tracker
 * 
 * 分类:
 * - advertising: 广告追踪
 * - analytics: 数据分析
 * - social: 社交媒体追踪
 * - fingerprinting: 已知使用fingerprinting的域名
 * - cname: 已知的CNAME cloaking域名
 */

const TRACKER_DATABASE = {
  
  // ============================================
  // 广告追踪 (Advertising)
  // ============================================
  advertising: [
    // Google Ads
    'doubleclick.net',
    'googlesyndication.com',
    'googleadservices.com',
    'googleads.g.doubleclick.net',
    'pagead2.googlesyndication.com',
    'adservice.google.com',
    
    // Facebook/Meta
    'facebook.net',
    'facebook.com',
    'fbcdn.net',
    'connect.facebook.net',
    
    // Amazon
    'amazon-adsystem.com',
    'aax.amazon-adsystem.com',
    
    // Microsoft/Bing
    'bat.bing.com',
    'ads.microsoft.com',
    
    // Twitter/X
    'ads-twitter.com',
    'ads-api.twitter.com',
    
    // 其他主要广告网络
    'criteo.com',
    'criteo.net',
    'outbrain.com',
    'taboola.com',
    'rubiconproject.com',
    'pubmatic.com',
    'openx.net',
    'casalemedia.com',
    'adnxs.com',
    'adsrvr.org',
    'demdex.net',
    'krxd.net',
    'bluekai.com',
    'exelator.com',
    'eyeota.net',
    'mediamath.com',
    'bidswitch.net',
    'adform.net',
    'smartadserver.com',
    'advertising.com',
    'yieldmo.com',
    'sharethrough.com',
    'spotxchange.com',
    'indexww.com',
    'lijit.com',
    'sovrn.com',
    'gumgum.com',
    'triplelift.com',
    '33across.com',
    'rhythmone.com',
    'undertone.com'
  ],
  
  // ============================================
  // 数据分析 (Analytics)
  // ============================================
  analytics: [
    // Google Analytics
    'google-analytics.com',
    'googletagmanager.com',
    'googletagservices.com',
    'analytics.google.com',
    
    // Adobe Analytics
    'omtrdc.net',
    'demdex.net',
    '2o7.net',
    'everesttech.net',
    
    // 其他分析服务
    'hotjar.com',
    'hotjar.io',
    'mixpanel.com',
    'amplitude.com',
    'segment.io',
    'segment.com',
    'heapanalytics.com',
    'fullstory.com',
    'mouseflow.com',
    'luckyorange.com',
    'crazyegg.com',
    'clicktale.net',
    'quantserve.com',
    'scorecardresearch.com',
    'comscore.com',
    'newrelic.com',
    'nr-data.net',
    'chartbeat.com',
    'parsely.com',
    'piano.io',
    'tinypass.com',
    'optimizely.com',
    'abtasty.com',
    'vwo.com',
    'kissmetrics.com',
    'keen.io',
    'pendo.io',
    'walkme.com',
    'appcues.com',
    'intercom.io',
    'drift.com',
    'zendesk.com',
    'freshworks.com'
  ],
  
  // ============================================
  // 社交媒体追踪 (Social)
  // ============================================
  social: [
    // Facebook/Meta
    'facebook.com',
    'facebook.net',
    'fbcdn.net',
    'instagram.com',
    'whatsapp.com',
    
    // Twitter/X
    'twitter.com',
    'twimg.com',
    'x.com',
    't.co',
    'syndication.twitter.com',
    'platform.twitter.com',
    
    // LinkedIn
    'linkedin.com',
    'licdn.com',
    'ads.linkedin.com',
    
    // Pinterest
    'pinterest.com',
    'pinimg.com',
    'ads.pinterest.com',
    
    // TikTok
    'tiktok.com',
    'tiktokcdn.com',
    'byteoversea.com',
    
    // Reddit
    'reddit.com',
    'redditstatic.com',
    'redditmedia.com',
    
    // Snapchat
    'snapchat.com',
    'snap.com',
    'sc-static.net',
    
    // 其他
    'addthis.com',
    'addtoany.com',
    'sharethis.com'
  ],
  
  // ============================================
  // 已知使用 Fingerprinting 的域名
  // ============================================
  fingerprinting: [
    // 设备识别服务
    'iovation.com',
    'threatmetrix.com',
    'fingerprintjs.com',
    'fpjs.io',
    'fraudlogicx.com',
    'signifyd.com',
    'sift.com',
    'forter.com',
    'riskified.com',
    'kount.com',
    'socure.com',
    'ekata.com',
    'emailage.com',
    
    // CDN 提供的追踪服务（常用于fingerprinting）
    'cloudflare.com',  // Cloudflare Insights (有争议，但包含追踪)
    'akamaihd.net',
    
    // 学术研究中发现的fingerprinting域名
    'bluecava.com',
    'maxmind.com',
    'id5-sync.com',
    'liveintent.com',
    'liveramp.com',
    'tapad.com',
    'drawbridge.com',
    'crosswise.com'
  ],
  
  // ============================================
  // CNAME Cloaking 域名
  // 这些是已知使用CNAME cloaking技术的第一方伪装域名
  // 来源: 学术论文 "Measuring the Prevalence of CNAME Cloaking-based Tracking"
  // ============================================
  cnameCloaking: [
    // Adobe Experience Cloud (常见CNAME目标)
    'data.adobedc.net',
    'dpm.demdex.net',
    
    // Eulerian
    'eulerian.net',
    
    // Criteo
    'dnsdelegation.io',
    
    // AT Internet
    'xiti.com',
    
    // Commanders Act
    'tagcommander.com',
    
    // Piano/AT Internet
    'at-o.net',
    
    // 常见的CNAME伪装模式 (子域名)
    // 这些是tracker经常CNAME到的目标
    'omtrdc.net',
    'sc.omtrdc.net',
    '2o7.net',
    'ati-host.net',
    'keyade.com',
    'wizaly.com',
    'oghub.io',
    'k.keyade.com',
    'affex.org',
    'intentmedia.net',
    'a]ffiliation.com',
    'weborama.fr',
    'mediarithmics.com'
  ]
};

// ============================================
// 高风险 Tracker 列表
// 这些tracker有更激进的追踪行为
// ============================================
const HIGH_RISK_TRACKERS = new Set([
  // Fingerprinting 专家
  'fingerprintjs.com',
  'fpjs.io',
  'iovation.com',
  'threatmetrix.com',
  
  // 跨设备追踪
  'tapad.com',
  'drawbridge.com',
  'liveramp.com',
  'crosswise.com',
  
  // 数据经纪商
  'bluekai.com',
  'exelator.com',
  'eyeota.net',
  'krxd.net',
  'demdex.net',
  
  // CNAME cloaking
  'eulerian.net',
  'dnsdelegation.io',
  'omtrdc.net'
]);

// ============================================
// 导出函数
// ============================================

/**
 * 检查域名是否是已知tracker
 * @param {string} domain - 要检查的域名
 * @returns {object|null} - tracker信息或null
 */
function checkTracker(domain) {
  if (!domain) return null;
  
  // 标准化域名
  const normalizedDomain = domain.toLowerCase().trim();
  
  // 检查每个分类
  for (const [category, domains] of Object.entries(TRACKER_DATABASE)) {
    for (const trackerDomain of domains) {
      // 精确匹配或子域名匹配
      if (normalizedDomain === trackerDomain || 
          normalizedDomain.endsWith('.' + trackerDomain)) {
        return {
          domain: trackerDomain,
          category: category,
          isHighRisk: HIGH_RISK_TRACKERS.has(trackerDomain),
          matched: normalizedDomain
        };
      }
    }
  }
  
  return null;
}

/**
 * 检查域名是否是CNAME cloaking
 * @param {string} domain - 要检查的域名
 * @returns {boolean}
 */
function isCnameCloaking(domain) {
  if (!domain) return false;
  
  const normalizedDomain = domain.toLowerCase().trim();
  
  for (const cnameDomain of TRACKER_DATABASE.cnameCloaking) {
    if (normalizedDomain === cnameDomain || 
        normalizedDomain.endsWith('.' + cnameDomain)) {
      return true;
    }
  }
  
  return false;
}

/**
 * 获取所有tracker域名（用于快速查找）
 * @returns {Set<string>}
 */
function getAllTrackerDomains() {
  const allDomains = new Set();
  
  for (const domains of Object.values(TRACKER_DATABASE)) {
    for (const domain of domains) {
      allDomains.add(domain);
    }
  }
  
  return allDomains;
}

/**
 * 获取tracker统计信息
 * @returns {object}
 */
function getTrackerStats() {
  const stats = {
    total: 0,
    byCategory: {}
  };
  
  for (const [category, domains] of Object.entries(TRACKER_DATABASE)) {
    stats.byCategory[category] = domains.length;
    stats.total += domains.length;
  }
  
  return stats;
}

// 导出供service worker使用
// 注意：由于service worker使用ES modules，需要用export
export { 
  TRACKER_DATABASE, 
  HIGH_RISK_TRACKERS,
  checkTracker, 
  isCnameCloaking,
  getAllTrackerDomains,
  getTrackerStats
};
