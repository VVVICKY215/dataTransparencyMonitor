/**
 * Data Transparency Monitor - Cookie Syncing Detection
 * 
 * Cookie Syncing (也叫 Cookie Matching 或 ID Syncing) 是一种追踪技术，
 * 允许不同的追踪公司通过重定向链共享用户标识符。
 * 
 * 检测策略:
 * 1. 检测跨域重定向链
 * 2. 检查 URL 参数中是否有追踪标识符
 * 3. 检查是否涉及已知 tracker
 * 4. 排除 OAuth 等合法重定向
 */

// ============================================
// 追踪参数关键词
// 这些参数名通常用于传递用户标识符
// ============================================

const TRACKING_PARAMS = [
  // 通用用户ID参数
  'uid', 'uuid', 'userid', 'user_id', 'u_id',
  'id', 'cid', 'clientid', 'client_id',
  'vid', 'visitorid', 'visitor_id',
  'sid', 'sessionid', 'session_id',
  
  // Cookie syncing 专用参数
  'sync', 'sync_id', 'syncid',
  'match', 'match_id', 'matchid',
  'partner', 'partner_id', 'partnerid',
  'pixel', 'pixelid', 'pixel_id',
  'bounce', 'bounceid',
  
  // 广告平台常用参数
  'gclid',      // Google Click ID
  'fbclid',     // Facebook Click ID
  'msclkid',    // Microsoft Click ID
  'ttclid',     // TikTok Click ID
  'dclid',      // DoubleClick ID
  'gaid',       // Google Advertising ID
  'idfa',       // iOS Advertising ID
  'aaid',       // Android Advertising ID
  
  // DSP/SSP 参数
  'bidid', 'bid_id',
  'impid', 'imp_id',
  'aucid', 'auction_id',
  'reqid', 'request_id',
  
  // 其他常见追踪参数
  'tracking', 'trackingid', 'tracking_id',
  'ref', 'refid', 'ref_id',
  'source', 'src',
  'campaign', 'cmp',
  'adid', 'ad_id',
  'clickid', 'click_id',
  'conversionid', 'conversion_id',
  
  // Base64/Hash 形式的 ID (通常很长的随机字符串)
  'data', 'payload', 'token', 'hash'
];

// ============================================
// 已知的 Cookie Syncing 端点模式
// ============================================

const SYNC_URL_PATTERNS = [
  '/sync',
  '/pixel',
  '/match',
  '/bounce',
  '/redirect',
  '/cm',           // Cookie Match
  '/id',
  '/usersync',
  '/cookiesync',
  '/idsync',
  '/getuid',
  '/setuid',
  '/beacon',
  '/track',
  '/collect',
  '/log',
  '/event',
  '/impression',
  '/conversion'
];

// ============================================
// 已知的 OAuth Providers（排除名单）
// 这些域名的重定向通常是合法的登录流程
// ============================================

const OAUTH_PROVIDERS = new Set([
  // Google
  'accounts.google.com',
  'accounts.youtube.com',
  'oauth2.googleapis.com',
  
  // Facebook/Meta
  'www.facebook.com',
  'facebook.com',
  
  // Apple
  'appleid.apple.com',
  
  // Microsoft
  'login.microsoftonline.com',
  'login.live.com',
  'login.windows.net',
  
  // Twitter/X
  'api.twitter.com',
  'twitter.com',
  
  // GitHub
  'github.com',
  
  // LinkedIn
  'www.linkedin.com',
  
  // Amazon
  'www.amazon.com',
  'amazon.com',
  
  // PayPal
  'www.paypal.com',
  'paypal.com',
  
  // Auth0
  'auth0.com',
  
  // Okta
  'okta.com',
  
  // 其他常见登录服务
  'login.yahoo.com',
  'auth.atlassian.com',
  'id.heroku.com',
  'sso.godaddy.com'
]);

// ============================================
// 已知的 Cookie Syncing 服务商
// 检测到这些域名参与重定向时，更可能是 cookie syncing
// ============================================

const KNOWN_SYNC_DOMAINS = new Set([
  // Google
  'cm.g.doubleclick.net',
  'googleads.g.doubleclick.net',
  'pagead2.googlesyndication.com',
  'www.googleadservices.com',
  
  // Facebook
  'www.facebook.com',
  'pixel.facebook.com',
  
  // 数据交换平台
  'idsync.rlcdn.com',        // LiveRamp
  'sync.1rx.io',             // RhythmOne
  'match.adsrvr.org',        // The Trade Desk
  'sync.outbrain.com',
  'cm.adform.net',
  'sync.smartadserver.com',
  'ib.adnxs.com',            // AppNexus
  'ssum.casalemedia.com',    // Index Exchange
  'pixel.rubiconproject.com',
  'sync.mathtag.com',        // MediaMath
  'x.bidswitch.net',
  'us-u.openx.net',
  'rtb.openx.net',
  
  // DMP (Data Management Platforms)
  'dpm.demdex.net',          // Adobe
  'tags.bluekai.com',        // Oracle
  'sync.krxd.net',           // Salesforce
  'loadus.exelator.com',     // Nielsen
  'stags.bluekai.com',
  'bh.contextweb.com',
  
  // 其他同步服务
  'match.rundsp.com',
  'x.bidder.criteo.com',
  'dis.criteo.com',
  'sync.taboola.com',
  'eb2.3lift.com',           // Triple Lift
  'tlx.3lift.com',
  'sync.sharethis.com',
  'pixel.advertising.com',
  'tap.rubiconproject.com',
  'token.rubiconproject.com'
]);

// ============================================
// 核心检测函数
// ============================================

/**
 * 分析单个重定向是否可能是 cookie syncing
 * @param {object} redirect - 重定向信息
 * @param {string} redirect.fromDomain - 来源域名
 * @param {string} redirect.toDomain - 目标域名
 * @param {string} redirect.url - 来源 URL
 * @param {string} redirect.redirectUrl - 目标 URL
 * @returns {object} - 分析结果
 */
function analyzeRedirect(redirect) {
  const { fromDomain, toDomain, url, redirectUrl } = redirect;
  
  const result = {
    isCrossDomain: fromDomain !== toDomain,
    isOAuthRelated: false,
    hasTrackingParams: false,
    hasSyncPattern: false,
    involvesKnownSyncDomain: false,
    trackingParamsFound: [],
    confidence: 0,  // 0-100
    reasons: []
  };
  
  // 1. 检查是否是跨域
  if (!result.isCrossDomain) {
    return result;
  }
  
  // 2. 检查是否是 OAuth 相关（排除）
  if (OAUTH_PROVIDERS.has(fromDomain) || OAUTH_PROVIDERS.has(toDomain)) {
    result.isOAuthRelated = true;
    result.reasons.push('OAuth provider detected');
    return result;
  }
  
  // 3. 检查 URL 是否包含追踪参数
  const trackingParams = extractTrackingParams(url);
  const redirectTrackingParams = extractTrackingParams(redirectUrl);
  const allTrackingParams = [...new Set([...trackingParams, ...redirectTrackingParams])];
  
  if (allTrackingParams.length > 0) {
    result.hasTrackingParams = true;
    result.trackingParamsFound = allTrackingParams;
    result.confidence += 30;
    result.reasons.push(`Tracking params: ${allTrackingParams.join(', ')}`);
  }
  
  // 4. 检查 URL 路径是否匹配同步模式
  if (matchesSyncPattern(url) || matchesSyncPattern(redirectUrl)) {
    result.hasSyncPattern = true;
    result.confidence += 25;
    result.reasons.push('URL matches sync pattern');
  }
  
  // 5. 检查是否涉及已知的 syncing 域名
  if (KNOWN_SYNC_DOMAINS.has(fromDomain) || KNOWN_SYNC_DOMAINS.has(toDomain)) {
    result.involvesKnownSyncDomain = true;
    result.confidence += 35;
    result.reasons.push('Known sync domain involved');
  }
  
  // 6. 检查 URL 中是否有疑似用户 ID 的长字符串
  if (hasLongIdString(url) || hasLongIdString(redirectUrl)) {
    result.confidence += 10;
    result.reasons.push('Long ID string detected');
  }
  
  return result;
}

/**
 * 从 URL 中提取追踪参数
 */
function extractTrackingParams(url) {
  const found = [];
  
  try {
    const urlObj = new URL(url);
    const params = urlObj.searchParams;
    
    for (const [key, value] of params) {
      const lowerKey = key.toLowerCase();
      
      // 检查参数名是否匹配已知追踪参数
      if (TRACKING_PARAMS.some(tp => lowerKey.includes(tp))) {
        found.push(key);
        continue;
      }
      
      // 检查参数值是否像是用户 ID（长随机字符串）
      if (value && value.length >= 16 && /^[a-zA-Z0-9_-]+$/.test(value)) {
        found.push(`${key}(id-like)`);
      }
    }
  } catch (e) {
    // Invalid URL, ignore
  }
  
  return found;
}

/**
 * 检查 URL 是否匹配同步模式
 */
function matchesSyncPattern(url) {
  try {
    const urlObj = new URL(url);
    const path = urlObj.pathname.toLowerCase();
    
    return SYNC_URL_PATTERNS.some(pattern => path.includes(pattern));
  } catch (e) {
    return false;
  }
}

/**
 * 检查 URL 中是否有疑似 ID 的长字符串
 */
function hasLongIdString(url) {
  // 匹配 16+ 字符的字母数字字符串（可能是 Base64 编码的 ID）
  const idPattern = /[a-zA-Z0-9_-]{20,}/;
  return idPattern.test(url);
}

/**
 * 分析整个重定向链，判断是否是 cookie syncing
 * @param {array} redirectChain - 重定向链
 * @returns {object} - 分析结果
 */
function analyzeCookieSyncChain(redirectChain) {
  const result = {
    detected: false,
    confidence: 0,
    chainLength: redirectChain.length,
    involvedDomains: new Set(),
    trackingParamsFound: [],
    knownSyncDomains: [],
    reasons: [],
    details: []
  };
  
  if (redirectChain.length < 2) {
    return result;
  }
  
  // 分析每个重定向
  for (const redirect of redirectChain) {
    const analysis = analyzeRedirect(redirect);
    result.details.push(analysis);
    
    // 跳过 OAuth 相关的
    if (analysis.isOAuthRelated) {
      continue;
    }
    
    // 累积证据
    result.involvedDomains.add(redirect.fromDomain);
    result.involvedDomains.add(redirect.toDomain);
    
    if (analysis.hasTrackingParams) {
      result.trackingParamsFound.push(...analysis.trackingParamsFound);
    }
    
    if (analysis.involvesKnownSyncDomain) {
      if (KNOWN_SYNC_DOMAINS.has(redirect.fromDomain)) {
        result.knownSyncDomains.push(redirect.fromDomain);
      }
      if (KNOWN_SYNC_DOMAINS.has(redirect.toDomain)) {
        result.knownSyncDomains.push(redirect.toDomain);
      }
    }
    
    result.confidence = Math.max(result.confidence, analysis.confidence);
    result.reasons.push(...analysis.reasons);
  }
  
  // 去重
  result.trackingParamsFound = [...new Set(result.trackingParamsFound)];
  result.knownSyncDomains = [...new Set(result.knownSyncDomains)];
  result.involvedDomains = [...result.involvedDomains];
  result.reasons = [...new Set(result.reasons)];
  
  // 判断是否检测到 cookie syncing
  // 条件：置信度 >= 40 且 涉及至少 2 个不同域名
  if (result.confidence >= 40 && result.involvedDomains.length >= 2) {
    result.detected = true;
  }
  
  // 如果涉及已知 sync 域名且有追踪参数，更确定
  if (result.knownSyncDomains.length > 0 && result.trackingParamsFound.length > 0) {
    result.detected = true;
    result.confidence = Math.max(result.confidence, 70);
  }
  
  // 如果只是普通的跨域重定向（没有追踪特征），不标记
  if (result.trackingParamsFound.length === 0 && 
      result.knownSyncDomains.length === 0 && 
      !result.reasons.some(r => r.includes('sync pattern'))) {
    result.detected = false;
    result.confidence = Math.min(result.confidence, 30);
  }
  
  return result;
}

/**
 * 简化版：快速判断单个重定向是否值得记录
 */
function shouldRecordRedirect(fromDomain, toDomain, url, redirectUrl) {
  // 同域不记录
  if (fromDomain === toDomain) {
    return false;
  }
  
  // OAuth 相关不记录
  if (OAUTH_PROVIDERS.has(fromDomain) || OAUTH_PROVIDERS.has(toDomain)) {
    return false;
  }
  
  // 检查是否有任何追踪特征
  const hasFeatures = 
    KNOWN_SYNC_DOMAINS.has(fromDomain) ||
    KNOWN_SYNC_DOMAINS.has(toDomain) ||
    matchesSyncPattern(url) ||
    matchesSyncPattern(redirectUrl) ||
    extractTrackingParams(url).length > 0 ||
    extractTrackingParams(redirectUrl).length > 0;
  
  return hasFeatures;
}

/**
 * 获取统计信息
 */
function getCookieSyncStats() {
  return {
    trackingParamsCount: TRACKING_PARAMS.length,
    syncPatternsCount: SYNC_URL_PATTERNS.length,
    oauthProvidersCount: OAUTH_PROVIDERS.size,
    knownSyncDomainsCount: KNOWN_SYNC_DOMAINS.size
  };
}

// ============================================
// 导出
// ============================================

export {
  TRACKING_PARAMS,
  SYNC_URL_PATTERNS,
  OAUTH_PROVIDERS,
  KNOWN_SYNC_DOMAINS,
  analyzeRedirect,
  analyzeCookieSyncChain,
  shouldRecordRedirect,
  extractTrackingParams,
  matchesSyncPattern,
  getCookieSyncStats
};
