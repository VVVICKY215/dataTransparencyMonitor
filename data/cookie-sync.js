// Prototype-level cookie-syncing heuristic.

// Parameter names that may carry identifiers.
const TRACKING_PARAMS = [
  // Common user identifier parameters.
  'uid', 'uuid', 'userid', 'user_id', 'u_id',
  'id', 'cid', 'clientid', 'client_id',
  'vid', 'visitorid', 'visitor_id',
  'sid', 'sessionid', 'session_id',

  // Cookie-syncing specific parameters.
  'sync', 'sync_id', 'syncid',
  'match', 'match_id', 'matchid',
  'partner', 'partner_id', 'partnerid',
  'pixel', 'pixelid', 'pixel_id',
  'bounce', 'bounceid',

  // Ad platform parameters.
  'gclid',      // Google Click ID
  'fbclid',     // Facebook Click ID
  'msclkid',    // Microsoft Click ID
  'ttclid',     // TikTok Click ID
  'dclid',      // DoubleClick ID
  'gaid',       // Google Advertising ID
  'idfa',       // iOS Advertising ID
  'aaid',       // Android Advertising ID

  // DSP and SSP parameters.
  'bidid', 'bid_id',
  'impid', 'imp_id',
  'aucid', 'auction_id',
  'reqid', 'request_id',

  // Other common tracking parameters.
  'tracking', 'trackingid', 'tracking_id',
  'ref', 'refid', 'ref_id',
  'source', 'src',
  'campaign', 'cmp',
  'adid', 'ad_id',
  'clickid', 'click_id',
  'conversionid', 'conversion_id',

  // Fields that may hold encoded or hashed identifiers.
  'data', 'payload', 'token', 'hash'
];

// URL path patterns often seen in syncing or tracking requests.
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

// Login providers excluded to reduce false positives.
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

  // Other common login services.
  'login.yahoo.com',
  'auth.atlassian.com',
  'id.heroku.com',
  'sso.godaddy.com'
]);

// Domains used as supporting evidence for possible syncing.
const KNOWN_SYNC_DOMAINS = new Set([
  // Google
  'cm.g.doubleclick.net',
  'googleads.g.doubleclick.net',
  'pagead2.googlesyndication.com',
  'www.googleadservices.com',

  // Facebook
  'www.facebook.com',
  'pixel.facebook.com',

  // Data exchange platforms.
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

  // Other syncing services.
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

/**
 * Checks one redirect for signs of cookie syncing.
 * @param {object} redirect
 * @param {string} redirect.fromDomain
 * @param {string} redirect.toDomain
 * @param {string} redirect.url
 * @param {string} redirect.redirectUrl
 * @returns {object}
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

  // Ignore same-domain redirects.
  if (!result.isCrossDomain) {
    return result;
  }

  // Login redirects can look similar, so they are excluded.
  if (OAUTH_PROVIDERS.has(fromDomain) || OAUTH_PROVIDERS.has(toDomain)) {
    result.isOAuthRelated = true;
    result.reasons.push('OAuth provider detected');
    return result;
  }

  const trackingParams = extractTrackingParams(url);
  const redirectTrackingParams = extractTrackingParams(redirectUrl);
  const allTrackingParams = [...new Set([...trackingParams, ...redirectTrackingParams])];

  if (allTrackingParams.length > 0) {
    result.hasTrackingParams = true;
    result.trackingParamsFound = allTrackingParams;
    result.confidence += 30;
    result.reasons.push(`Tracking params: ${allTrackingParams.join(', ')}`);
  }

  // Sync-like paths are treated as supporting evidence.
  if (matchesSyncPattern(url) || matchesSyncPattern(redirectUrl)) {
    result.hasSyncPattern = true;
    result.confidence += 25;
    result.reasons.push('URL matches sync pattern');
  }

  // Known sync domains add stronger evidence.
  if (KNOWN_SYNC_DOMAINS.has(fromDomain) || KNOWN_SYNC_DOMAINS.has(toDomain)) {
    result.involvesKnownSyncDomain = true;
    result.confidence += 35;
    result.reasons.push('Known sync domain involved');
  }

  // Long random-looking strings are weak supporting evidence.
  if (hasLongIdString(url) || hasLongIdString(redirectUrl)) {
    result.confidence += 10;
    result.reasons.push('Long ID string detected');
  }

  return result;
}

// Extract parameters that look relevant to tracking or syncing.
function extractTrackingParams(url) {
  const found = [];

  try {
    const urlObj = new URL(url);
    const params = urlObj.searchParams;

    for (const [key, value] of params) {
      const lowerKey = key.toLowerCase();

      if (TRACKING_PARAMS.some(tp => lowerKey.includes(tp))) {
        found.push(key);
        continue;
      }

      // Long alphanumeric values may be user identifiers.
      if (value && value.length >= 16 && /^[a-zA-Z0-9_-]+$/.test(value)) {
        found.push(`${key}(id-like)`);
      }
    }
  } catch (e) {
    // Invalid URL, ignore.
  }

  return found;
}

// Check whether the URL path matches a sync-like pattern.
function matchesSyncPattern(url) {
  try {
    const urlObj = new URL(url);
    const path = urlObj.pathname.toLowerCase();

    return SYNC_URL_PATTERNS.some(pattern => path.includes(pattern));
  } catch (e) {
    return false;
  }
}

// Look for long strings that may be encoded identifiers.
function hasLongIdString(url) {
  const idPattern = /[a-zA-Z0-9_-]{20,}/;
  return idPattern.test(url);
}

/**
 * Checks a redirect chain for possible cookie syncing.
 * @param {array} redirectChain
 * @returns {object}
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

  for (const redirect of redirectChain) {
    const analysis = analyzeRedirect(redirect);
    result.details.push(analysis);

    // Skip login-related redirects.
    if (analysis.isOAuthRelated) {
      continue;
    }

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

  result.trackingParamsFound = [...new Set(result.trackingParamsFound)];
  result.knownSyncDomains = [...new Set(result.knownSyncDomains)];
  result.involvedDomains = [...result.involvedDomains];
  result.reasons = [...new Set(result.reasons)];

  // Confidence values are manually tuned for this prototype, not probabilistic.
  if (result.confidence >= 40 && result.involvedDomains.length >= 2) {
    result.detected = true;
  }

  // A known sync domain plus tracking parameters is stronger evidence.
  if (result.knownSyncDomains.length > 0 && result.trackingParamsFound.length > 0) {
    result.detected = true;
    result.confidence = Math.max(result.confidence, 70);
  }

  // Cross-domain redirects without syncing features stay low confidence.
  if (result.trackingParamsFound.length === 0 &&
      result.knownSyncDomains.length === 0 &&
      !result.reasons.some(r => r.includes('sync pattern'))) {
    result.detected = false;
    result.confidence = Math.min(result.confidence, 30);
  }

  return result;
}

// Lightweight check for whether a redirect is worth recording.
function shouldRecordRedirect(fromDomain, toDomain, url, redirectUrl) {
  if (fromDomain === toDomain) {
    return false;
  }

  if (OAUTH_PROVIDERS.has(fromDomain) || OAUTH_PROVIDERS.has(toDomain)) {
    return false;
  }

  const hasFeatures =
    KNOWN_SYNC_DOMAINS.has(fromDomain) ||
    KNOWN_SYNC_DOMAINS.has(toDomain) ||
    matchesSyncPattern(url) ||
    matchesSyncPattern(redirectUrl) ||
    extractTrackingParams(url).length > 0 ||
    extractTrackingParams(redirectUrl).length > 0;

  return hasFeatures;
}

// Counts exposed for diagnostics.
function getCookieSyncStats() {
  return {
    trackingParamsCount: TRACKING_PARAMS.length,
    syncPatternsCount: SYNC_URL_PATTERNS.length,
    oauthProvidersCount: OAUTH_PROVIDERS.size,
    knownSyncDomainsCount: KNOWN_SYNC_DOMAINS.size
  };
}

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
