// Known tracker domains used by the monitor.

const TRACKER_DATABASE = {

  // Advertising trackers.
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

    // Other major ad networks.
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

  // Analytics services.
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

    // Other analytics services.
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

  // Social trackers.
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

    // Other sharing widgets.
    'addthis.com',
    'addtoany.com',
    'sharethis.com'
  ],

  // Domains associated with fingerprinting.
  fingerprinting: [
    // Device identification services.
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

    // CDN-provided services that may include tracking.
    'cloudflare.com',  // Cloudflare Insights
    'akamaihd.net',

    // Fingerprinting domains reported in research.
    'bluecava.com',
    'maxmind.com',
    'id5-sync.com',
    'liveintent.com',
    'liveramp.com',
    'tapad.com',
    'drawbridge.com',
    'crosswise.com'
  ],

  // Known CNAME cloaking targets.
  cnameCloaking: [
    // Adobe Experience Cloud
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

    // Common CNAME destinations.
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
    'affiliation.com',
    'weborama.fr',
    'mediarithmics.com'
  ]
};

// Trackers treated as higher risk by the UI.
const HIGH_RISK_TRACKERS = new Set([
  // Fingerprinting specialists.
  'fingerprintjs.com',
  'fpjs.io',
  'iovation.com',
  'threatmetrix.com',

  // Cross-device tracking.
  'tapad.com',
  'drawbridge.com',
  'liveramp.com',
  'crosswise.com',

  // Data brokers.
  'bluekai.com',
  'exelator.com',
  'eyeota.net',
  'krxd.net',
  'demdex.net',

  // CNAME cloaking.
  'eulerian.net',
  'dnsdelegation.io',
  'omtrdc.net'
]);

/**
 * Checks whether a domain matches a known tracker entry.
 * @param {string} domain
 * @returns {object|null}
 */
function checkTracker(domain) {
  if (!domain) return null;

  const normalizedDomain = domain.toLowerCase().trim();

  for (const [category, domains] of Object.entries(TRACKER_DATABASE)) {
    for (const trackerDomain of domains) {
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
 * Checks whether a domain matches a known CNAME cloaking target.
 * @param {string} domain
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

// Build a set for faster domain lookups.
function getAllTrackerDomains() {
  const allDomains = new Set();

  for (const domains of Object.values(TRACKER_DATABASE)) {
    for (const domain of domains) {
      allDomains.add(domain);
    }
  }

  return allDomains;
}

// Counts exposed for diagnostics.
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

export {
  TRACKER_DATABASE,
  HIGH_RISK_TRACKERS,
  checkTracker,
  isCnameCloaking,
  getAllTrackerDomains,
  getTrackerStats
};
