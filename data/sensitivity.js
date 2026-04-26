// Website sensitivity scoring based on broad content categories.

// Score ranges used by the popup and reporting views.
const SENSITIVITY_LEVELS = {
  CRITICAL: { min: 90, max: 100, label: 'Critical', description: 'Highly sensitive personal data' },
  HIGH: { min: 70, max: 89, label: 'High', description: 'Sensitive personal/financial data' },
  MEDIUM: { min: 40, max: 69, label: 'Medium', description: 'Personal preferences and behaviors' },
  LOW: { min: 20, max: 39, label: 'Low', description: 'General interests and activities' },
  MINIMAL: { min: 10, max: 19, label: 'Minimal', description: 'Functional usage data' },
  DEFAULT: { min: 30, max: 30, label: 'Unknown', description: 'Unclassified website' }
};

// Exact domain matches. These take priority over keyword checks.
const KNOWN_DOMAINS = {
  // Critical sensitivity: health and medical.
  critical: {
    score: 95,
    domains: [
      // Health information sites.
      'webmd.com',
      'mayoclinic.org',
      'healthline.com',
      'medicalnewstoday.com',
      'drugs.com',
      'medscape.com',
      'everydayhealth.com',
      'health.com',
      'verywellhealth.com',
      'patient.info',

      // Public health services.
      'nhs.uk',
      'nih.gov',
      'cdc.gov',
      'who.int',

      // Mental health.
      'psychologytoday.com',
      'betterhelp.com',
      'talkspace.com',
      'calm.com',
      'headspace.com',
      '7cups.com',
      'mentalhealth.gov',

      // Hospitals and clinics.
      'zocdoc.com',
      'healthgrades.com',
      'vitals.com',

      // Pharmacies.
      'cvs.com',
      'walgreens.com',
      'riteaid.com',
      'pharmacy.amazon.com',

      // Health insurance.
      'healthcare.gov',
      'medicare.gov',

      // Fitness tracking.
      'myfitnesspal.com',
      'fitbit.com',
      'strava.com'
    ]
  },

  // High sensitivity: finance, government, legal, and adult content.
  high: {
    score: 80,
    domains: [
      // Banking.
      'chase.com',
      'bankofamerica.com',
      'wellsfargo.com',
      'citibank.com',
      'usbank.com',
      'capitalone.com',
      'discover.com',
      'ally.com',
      'marcus.com',
      'barclays.co.uk',
      'hsbc.com',
      'lloydsbank.com',
      'natwest.com',
      'santander.co.uk',

      // Investing and trading.
      'fidelity.com',
      'schwab.com',
      'vanguard.com',
      'etrade.com',
      'tdameritrade.com',
      'robinhood.com',
      'coinbase.com',
      'binance.com',
      'kraken.com',

      // Payment services.
      'paypal.com',
      'venmo.com',
      'squareup.com',
      'stripe.com',

      // Credit and lending.
      'creditkarma.com',
      'experian.com',
      'equifax.com',
      'transunion.com',
      'annualcreditreport.com',
      'lendingtree.com',
      'sofi.com',
      'lendingclub.com',

      // Tax.
      'irs.gov',
      'turbotax.com',
      'hrblock.com',
      'taxact.com',

      // Government services.
      'gov.uk',
      'usa.gov',
      'ssa.gov',
      'dmv.org',

      // Legal services.
      'legalzoom.com',
      'rocketlawyer.com',
      'avvo.com',
      'findlaw.com',

      // Dating apps.
      'tinder.com',
      'bumble.com',
      'hinge.co',
      'match.com',
      'okcupid.com',
      'pof.com',
      'eharmony.com',
      'grindr.com',

      // Insurance.
      'geico.com',
      'progressive.com',
      'statefarm.com',
      'allstate.com',
      'libertymutual.com'
    ]
  },

  // Medium sensitivity: shopping, social, work, and education.
  medium: {
    score: 55,
    domains: [
      // Ecommerce.
      'amazon.com',
      'amazon.co.uk',
      'ebay.com',
      'walmart.com',
      'target.com',
      'bestbuy.com',
      'costco.com',
      'homedepot.com',
      'lowes.com',
      'wayfair.com',
      'etsy.com',
      'aliexpress.com',
      'wish.com',
      'shopify.com',
      'asos.com',
      'zara.com',
      'hm.com',
      'uniqlo.com',
      'nike.com',
      'adidas.com',

      // Social media.
      'facebook.com',
      'instagram.com',
      'twitter.com',
      'x.com',
      'linkedin.com',
      'snapchat.com',
      'tiktok.com',
      'pinterest.com',
      'reddit.com',
      'tumblr.com',
      'discord.com',
      'twitch.tv',

      // Job search.
      'indeed.com',
      'glassdoor.com',
      'monster.com',
      'ziprecruiter.com',
      'careerbuilder.com',
      'dice.com',
      'hired.com',

      // Education.
      'coursera.org',
      'udemy.com',
      'edx.org',
      'khanacademy.org',
      'skillshare.com',
      'udacity.com',
      'pluralsight.com',
      'lynda.com',
      'duolingo.com',

      // Real estate.
      'zillow.com',
      'realtor.com',
      'redfin.com',
      'trulia.com',
      'rightmove.co.uk',
      'zoopla.co.uk',

      // Delivery and groceries.
      'doordash.com',
      'ubereats.com',
      'grubhub.com',
      'postmates.com',
      'instacart.com',
      'deliveroo.co.uk',
      'justeat.co.uk'
    ]
  },

  // Low sensitivity: news, entertainment, sports, and travel.
  low: {
    score: 30,
    domains: [
      // News.
      'bbc.com',
      'bbc.co.uk',
      'cnn.com',
      'nytimes.com',
      'washingtonpost.com',
      'theguardian.com',
      'reuters.com',
      'apnews.com',
      'npr.org',
      'foxnews.com',
      'nbcnews.com',
      'abcnews.go.com',
      'cbsnews.com',
      'usatoday.com',
      'huffpost.com',
      'buzzfeed.com',
      'vice.com',
      'vox.com',
      'politico.com',

      // Entertainment.
      'netflix.com',
      'hulu.com',
      'disneyplus.com',
      'hbomax.com',
      'primevideo.com',
      'youtube.com',
      'vimeo.com',
      'dailymotion.com',
      'spotify.com',
      'apple.com/music',
      'soundcloud.com',
      'pandora.com',
      'imdb.com',
      'rottentomatoes.com',

      // Sports.
      'espn.com',
      'sports.yahoo.com',
      'bleacherreport.com',
      'cbssports.com',
      'nba.com',
      'nfl.com',
      'mlb.com',
      'nhl.com',
      'fifa.com',
      'skysports.com',

      // Travel.
      'booking.com',
      'expedia.com',
      'tripadvisor.com',
      'airbnb.com',
      'hotels.com',
      'kayak.com',
      'skyscanner.com',
      'trip.com',
      'agoda.com',

      // Games.
      'steampowered.com',
      'epicgames.com',
      'ea.com',
      'ubisoft.com',
      'playstation.com',
      'xbox.com',
      'nintendo.com',
      'ign.com',
      'gamespot.com',
      'kotaku.com'
    ]
  },

  // Minimal sensitivity: tools and reference sites.
  minimal: {
    score: 15,
    domains: [
      // Search engines.
      'google.com',
      'bing.com',
      'duckduckgo.com',
      'yahoo.com',
      'baidu.com',

      // Utilities.
      'translate.google.com',
      'wolframalpha.com',
      'calculator.net',
      'timeanddate.com',
      'speedtest.net',

      // Reference.
      'wikipedia.org',
      'wikihow.com',
      'britannica.com',
      'dictionary.com',
      'thesaurus.com',
      'merriam-webster.com',

      // Weather.
      'weather.com',
      'accuweather.com',
      'wunderground.com',

      // Maps.
      'maps.google.com',
      'waze.com',

      // Developer tools.
      'github.com',
      'gitlab.com',
      'stackoverflow.com',
      'npmjs.com',
      'developer.mozilla.org'
    ]
  }
};

// URL path keywords. Checked after exact domain matches.
const URL_PATH_KEYWORDS = {
  critical: {
    score: 90,
    keywords: [
      '/health',
      '/medical',
      '/patient',
      '/doctor',
      '/diagnosis',
      '/symptoms',
      '/treatment',
      '/prescription',
      '/pharmacy',
      '/mental-health',
      '/therapy',
      '/counseling',
      '/addiction',
      '/disease',
      '/cancer',
      '/diabetes',
      '/pregnancy',
      '/fertility'
    ]
  },

  high: {
    score: 75,
    keywords: [
      '/bank',
      '/account',
      '/finance',
      '/invest',
      '/trading',
      '/wallet',
      '/payment',
      '/checkout',
      '/billing',
      '/credit',
      '/loan',
      '/mortgage',
      '/insurance',
      '/tax',
      '/legal',
      '/dating',
      '/adult',
      '/18+',
      '/nsfw'
    ]
  },

  medium: {
    score: 50,
    keywords: [
      '/cart',
      '/shop',
      '/buy',
      '/order',
      '/profile',
      '/settings',
      '/account',
      '/dashboard',
      '/messages',
      '/inbox',
      '/jobs',
      '/career',
      '/resume',
      '/apply',
      '/course',
      '/learn',
      '/class'
    ]
  },

  low: {
    score: 25,
    keywords: [
      '/news',
      '/article',
      '/blog',
      '/post',
      '/video',
      '/watch',
      '/play',
      '/game',
      '/sport',
      '/entertainment',
      '/travel',
      '/recipe',
      '/review'
    ]
  }
};

// Domain keywords. Used only when no stronger rule matches.
const DOMAIN_KEYWORDS = {
  critical: {
    score: 85,
    keywords: [
      'health',
      'medical',
      'med',
      'clinic',
      'hospital',
      'doctor',
      'pharmacy',
      'rx',
      'drug',
      'therapy',
      'mental',
      'psych',
      'care',
      'patient',
      'wellness'
    ]
  },

  high: {
    score: 70,
    keywords: [
      'bank',
      'finance',
      'credit',
      'loan',
      'invest',
      'trade',
      'pay',
      'money',
      'tax',
      'insurance',
      'legal',
      'law',
      'attorney',
      'dating',
      'adult',
      'xxx',
      'porn',
      'sex'
    ]
  },

  medium: {
    score: 45,
    keywords: [
      'shop',
      'store',
      'buy',
      'market',
      'mall',
      'deal',
      'social',
      'friend',
      'chat',
      'job',
      'career',
      'work',
      'hire',
      'recruit',
      'edu',
      'learn',
      'school',
      'university',
      'college',
      'course'
    ]
  },

  low: {
    score: 25,
    keywords: [
      'news',
      'media',
      'press',
      'blog',
      'magazine',
      'journal',
      'video',
      'music',
      'game',
      'play',
      'sport',
      'travel',
      'tour',
      'hotel',
      'book',
      'food',
      'recipe'
    ]
  }
};

/**
 * Calculates a sensitivity score for a URL and domain.
 * @param {string} url
 * @param {string} domain
 * @returns {object}
 */
function calculateSensitivity(url, domain) {
  if (!url || !domain) {
    return {
      score: SENSITIVITY_LEVELS.DEFAULT.min,
      level: 'DEFAULT',
      reason: 'No URL or domain provided',
      category: 'unknown'
    };
  }

  const normalizedDomain = domain.toLowerCase().trim();
  const normalizedUrl = url.toLowerCase();

  const domainMatch = checkKnownDomains(normalizedDomain);
  if (domainMatch) {
    return domainMatch;
  }

  const pathMatch = checkUrlPathKeywords(normalizedUrl);
  if (pathMatch) {
    return pathMatch;
  }

  const keywordMatch = checkDomainKeywords(normalizedDomain);
  if (keywordMatch) {
    return keywordMatch;
  }

  return {
    score: SENSITIVITY_LEVELS.DEFAULT.min,
    level: 'DEFAULT',
    reason: 'No matching rules',
    category: 'general'
  };
}

// Exact domain and subdomain matches.
function checkKnownDomains(domain) {
  for (const [level, data] of Object.entries(KNOWN_DOMAINS)) {
    for (const knownDomain of data.domains) {
      if (domain === knownDomain || domain.endsWith('.' + knownDomain)) {
        return {
          score: data.score,
          level: level.toUpperCase(),
          reason: `Known ${level} sensitivity domain: ${knownDomain}`,
          category: getCategoryFromLevel(level)
        };
      }
    }
  }
  return null;
}

// URL path keyword matches.
function checkUrlPathKeywords(url) {
  try {
    const urlObj = new URL(url);
    const path = urlObj.pathname.toLowerCase();

    for (const [level, data] of Object.entries(URL_PATH_KEYWORDS)) {
      for (const keyword of data.keywords) {
        if (path.includes(keyword)) {
          return {
            score: data.score,
            level: level.toUpperCase(),
            reason: `URL path contains ${level} sensitivity keyword: ${keyword}`,
            category: getCategoryFromLevel(level)
          };
        }
      }
    }
  } catch (e) {
    // Invalid URL, skip path check.
  }
  return null;
}

// Domain keyword matches, with common suffixes removed first.
function checkDomainKeywords(domain) {
  const domainWithoutTLD = domain.replace(/\.(com|org|net|co\.uk|io|gov|edu)$/i, '');

  for (const [level, data] of Object.entries(DOMAIN_KEYWORDS)) {
    for (const keyword of data.keywords) {
      if (domainWithoutTLD.includes(keyword)) {
        return {
          score: data.score,
          level: level.toUpperCase(),
          reason: `Domain contains ${level} sensitivity keyword: ${keyword}`,
          category: getCategoryFromLevel(level)
        };
      }
    }
  }
  return null;
}

// Map scoring levels to broader display categories.
function getCategoryFromLevel(level) {
  const categories = {
    critical: 'health/medical',
    high: 'finance/legal/adult',
    medium: 'shopping/social/work',
    low: 'news/entertainment',
    minimal: 'tools/reference'
  };
  return categories[level] || 'general';
}

// Resolve a score to its configured sensitivity level.
function getSensitivityLevel(score) {
  if (score >= 90) return SENSITIVITY_LEVELS.CRITICAL;
  if (score >= 70) return SENSITIVITY_LEVELS.HIGH;
  if (score >= 40) return SENSITIVITY_LEVELS.MEDIUM;
  if (score >= 20) return SENSITIVITY_LEVELS.LOW;
  if (score >= 10) return SENSITIVITY_LEVELS.MINIMAL;
  return SENSITIVITY_LEVELS.DEFAULT;
}

// Counts exposed for diagnostics.
function getSensitivityStats() {
  let totalDomains = 0;
  const byLevel = {};

  for (const [level, data] of Object.entries(KNOWN_DOMAINS)) {
    byLevel[level] = data.domains.length;
    totalDomains += data.domains.length;
  }

  return {
    totalKnownDomains: totalDomains,
    byLevel: byLevel,
    urlKeywordCategories: Object.keys(URL_PATH_KEYWORDS).length,
    domainKeywordCategories: Object.keys(DOMAIN_KEYWORDS).length
  };
}

export {
  SENSITIVITY_LEVELS,
  KNOWN_DOMAINS,
  URL_PATH_KEYWORDS,
  DOMAIN_KEYWORDS,
  calculateSensitivity,
  getSensitivityLevel,
  getSensitivityStats
};
