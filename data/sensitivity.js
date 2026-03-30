/**
 * Data Transparency Monitor - Website Sensitivity Classification
 * 
 * 基于 Contextual Integrity 理论 (Nissenbaum, 2004)
 * 不同类型网站的数据敏感度不同，相同追踪技术造成的隐私风险也不同
 * 
 * 敏感度等级:
 * - CRITICAL (90-100): 健康、医疗、心理健康
 * - HIGH (70-89): 金融、政府、法律、成人、约会
 * - MEDIUM (40-69): 购物、社交、求职、教育
 * - LOW (20-39): 新闻、娱乐、体育、旅游
 * - MINIMAL (10-19): 工具、参考、搜索引擎
 */

// ============================================
// 敏感度等级定义
// ============================================

const SENSITIVITY_LEVELS = {
  CRITICAL: { min: 90, max: 100, label: 'Critical', description: 'Highly sensitive personal data' },
  HIGH: { min: 70, max: 89, label: 'High', description: 'Sensitive personal/financial data' },
  MEDIUM: { min: 40, max: 69, label: 'Medium', description: 'Personal preferences and behaviors' },
  LOW: { min: 20, max: 39, label: 'Low', description: 'General interests and activities' },
  MINIMAL: { min: 10, max: 19, label: 'Minimal', description: 'Functional usage data' },
  DEFAULT: { min: 30, max: 30, label: 'Unknown', description: 'Unclassified website' }
};

// ============================================
// Layer 1: 已知域名精确匹配
// 最高优先级，精确匹配域名
// ============================================

const KNOWN_DOMAINS = {
  // ========== CRITICAL (90-100): 健康、医疗 ==========
  critical: {
    score: 95,
    domains: [
      // 健康信息网站
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
      
      // 国家健康服务
      'nhs.uk',
      'nih.gov',
      'cdc.gov',
      'who.int',
      
      // 心理健康
      'psychologytoday.com',
      'betterhelp.com',
      'talkspace.com',
      'calm.com',
      'headspace.com',
      '7cups.com',
      'mentalhealth.gov',
      
      // 医院和诊所
      'zocdoc.com',
      'healthgrades.com',
      'vitals.com',
      
      // 药房
      'cvs.com',
      'walgreens.com',
      'riteaid.com',
      'pharmacy.amazon.com',
      
      // 医疗保险
      'healthcare.gov',
      'medicare.gov',
      
      // 健身追踪 (涉及健康数据)
      'myfitnesspal.com',
      'fitbit.com',
      'strava.com'
    ]
  },
  
  // ========== HIGH (70-89): 金融、政府、法律、成人 ==========
  high: {
    score: 80,
    domains: [
      // 银行
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
      
      // 投资和交易
      'fidelity.com',
      'schwab.com',
      'vanguard.com',
      'etrade.com',
      'tdameritrade.com',
      'robinhood.com',
      'coinbase.com',
      'binance.com',
      'kraken.com',
      
      // 支付服务
      'paypal.com',
      'venmo.com',
      'squareup.com',
      'stripe.com',
      
      // 信用和贷款
      'creditkarma.com',
      'experian.com',
      'equifax.com',
      'transunion.com',
      'annualcreditreport.com',
      'lendingtree.com',
      'sofi.com',
      'lendingclub.com',
      
      // 税务
      'irs.gov',
      'turbotax.com',
      'hrblock.com',
      'taxact.com',
      
      // 政府服务
      'gov.uk',
      'usa.gov',
      'ssa.gov',
      'dmv.org',
      
      // 法律服务
      'legalzoom.com',
      'rocketlawyer.com',
      'avvo.com',
      'findlaw.com',
      
      // 约会应用
      'tinder.com',
      'bumble.com',
      'hinge.co',
      'match.com',
      'okcupid.com',
      'pof.com',
      'eharmony.com',
      'grindr.com',
      
      // 保险
      'geico.com',
      'progressive.com',
      'statefarm.com',
      'allstate.com',
      'libertymutual.com'
    ]
  },
  
  // ========== MEDIUM (40-69): 购物、社交、求职、教育 ==========
  medium: {
    score: 55,
    domains: [
      // 电商
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
      
      // 社交媒体
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
      
      // 求职
      'indeed.com',
      'glassdoor.com',
      'monster.com',
      'ziprecruiter.com',
      'careerbuilder.com',
      'dice.com',
      'hired.com',
      
      // 教育
      'coursera.org',
      'udemy.com',
      'edx.org',
      'khanacademy.org',
      'skillshare.com',
      'udacity.com',
      'pluralsight.com',
      'lynda.com',
      'duolingo.com',
      
      // 房产
      'zillow.com',
      'realtor.com',
      'redfin.com',
      'trulia.com',
      'rightmove.co.uk',
      'zoopla.co.uk',
      
      // 外卖和食品
      'doordash.com',
      'ubereats.com',
      'grubhub.com',
      'postmates.com',
      'instacart.com',
      'deliveroo.co.uk',
      'justeat.co.uk'
    ]
  },
  
  // ========== LOW (20-39): 新闻、娱乐、体育 ==========
  low: {
    score: 30,
    domains: [
      // 新闻
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
      
      // 娱乐
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
      
      // 体育
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
      
      // 旅游
      'booking.com',
      'expedia.com',
      'tripadvisor.com',
      'airbnb.com',
      'hotels.com',
      'kayak.com',
      'skyscanner.com',
      'trip.com',
      'agoda.com',
      
      // 游戏
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
  
  // ========== MINIMAL (10-19): 工具、参考 ==========
  minimal: {
    score: 15,
    domains: [
      // 搜索引擎
      'google.com',
      'bing.com',
      'duckduckgo.com',
      'yahoo.com',
      'baidu.com',
      
      // 工具
      'translate.google.com',
      'wolframalpha.com',
      'calculator.net',
      'timeanddate.com',
      'speedtest.net',
      
      // 参考
      'wikipedia.org',
      'wikihow.com',
      'britannica.com',
      'dictionary.com',
      'thesaurus.com',
      'merriam-webster.com',
      
      // 天气
      'weather.com',
      'accuweather.com',
      'wunderground.com',
      
      // 地图
      'maps.google.com',
      'waze.com',
      
      // 开发者工具
      'github.com',
      'gitlab.com',
      'stackoverflow.com',
      'npmjs.com',
      'developer.mozilla.org'
    ]
  }
};

// ============================================
// Layer 2: URL 路径关键词
// 中等优先级，匹配 URL 中的路径
// ============================================

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

// ============================================
// Layer 3: 域名关键词
// 最低优先级，匹配域名中的关键词
// ============================================

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

// ============================================
// 核心检测函数
// ============================================

/**
 * 计算网站的数据敏感度分数
 * @param {string} url - 完整的URL
 * @param {string} domain - 域名
 * @returns {object} - { score, level, reason, category }
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
  
  // Layer 1: 精确域名匹配
  const domainMatch = checkKnownDomains(normalizedDomain);
  if (domainMatch) {
    return domainMatch;
  }
  
  // Layer 2: URL路径关键词匹配
  const pathMatch = checkUrlPathKeywords(normalizedUrl);
  if (pathMatch) {
    return pathMatch;
  }
  
  // Layer 3: 域名关键词匹配
  const keywordMatch = checkDomainKeywords(normalizedDomain);
  if (keywordMatch) {
    return keywordMatch;
  }
  
  // 默认值
  return {
    score: SENSITIVITY_LEVELS.DEFAULT.min,
    level: 'DEFAULT',
    reason: 'No matching rules',
    category: 'general'
  };
}

/**
 * Layer 1: 检查已知域名
 */
function checkKnownDomains(domain) {
  for (const [level, data] of Object.entries(KNOWN_DOMAINS)) {
    for (const knownDomain of data.domains) {
      // 精确匹配或子域名匹配
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

/**
 * Layer 2: 检查URL路径关键词
 */
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
    // Invalid URL, skip path check
  }
  return null;
}

/**
 * Layer 3: 检查域名关键词
 */
function checkDomainKeywords(domain) {
  // 移除常见后缀以便更好匹配
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

/**
 * 从敏感度等级获取分类名称
 */
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

/**
 * 获取敏感度等级信息
 */
function getSensitivityLevel(score) {
  if (score >= 90) return SENSITIVITY_LEVELS.CRITICAL;
  if (score >= 70) return SENSITIVITY_LEVELS.HIGH;
  if (score >= 40) return SENSITIVITY_LEVELS.MEDIUM;
  if (score >= 20) return SENSITIVITY_LEVELS.LOW;
  if (score >= 10) return SENSITIVITY_LEVELS.MINIMAL;
  return SENSITIVITY_LEVELS.DEFAULT;
}

/**
 * 获取敏感度统计信息
 */
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

// ============================================
// 导出
// ============================================

export {
  SENSITIVITY_LEVELS,
  KNOWN_DOMAINS,
  URL_PATH_KEYWORDS,
  DOMAIN_KEYWORDS,
  calculateSensitivity,
  getSensitivityLevel,
  getSensitivityStats
};
