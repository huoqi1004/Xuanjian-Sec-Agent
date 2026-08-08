const axios = require('axios');
const logger = require('../utils/logger');

const THREATBOOK_API_KEY = process.env.THREATBOOK_API_KEY;
const SHODAN_API_KEY = process.env.SHODAN_API_KEY;
const GOOGLE_SAFE_BROWSING_API_KEY = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
const ABUSEIPDB_API_KEY = process.env.ABUSEIPDB_API_KEY;
const IPINFO_TOKEN = process.env.IPINFO_TOKEN;
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const HACKERTARGET_API_KEY = process.env.HACKERTARGET_API_KEY;

/**
 * Shodan InternetDB - 完全免费，无需Key (https://internetdb.shodan.io)
 */
async function queryShodanInternetDB(ip) {
  try {
    const resp = await axios.get(`https://internetdb.shodan.io/${ip}`, { timeout: 8000 });
    const data = resp.data;
    if (data && data.ip) {
      return {
        source: 'Shodan(InternetDB)',
        available: true,
        data: {
          ip: data.ip,
          hostnames: data.hostnames || [],
          openPorts: data.ports || [],
          cpes: data.cpes || [],
          vulns: data.vulns || [],
          tags: data.tags || []
        },
        verdict: (data.vulns && data.vulns.length > 0) ? 'has_vulns' : 'clean',
        raw: data
      };
    }
    return { source: 'Shodan(InternetDB)', available: true, data: null, verdict: 'not_found' };
  } catch (e) {
    return { source: 'Shodan(InternetDB)', available: true, error: e.message };
  }
}

/**
 * Shodan 完整API - 需要API Key
 */
async function queryShodan(ip) {
  if (!SHODAN_API_KEY || SHODAN_API_KEY === 'your_shodan_api_key_here') {
    return await queryShodanInternetDB(ip);
  }
  try {
    const url = `https://api.shodan.io/shodan/host/${ip}`;
    const resp = await axios.get(url, { params: { key: SHODAN_API_KEY }, timeout: 10000 });
    const data = resp.data;
    return {
      source: 'Shodan',
      available: true,
      data: {
        ip: data.ip_str,
        country: data.country_name,
        city: data.city,
        org: data.org,
        asn: data.asn,
        openPorts: data.ports,
        vulns: data.vulns || [],
        services: (data.data || []).map(d => ({ port: d.port, service: d.product || 'unknown', version: d.version || '' }))
      },
      raw: data
    };
  } catch (e) {
    if (e.response?.status === 404) {
      return await queryShodanInternetDB(ip);
    }
    return { source: 'Shodan', available: true, error: e.message };
  }
}

/**
 * HackerTarget - 完全免费，无需Key
 */
async function queryHackerTargetFree(tool, target) {
  try {
    const toolMap = {
      'reverse_dns': 'reversedns',
      'whois': 'whois',
      'port_scan': 'nmap',
      'mtr': 'mtr',
      'dns_lookup': 'dnslookup',
      'host_search': 'hostsearch',
      'geoip': 'geoip'
    };
    const toolName = toolMap[tool] || tool;
    const resp = await axios.get(`https://api.hackertarget.com/${toolName}/`, {
      params: { q: target },
      timeout: 10000
    });
    return {
      source: 'HackerTarget',
      available: true,
      data: { tool, target, result: resp.data },
      raw: resp.data
    };
  } catch (e) {
    return { source: 'HackerTarget', available: true, error: e.message };
  }
}

/**
 * 公开IP地理位置服务 (免费，无需Key)
 */
async function queryPublicGeoIP(ip) {
  try {
    const resp = await axios.get(`https://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query`, { timeout: 8000 });
    if (resp.data && resp.data.status === 'success') {
      const d = resp.data;
      return {
        source: 'IP-API',
        available: true,
        data: {
          ip: d.query,
          country: d.country,
          countryCode: d.countryCode,
          region: d.regionName,
          city: d.city,
          zip: d.zip,
          lat: d.lat,
          lon: d.lon,
          timezone: d.timezone,
          isp: d.isp,
          org: d.org,
          asn: d.as
        },
        raw: d
      };
    }
    return { source: 'IP-API', available: true, data: null, verdict: 'not_found' };
  } catch (e) {
    return { source: 'IP-API', available: true, error: e.message };
  }
}

/**
 * 微步TI (ThreatBook)
 */
async function queryThreatBook(iocType, value) {
  if (!THREATBOOK_API_KEY || THREATBOOK_API_KEY === 'your_threatbook_api_key_here') {
    return { source: 'ThreatBook', available: false, error: 'API Key未配置' };
  }
  try {
    const url = `https://api.threatbook.cn/v3/indicators`;
    const params = { resource: value, apikey: THREATBOOK_API_KEY };
    const resp = await axios.get(url, { params, timeout: 10000 });
    if (resp.data?.code === 0 && resp.data?.data) {
      return {
        source: 'ThreatBook',
        available: true,
        data: resp.data.data,
        verdict: getThreatBookVerdict(resp.data.data),
        raw: resp.data
      };
    }
    return { source: 'ThreatBook', available: true, data: null, verdict: 'unknown', raw: resp.data };
  } catch (e) {
    logger.warn(`微步TI查询失败: ${e.message}`);
    return { source: 'ThreatBook', available: true, error: e.message, verdict: 'unknown' };
  }
}

/**
 * Google Safe Browsing
 */
async function queryGoogleSafeBrowsing(url) {
  if (!GOOGLE_SAFE_BROWSING_API_KEY || GOOGLE_SAFE_BROWSING_API_KEY === 'your_google_safe_browsing_api_key_here') {
    return { source: 'GoogleSafeBrowsing', available: false, error: 'API Key未配置' };
  }
  try {
    const resp = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_SAFE_BROWSING_API_KEY}`,
      {
        client: { clientId: 'xuanjian-security-agent', clientVersion: '1.0.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }]
        }
      },
      { timeout: 10000 }
    );
    if (resp.data?.matches?.length > 0) {
      return {
        source: 'GoogleSafeBrowsing',
        available: true,
        data: { matches: resp.data.matches },
        verdict: 'malicious',
        raw: resp.data
      };
    }
    return { source: 'GoogleSafeBrowsing', available: true, data: null, verdict: 'clean', raw: resp.data };
  } catch (e) {
    logger.warn(`Google Safe Browsing查询失败: ${e.message}`);
    return { source: 'GoogleSafeBrowsing', available: true, error: e.message, verdict: 'unknown' };
  }
}

/**
 * AbuseIPDB
 */
async function queryAbuseIPDB(ip) {
  if (!ABUSEIPDB_API_KEY || ABUSEIPDB_API_KEY === 'your_abuseipdb_api_key_here') {
    return { source: 'AbuseIPDB', available: false, error: 'API Key未配置' };
  }
  try {
    const resp = await axios.get('https://api.abuseipdb.com/api/v2/check', {
      params: { ipAddress: ip, maxAgeInDays: 90, verbose: true },
      headers: { 'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json' },
      timeout: 10000
    });
    const data = resp.data.data;
    return {
      source: 'AbuseIPDB',
      available: true,
      data: {
        ip: data.ipAddress,
        confidence: data.abuseConfidenceScore,
        totalReports: data.totalReports,
        reports: (data.reports || []).slice(0, 5).map(r => ({
          reportedAt: r.reportedAt,
          comment: r.comment,
          categories: r.categories
        })),
        country: data.countryCode,
        isp: data.isp,
        usageType: data.usageType
      },
      verdict: getAbuseVerdict(data.abuseConfidenceScore),
      raw: data
    };
  } catch (e) {
    logger.warn(`AbuseIPDB查询失败: ${e.message}`);
    return { source: 'AbuseIPDB', available: true, error: e.message, verdict: 'unknown' };
  }
}

/**
 * IPinfo
 */
async function queryIPInfo(ip) {
  if (!IPINFO_TOKEN || IPINFO_TOKEN === 'your_ipinfo_token_here') {
    return await queryPublicGeoIP(ip);
  }
  try {
    const resp = await axios.get(`https://ipinfo.io/${ip}/json?token=${IPINFO_TOKEN}`, { timeout: 10000 });
    return {
      source: 'IPinfo',
      available: true,
      data: {
        ip: resp.data.ip,
        city: resp.data.city,
        region: resp.data.region,
        country: resp.data.country,
        org: resp.data.org,
        asn: resp.data.asn,
        timezone: resp.data.timezone,
        bogon: resp.data.bogon
      },
      raw: resp.data
    };
  } catch (e) {
    return await queryPublicGeoIP(ip);
  }
}

/**
 * VirusTotal
 */
async function queryVirusTotal(iocType, value) {
  if (!VIRUSTOTAL_API_KEY || VIRUSTOTAL_API_KEY === 'your_virustotal_api_key_here') {
    return { source: 'VirusTotal', available: false, error: 'API Key未配置' };
  }
  try {
    let endpoint = '';
    if (iocType === 'ip') {
      endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${value}`;
    } else if (iocType === 'domain') {
      endpoint = `https://www.virustotal.com/api/v3/domains/${value}`;
    } else if (iocType === 'hash') {
      endpoint = `https://www.virustotal.com/api/v3/files/${value}`;
    } else {
      return { source: 'VirusTotal', available: true, error: '不支持的IOC类型' };
    }
    const resp = await axios.get(endpoint, {
      headers: { 'x-apikey': VIRUSTOTAL_API_KEY },
      timeout: 10000
    });
    const data = resp.data.data;
    return {
      source: 'VirusTotal',
      available: true,
      data: {
        malicious: data.attributes?.last_analysis_stats?.malicious || 0,
        suspicious: data.attributes?.last_analysis_stats?.suspicious || 0,
        harmless: data.attributes?.last_analysis_stats?.harmless || 0,
        undetected: data.attributes?.last_analysis_stats?.undetected || 0,
        communityScore: data.attributes?.reputation || 0,
        tags: data.attributes?.tags || [],
        categories: data.attributes?.categories || {}
      },
      verdict: getVTVerdict(data.attributes?.last_analysis_stats),
      raw: data
    };
  } catch (e) {
    if (e.response?.status === 404) {
      return { source: 'VirusTotal', available: true, data: null, verdict: 'not_found' };
    }
    return { source: 'VirusTotal', available: true, error: e.message, verdict: 'unknown' };
  }
}

/**
 * HackerTarget (带Key版本)
 */
async function queryHackerTarget(tool, target) {
  if (!HACKERTARGET_API_KEY || HACKERTARGET_API_KEY === 'your_hackertarget_api_key_here') {
    return await queryHackerTargetFree(tool, target);
  }
  return await queryHackerTargetFree(tool, target);
}

// ========== 辅助函数 ==========

function getThreatBookVerdict(data) {
  if (!data) return 'unknown';
  const judgment = data?.judgments;
  if (!judgment) return 'unknown';
  if (judgment.includes('malware')) return 'malicious';
  if (judgment.includes('suspicious')) return 'suspicious';
  if (judgment.includes('cnc')) return 'c2';
  return 'clean';
}

function getAbuseVerdict(score) {
  if (score >= 80) return 'high_risk';
  if (score >= 40) return 'medium_risk';
  if (score >= 1) return 'low_risk';
  return 'clean';
}

function getVTVerdict(stats) {
  if (!stats) return 'unknown';
  const { malicious = 0, suspicious = 0, harmless = 0 } = stats;
  const total = malicious + suspicious + harmless;
  if (total === 0) return 'not_found';
  const ratio = (malicious + suspicious * 0.5) / total;
  if (ratio >= 0.3) return 'malicious';
  if (ratio >= 0.1) return 'suspicious';
  return 'clean';
}

/**
 * 多源聚合查询
 */
async function aggregateQuery(iocType, value) {
  const results = [];
  const startTime = Date.now();

  switch (iocType) {
    case 'ip': {
      const [shodan, geoip, htGeo, abuse, vt] = await Promise.allSettled([
        queryShodan(value),
        queryIPInfo(value),
        queryHackerTargetFree('geoip', value),
        queryAbuseIPDB(value),
        queryVirusTotal('ip', value)
      ]);
      if (shodan.status === 'fulfilled') results.push(shodan.value);
      if (geoip.status === 'fulfilled') results.push(geoip.value);
      if (htGeo.status === 'fulfilled') results.push(htGeo.value);
      if (abuse.status === 'fulfilled') results.push(abuse.value);
      if (vt.status === 'fulfilled') results.push(vt.value);
      break;
    }
    case 'domain': {
      const [tb, vt, gsb] = await Promise.allSettled([
        queryThreatBook('domain', value),
        queryVirusTotal('domain', value),
        queryGoogleSafeBrowsing(value)
      ]);
      if (tb.status === 'fulfilled') results.push(tb.value);
      if (vt.status === 'fulfilled') results.push(vt.value);
      if (gsb.status === 'fulfilled') results.push(gsb.value);
      break;
    }
    case 'hash': {
      const [tb, vt] = await Promise.allSettled([
        queryThreatBook('hash', value),
        queryVirusTotal('hash', value)
      ]);
      if (tb.status === 'fulfilled') results.push(tb.value);
      if (vt.status === 'fulfilled') results.push(vt.value);
      break;
    }
    case 'url': {
      const [gsb, tb] = await Promise.allSettled([
        queryGoogleSafeBrowsing(value),
        queryThreatBook('domain', value)
      ]);
      if (gsb.status === 'fulfilled') results.push(gsb.value);
      if (tb.status === 'fulfilled') results.push(tb.value);
      break;
    }
    default:
      break;
  }

  const riskAssessment = assessRisk(results);

  return {
    iocType,
    value,
    sources: results,
    riskLevel: riskAssessment.level,
    riskScore: riskAssessment.score,
    summary: riskAssessment.summary,
    queryTime: Date.now() - startTime
  };
}

/**
 * 综合风险评估
 */
function assessRisk(results) {
  let score = 0;
  const details = [];

  for (const r of results) {
    if (!r.available || r.error) continue;
    if (r.verdict === 'malicious' || r.verdict === 'high_risk') {
      score += 40;
      details.push(`${r.source}: 高风险`);
    } else if (r.verdict === 'suspicious' || r.verdict === 'medium_risk') {
      score += 20;
      details.push(`${r.source}: 可疑`);
    } else if (r.verdict === 'low_risk') {
      score += 5;
      details.push(`${r.source}: 低风险`);
    } else if (r.verdict === 'has_vulns') {
      score += 10;
      details.push(`${r.source}: 存在已知漏洞`);
    }
  }

  score = Math.min(score, 100);
  let level = 'safe';
  if (score >= 70) level = 'critical';
  else if (score >= 40) level = 'high';
  else if (score >= 15) level = 'medium';
  else if (score > 0) level = 'low';

  return {
    score,
    level,
    summary: details.length > 0 ? details.join('；') : '未发现威胁'
  };
}

/**
 * 获取所有可用数据源状态
 */
function getSourcesStatus() {
  return {
    threatBook: { name: '微步TI', enabled: !!(THREATBOOK_API_KEY && THREATBOOK_API_KEY !== 'your_threatbook_api_key_here'), free: false },
    shodan: { name: 'Shodan(InternetDB)', enabled: true, free: true, note: '免费版，无需Key' },
    googleSafeBrowsing: { name: 'Google Safe Browsing', enabled: !!(GOOGLE_SAFE_BROWSING_API_KEY && GOOGLE_SAFE_BROWSING_API_KEY !== 'your_google_safe_browsing_api_key_here'), free: false },
    abuseIPDB: { name: 'AbuseIPDB', enabled: !!(ABUSEIPDB_API_KEY && ABUSEIPDB_API_KEY !== 'your_abuseipdb_api_key_here'), free: false },
    ipinfo: { name: 'IP-API(公开)', enabled: true, free: true, note: '免费版，无需Key' },
    virusTotal: { name: 'VirusTotal', enabled: !!(VIRUSTOTAL_API_KEY && VIRUSTOTAL_API_KEY !== 'your_virustotal_api_key_here'), free: false },
    hackerTarget: { name: 'HackerTarget', enabled: true, free: true, note: '免费版，无需Key' }
  };
}

module.exports = {
  queryShodanInternetDB,
  queryShodan,
  queryHackerTargetFree,
  queryPublicGeoIP,
  queryThreatBook,
  queryGoogleSafeBrowsing,
  queryAbuseIPDB,
  queryIPInfo,
  queryVirusTotal,
  queryHackerTarget,
  aggregateQuery,
  assessRisk,
  getSourcesStatus
};
