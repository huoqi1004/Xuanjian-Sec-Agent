/** 情报查询工具组：get_threat_intel / query_shodan / query_abuseipdb / query_virustotal / analyze_virus_hash */
const { registerTool } = require('./registry');
const { getDb } = require('../../db/database');

function registerIntelTools() {
  registerTool({
    name: 'get_threat_intel',
    desc: '多源威胁情报聚合查询',
    params: ['iocType', 'value'],
    risk: 'low',
    handler: async (params) => {
      const threatIntelligence = require('../../services/threatIntelligence');
      const result = await threatIntelligence.aggregateQuery(params.iocType, params.value);
      return {
        data: {
          riskLevel: result.riskLevel,
          riskScore: result.riskScore,
          sources: result.sources.map((s) => ({ source: s.source, verdict: s.verdict })),
          summary: result.summary
        },
        message: `多源威胁情报查询完成，风险等级: ${result.riskLevel}`
      };
    }
  });

  registerTool({
    name: 'query_shodan',
    desc: 'Shodan 查询 IP 开放端口',
    params: ['ip'],
    risk: 'low',
    handler: async (params) => {
      const threatIntelligence = require('../../services/threatIntelligence');
      const result = await threatIntelligence.queryShodan(params.ip);
      if (result.data) {
        return {
          data: {
            ip: result.data.ip, country: result.data.country, org: result.data.org,
            openPorts: result.data.openPorts, vulns: result.data.vulns, services: result.data.services
          },
          message: `Shodan查询完成，发现 ${result.data.openPorts.length} 个开放端口`
        };
      }
      return { data: null, message: 'Shodan未收录该IP信息' };
    }
  });

  registerTool({
    name: 'query_abuseipdb',
    desc: 'AbuseIPDB 滥用查询',
    params: ['ip'],
    risk: 'low',
    handler: async (params) => {
      const threatIntelligence = require('../../services/threatIntelligence');
      const result = await threatIntelligence.queryAbuseIPDB(params.ip);
      if (result.data) {
        return {
          data: {
            confidence: result.data.confidence, totalReports: result.data.totalReports,
            country: result.data.country, isp: result.data.isp, recentReports: result.data.reports
          },
          message: `AbuseIPDB查询完成，滥用置信度: ${result.data.confidence}%`
        };
      }
      return { data: null, message: 'AbuseIPDB未找到该IP报告' };
    }
  });

  registerTool({
    name: 'query_virustotal',
    desc: 'VirusTotal IOC 查询',
    params: ['iocType', 'value'],
    risk: 'low',
    handler: async (params) => {
      const threatIntelligence = require('../../services/threatIntelligence');
      const result = await threatIntelligence.queryVirusTotal(params.iocType, params.value);
      if (result.data) {
        return {
          data: {
            malicious: result.data.malicious, suspicious: result.data.suspicious,
            harmless: result.data.harmless, communityScore: result.data.communityScore, verdict: result.verdict
          },
          message: `VirusTotal查询完成，${result.data.malicious} 个引擎标记为恶意`
        };
      }
      return { data: null, message: 'VirusTotal未找到该IOC信息' };
    }
  });

  registerTool({
    name: 'analyze_virus_hash',
    desc: '文件哈希多源分析',
    params: ['hash'],
    risk: 'low',
    handler: async (params) => {
      const threatIntelligence = require('../../services/threatIntelligence');
      const [vt, tb] = await Promise.allSettled([
        threatIntelligence.queryVirusTotal('hash', params.hash),
        threatIntelligence.queryThreatBook('hash', params.hash)
      ]);
      const sources = [];
      if (vt.status === 'fulfilled') sources.push(vt.value);
      if (tb.status === 'fulfilled') sources.push(tb.value);
      return { data: { hash: params.hash, sources }, message: `文件哈希 ${params.hash} 分析完成` };
    }
  });
}

module.exports = { registerIntelTools };
