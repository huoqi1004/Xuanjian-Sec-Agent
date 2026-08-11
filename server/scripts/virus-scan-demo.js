// 病毒查杀流程演示模块
// 使用方式:
//   const { VirusScanDemo } = require('./scripts/virus-scan-demo');
//   const demo = new VirusScanDemo({ seedHashes: [...] });
//   await demo.run();
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const { resetForTest, getDb } = require('../db/database');
const aiService = require('../services/aiService');
const multiEngineScanService = require('../services/multiEngineScanService');
const llmVirusScanService = require('../services/llmVirusScanService');

/**
 * 病毒查杀流程演示模块
 * 封装完整的 7 引擎扫描 → LLM 威胁分析 → LLM 处置建议流程
 */
class VirusScanDemo {
  /**
   * @param {object} options
   * @param {Array}  options.seedHashes      - 种子威胁记录，每项 {hash, type, threatName, severity, source}
   * @param {Array}  options.testCases       - 测试用例，每项 {name, content, expectedVerdict?}
   * @param {string} options.tmpDir          - 临时目录，默认 os.tmpdir()/xuanjian-demo
   * @param {function} options.setupMocks   - 自定义 mock 函数，接收 aiService 对象
   */
  constructor(options = {}) {
    this.seedHashes = options.seedHashes || [];
    this.testCases = options.testCases || [];
    this.tmpDir = options.tmpDir || path.join(os.tmpdir(), 'xuanjian-demo');
    this.setupMocks = options.setupMocks || null;
  }

  /** 初始化测试数据库并写入种子数据 */
  initDatabase() {
    resetForTest();
    const db = getDb();
    for (const h of this.seedHashes) {
      db.prepare(
        'INSERT OR REPLACE INTO virus_hashes (hash_value, hash_type, threat_name, severity, source) VALUES (?, ?, ?, ?, ?)'
      ).run(h.hash, h.type, h.threatName, h.severity, h.source);
    }
    return db;
  }

  /** 创建测试文件 */
  createTestFiles() {
    if (!fs.existsSync(this.tmpDir)) fs.mkdirSync(this.tmpDir, { recursive: true });
    return this.testCases.map(tc => {
      const content = typeof tc.content === 'string' ? tc.content : tc.content();
      const filePath = path.join(this.tmpDir, tc.name);
      fs.writeFileSync(filePath, content);
      return {
        path: filePath,
        originalname: tc.name,
        size: fs.statSync(filePath).size,
        mimetype: tc.mimetype || 'application/octet-stream'
      };
    });
  }

  /** 配置 AI 服务 mock */
  configureMocks() {
    if (this.setupMocks) this.setupMocks(aiService);
  }

  /** 运行多引擎扫描 */
  async scanFiles(files) {
    return Promise.all(files.map(f => multiEngineScanService.scanFile(f, 1)));
  }

  /** 运行 LLM 哈希分析 */
  async analyzeHashes(cases) {
    return Promise.all(cases.map(c => llmVirusScanService.analyzeHashWithLLM(c.hash, c.type, 1)));
  }

  /** 运行完整 LLM 查杀 */
  async fullScan(file) {
    return llmVirusScanService.runLLMVirusScan(file, 1);
  }

  /** 运行完整演示流程 */
  async run(options = {}) {
    const { verbose = true, printResults = true } = options;
    this.configureMocks();
    const db = this.initDatabase();
    if (verbose) {
      console.log(`[VirusScanDemo] Database initialized, ${this.seedHashes.length} seed records`);
    }

    const files = this.testCases.length > 0
      ? this.createTestFiles()
      : (options.files || []);

    let scanResults = [];
    if (files.length > 0) {
      scanResults = await this.scanFiles(files);
      if (verbose) {
        console.log(`[VirusScanDemo] Multi-engine scan completed: ${files.length} files`);
      }
    }

    let hashResults = [];
    const hashCases = options.hashCases || [];
    if (hashCases.length > 0) {
      hashResults = await this.analyzeHashes(hashCases);
      if (verbose) {
        console.log(`[VirusScanDemo] Hash analysis completed: ${hashCases.length} queries`);
      }
    }

    let fullResult = null;
    if (files.length > 0) {
      fullResult = await this.fullScan(files[0]);
      if (verbose) {
        console.log(`[VirusScanDemo] Full LLM scan completed in ${fullResult.totalTime}s`);
      }
    }

    if (printResults) {
      this.printResults({ files, scanResults, hashResults, fullResult });
    }

    return { db, files, scanResults, hashResults, fullResult };
  }

  /** 打印结果摘要 */
  printResults({ files, scanResults, hashResults, fullResult }) {
    console.log('\n' + '='.repeat(70));
    console.log('  Virus Scan Demo Results');
    console.log('='.repeat(70));

    if (scanResults.length > 0) {
      console.log('\n--- Multi-Engine Scan ---');
      for (let i = 0; i < scanResults.length; i++) {
        const r = scanResults[i];
        console.log(`  [${i + 1}] ${files[i].originalname}`);
        console.log(`      Verdict: ${r.decision.verdict.toUpperCase()} | Confidence: ${(r.decision.confidence * 100).toFixed(1)}%`);
        console.log(`      Engines: ${Object.values(r.engines).filter(e => e.verdict === 'malicious').length} malicious, ` +
          `${Object.values(r.engines).filter(e => e.verdict === 'suspicious').length} suspicious, ` +
          `${Object.values(r.engines).filter(e => e.verdict === 'clean').length} clean`);
      }
    }

    if (hashResults.length > 0) {
      console.log('\n--- LLM Hash Analysis ---');
      for (let i = 0; i < hashResults.length; i++) {
        const r = hashResults[i];
        console.log(`  [${i + 1}] ${r.hashes.md5 || r.hashes.sha256}`);
        console.log(`      Local DB: ${r.localMatch ? r.localMatch.threat_name : 'No match'}`);
        if (r.llmAnalysis) {
          const llm = r.llmAnalysis;
          console.log(`      LLM: ${llm.threat_classification} | ${llm.threat_level} | ${(llm.confidence * 100).toFixed(0)}%`);
        }
      }
    }

    if (fullResult) {
      console.log('\n--- Full LLM Scan ---');
      console.log(`      Verdict: ${fullResult.decision.verdict.toUpperCase()} | ${(fullResult.decision.confidence * 100).toFixed(1)}%`);
      if (fullResult.llmAnalysis) {
        const llm = fullResult.llmAnalysis;
        const src = llm.threat_classification !== 'unknown' ? 'LLM API' : 'Rule fallback';
        console.log(`      Source: ${src}`);
        console.log(`      Classification: ${llm.threat_classification} | ${llm.threat_family} | ${llm.threat_level} | ${(llm.confidence * 100).toFixed(0)}%`);
      }
      if (fullResult.remediationPlan) {
        const plan = fullResult.remediationPlan;
        console.log(`      Remediation: priority=${plan.priority} | escalation=${plan.escalation_needed}`);
      }
      console.log(`      Total Time: ${fullResult.totalTime}s`);
    }

    console.log('\n' + '='.repeat(70));
  }
}

/**
 * 快捷函数：使用默认配置运行完整演示
 */
async function runDemo(options = {}) {
  const defaultCases = [
    { name: 'eicar_test.txt', content: 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR', mimetype: 'text/plain' },
    { name: 'high_entropy.bin', content: () => crypto.randomBytes(512), mimetype: 'application/octet-stream' },
    { name: 'safe.txt', content: 'Hello, this is a safe file.', mimetype: 'text/plain' }
  ];

  const demo = new VirusScanDemo({
    seedHashes: options.seedHashes || [
      { hash: '44d88612fea8a8f36de82e1278abb02f', type: 'md5', threatName: 'EICAR-Test-File', severity: 'low', source: 'EICAR' },
      { hash: 'e99a18c428cb38d5f260853678922e03', type: 'md5', threatName: 'Backdoor.Win32.Meterpreter', severity: 'critical', source: 'VirusTotal' }
    ],
    testCases: options.testCases || defaultCases,
    tmpDir: options.tmpDir,
    setupMocks: options.setupMocks
  });
  return demo.run(options);
}

module.exports = { VirusScanDemo, runDemo };
