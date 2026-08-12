/**
 * wasmSandboxService 单元测试
 *
 * 测试覆盖：
 * - 软 WASM 分析器（PE 检测、熵值、API 匹配、NOP sled、恶意字符串）
 * - 启发式分析降级路径
 * - getStats 统计信息
 * - 哈希计算
 */

const fs = require('fs');
const path = require('path');
const wasmSandboxService = require('../services/wasmSandboxService');

describe('wasmSandboxService', () => {
  describe('soft WASM analyzer', () => {
    const analyzer = require('../assets/wasm/analyzer.js');

    it('should detect PE MZ header', () => {
      const data = Buffer.from([0x4d, 0x5a, 0x00, 0x00, ...Buffer.alloc(100, 0x00)]);
      const result = analyzer.analyze(data);
      expect(result.is_pe).toBe(true);
      // PE_MZ_header gives 0.2 score → below 0.25 threshold → clean
      expect(result.verdict).toBe('clean');
      expect(result.behaviors).toContain('PE_MZ_header');
    });

    it('should detect suspicious API strings', () => {
      const data = Buffer.from([0x4d, 0x5a, ...Buffer.from('VirtualAlloc WriteProcessMemory powershell')]);
      const result = analyzer.analyze(data);
      expect(result.behaviors).toContain('suspicious_api:VirtualAlloc');
      expect(result.behaviors).toContain('suspicious_api:WriteProcessMemory');
      expect(result.behaviors).toContain('suspicious_api:powershell');
    });

    it('should detect high entropy', () => {
      // 随机数据（高熵）
      const data = Buffer.alloc(1024);
      for (let i = 0; i < 1024; i++) data[i] = Math.random() * 256;
      const result = analyzer.analyze(data);
      expect(result.entropy).toBeGreaterThan(7.0);
      expect(result.behaviors).toContain('high_entropy:');
    });

    it('should detect NOP sled', () => {
      const data = Buffer.alloc(32, 0x90); // 32 NOP bytes
      const result = analyzer.analyze(data);
      expect(result.behaviors).toContain('nop_sled:32');
      expect(result.score).toBeGreaterThanOrEqual(0.25);
    });

    it('should detect malware strings', () => {
      const data = Buffer.from('eval(base64_decode("test")) powershell -enc');
      const result = analyzer.analyze(data);
      expect(result.behaviors).toContain('malware_string:eval(');
      expect(result.behaviors).toContain('malware_string:base64');
      // 无 PE header 时 API 检测不运行，验证恶意字符串检测
      expect(result.score).toBeGreaterThan(0);
    });

    it('should return clean for benign data', () => {
      const data = Buffer.from('Hello, this is a normal text file with no malicious content.');
      const result = analyzer.analyze(data);
      expect(result.verdict).toBe('clean');
      expect(result.confidence).toBeLessThan(0.25);
    });

    it('should return malicious for combined suspicious indicators', () => {
      const data = Buffer.from([0x4d, 0x5a, ...Buffer.alloc(100, 0x90), ...Buffer.from('VirtualAlloc powershell eval(')]);
      const result = analyzer.analyze(data);
      expect(result.verdict).toBe('malicious');
      expect(result.confidence).toBeGreaterThanOrEqual(0.5);
    });

    it('should handle empty buffer', () => {
      const result = analyzer.analyze(Buffer.alloc(0));
      expect(result).toBeDefined();
      expect(result.verdict).toBe('clean');
    });

    it('should handle small buffer', () => {
      const result = analyzer.analyze(Buffer.from([0x42, 0x49, 0x4d]));
      expect(result).toBeDefined();
      expect(result.verdict).toBe('clean');
    });
  });

  describe('heuristicAnalysis', () => {
    it('should return verdict for a file path', () => {
      const tmpFile = path.join(__dirname, '..', 'tmp_test_wasm.bin');
      fs.writeFileSync(tmpFile, Buffer.from([0x4d, 0x5a, ...Buffer.alloc(100, 0x90), Buffer.from('powershell')]));
      try {
        const result = wasmSandboxService.heuristicAnalysis(tmpFile, null);
        expect(result).toBeDefined();
        expect(result.verdict).toBeDefined();
        expect(result.confidence).toBeGreaterThanOrEqual(0);
        expect(result.confidence).toBeLessThanOrEqual(1);
      } finally {
        fs.unlinkSync(tmpFile);
      }
    });

    it('should accept fileData parameter to avoid re-reading file', () => {
      const data = Buffer.from([0x4d, 0x5a, ...Buffer.alloc(50, 0x90)]);
      const result = wasmSandboxService.heuristicAnalysis('/tmp/fake.bin', null, data);
      expect(result).toBeDefined();
      expect(result.verdict).toBeDefined();
    });
  });

  describe('hashFile', () => {
    it('should compute MD5, SHA1, SHA256 for a file', () => {
      const tmpFile = path.join(__dirname, '..', 'tmp_test_hash.bin');
      fs.writeFileSync(tmpFile, Buffer.from('test data for hashing'));
      try {
        const hashes = wasmSandboxService.hashFile(tmpFile);
        expect(hashes).toBeDefined();
        expect(hashes.md5).toHaveLength(32);
        expect(hashes.sha1).toHaveLength(40);
        expect(hashes.sha256).toHaveLength(64);
      } finally {
        fs.unlinkSync(tmpFile);
      }
    });

    it('should return null for non-existent file', () => {
      const result = wasmSandboxService.hashFile('/nonexistent/file.bin');
      expect(result).toBeNull();
    });
  });

  describe('getStats', () => {
    it('should return valid stats object', () => {
      const stats = wasmSandboxService.getStats();
      expect(stats).toBeDefined();
      expect(typeof stats.total_analyses).toBe('number');
      expect(typeof stats.current_mode).toBe('string');
      expect(['native', 'soft', 'heuristic']).toContain(stats.current_mode);
    });
  });

  describe('analysisMode initialization', () => {
    it('should have valid current_mode', () => {
      const stats = wasmSandboxService.getStats();
      expect(stats.current_mode).toMatch(/^(native|soft|heuristic)$/);
    });
  });
});
