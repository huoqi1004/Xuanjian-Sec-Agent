const { identifyService, scanPort } = require('../services/scanService');
const { parseNmapOutput, detectTools, resolveEngine } = require('../services/scanEngine');

describe('scanService 服务指纹识别', () => {
  test('常见端口识别', () => {
    expect(identifyService(22, 'SSH-2.0-OpenSSH_8.2').service).toBe('ssh');
    expect(identifyService(80, '').service).toBe('http');
    expect(identifyService(3306, 'MySQL').service).toBe('mysql');
    expect(identifyService(6379, '').service).toBe('redis');
    expect(identifyService(9999, '').service).toBe('unknown');
  });

  test('从 Banner 提取版本', () => {
    const r = identifyService(80, 'Server: nginx/1.18.0');
    expect(r.service).toBe('http');
    expect(r.version).toBe('1.18.0');
  });

  test('未知端口可从 Banner 推断服务', () => {
    const r = identifyService(2121, '220 Welcome to vsftpd 3.0.3');
    expect(r.service).toBe('ftp');
  });

  test('TCP Connect 扫描本机关闭端口', async () => {
    const result = await scanPort('127.0.0.1', 9, 800); // 端口9通常关闭
    expect(['closed', 'filtered']).toContain(result.state);
  });
});

describe('scanEngine nmap 输出解析', () => {
  test('解析开放端口行', () => {
    const out = [
      'Starting Nmap 7.80 ( https://nmap.org ) at 2026-08-08 10:00 CST',
      'Nmap scan report for 192.168.1.10',
      'Host is up (0.0010s latency).',
      'PORT     STATE    SERVICE',
      '22/tcp   open     ssh',
      '80/tcp   filtered http',
      '443/tcp  open     https',
      'MAC Address: 00:11:22:33:44:55',
      'Nmap done: 1 IP address (1 host up) scanned'
    ].join('\n');

    const results = parseNmapOutput(out, '192.168.1.10');
    expect(results).toHaveLength(2);
    expect(results[0]).toMatchObject({ ip: '192.168.1.10', port: 22, service: 'ssh', state: 'open' });
    expect(results[1].port).toBe(443);
  });

  test('引擎选择：无外部工具时回退 node', () => {
    const tools = detectTools();
    const engine = resolveEngine('auto');
    expect(['nmap', 'masscan', 'node']).toContain(engine);
    if (!tools.nmap) {
      expect(engine).toBe('node');
    }
  });
});
