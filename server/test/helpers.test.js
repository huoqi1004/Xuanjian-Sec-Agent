const { parseCIDR, parsePortRange, formatFileSize } = require('../utils/helpers');

describe('parseCIDR 地址段解析', () => {
  test('单个 IP 直接返回', () => {
    expect(parseCIDR('192.168.1.1')).toEqual(['192.168.1.1']);
  });

  test('解析 /30 网段（4-2=2 个可用地址）', () => {
    expect(parseCIDR('192.168.1.0/30')).toEqual(['192.168.1.1', '192.168.1.2']);
  });

  test('解析 /32 掩码', () => {
    expect(parseCIDR('10.0.0.5/32')).toEqual(['10.0.0.5']);
  });

  test('超大网段按上限截断（防内存溢出）', () => {
    const hosts = parseCIDR('10.0.0.0/8');
    expect(hosts.length).toBe(65536);
    expect(hosts[0]).toBe('10.0.0.1');
  });
});

describe('parsePortRange 端口范围解析', () => {
  test('单个端口', () => {
    expect(parsePortRange('80')).toEqual([80]);
  });

  test('区间端口', () => {
    expect(parsePortRange('80-82')).toEqual([80, 81, 82]);
  });

  test('多段合并去重排序', () => {
    expect(parsePortRange('443,80,80-81')).toEqual([80, 81, 443]);
  });

  test('非法输入被忽略', () => {
    expect(parsePortRange('0,70000,22')).toEqual([22]);
  });
});

describe('formatFileSize 文件大小格式化', () => {
  test('字节', () => expect(formatFileSize(0)).toBe('0 B'));
  test('KB', () => expect(formatFileSize(1024)).toBe('1 KB'));
  test('MB', () => expect(formatFileSize(1048576)).toBe('1 MB'));
});
