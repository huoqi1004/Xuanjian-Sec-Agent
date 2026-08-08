const { validatePasswordStrength } = require('../routes/auth');

describe('密码强度校验 validatePasswordStrength', () => {
  test('长度不足 8 位拒绝', () => {
    expect(validatePasswordStrength('a1')).not.toBeNull();
    expect(validatePasswordStrength('Abc123')).not.toBeNull();
  });

  test('纯字母拒绝', () => {
    expect(validatePasswordStrength('abcdefgh')).not.toBeNull();
  });

  test('纯数字拒绝', () => {
    expect(validatePasswordStrength('12345678')).not.toBeNull();
  });

  test('空值拒绝', () => {
    expect(validatePasswordStrength('')).not.toBeNull();
    expect(validatePasswordStrength(null)).not.toBeNull();
  });

  test('字母+数字组合通过', () => {
    expect(validatePasswordStrength('admin123')).toBeNull();
    expect(validatePasswordStrength('Security2026')).toBeNull();
  });
});
