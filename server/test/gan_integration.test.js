// -*- coding: utf-8 -*-
/**
 * GAN 投票融合集成测试
 *
 * 测试 GAN 引擎在 multiEngineScanService 中的集成行为：
 * - 规则1: GAN异常 + 低恶意分数 → suspicious
 * - 规则2: GAN异常 + 高恶意分数 → 提升 confidence
 * - 规则3: GAN clean + 高恶意分数 → 降级确认
 * - 规则4: GAN 不可用 → 跳过
 *
 * 运行: cd server && npx jest test/gan_integration.test.js
 */

const multiEngineScanService = require('../services/multiEngineScanService');

describe('GAN 投票融合测试', () => {
    describe('_ganVoteMerge', () => {
        const baseDecision = {
            verdict: 'clean',
            confidence: 0.3,
            maliciousScore: 0.1,
            suspiciousScore: 0.0,
            recommendation: '文件安全',
            primaryEngine: '本地哈希库'
        };

        it('规则1: GAN异常 + maliciousScore < 0.3 → 升级为 suspicious', () => {
            const engineResultsMap = {
                gan_anomaly: {
                    engine: 'GAN异常检测',
                    status: 'completed',
                    verdict: 'suspicious',
                    confidence: 0.7,
                    reconstructionError: 0.05,
                    detail: 'GAN异常检测: 重构误差=0.050000, 判定为异常'
                }
            };
            const decision = JSON.parse(JSON.stringify(baseDecision));
            decision.maliciousScore = 0.1;
            decision.confidence = 0.3;

            const result = multiEngineScanService._ganVoteMerge(engineResultsMap, decision);

            expect(result.verdict).toBe('suspicious');
            expect(result.ganBoosted).toBe(true);
            expect(result.ganDetail).toContain('GAN重构误差异常');
            expect(result.confidence).toBeGreaterThanOrEqual(0.3);
        });

        it('规则2: GAN异常 + maliciousScore >= 0.3 → 提升 confidence', () => {
            const engineResultsMap = {
                gan_anomaly: {
                    engine: 'GAN异常检测',
                    status: 'completed',
                    verdict: 'suspicious',
                    confidence: 0.8,
                    reconstructionError: 0.06
                }
            };
            const decision = JSON.parse(JSON.stringify(baseDecision));
            decision.maliciousScore = 0.6;
            decision.confidence = 0.75;
            decision.verdict = 'malicious';

            const result = multiEngineScanService._ganVoteMerge(engineResultsMap, decision);

            expect(result.ganBoosted).toBe(true);
            expect(result.confidence).toBeGreaterThan(0.75);
            expect(result.confidence).toBeLessThanOrEqual(0.99);
            expect(result.ganDetail).toContain('双重命中');
        });

        it('规则3: GAN clean + 恶意引擎 >= 3 → 降级确认', () => {
            const engineResultsMap = {
                gan_anomaly: {
                    engine: 'GAN异常检测',
                    status: 'completed',
                    verdict: 'clean',
                    confidence: 0.9,
                    reconstructionError: 0.001
                },
                local_hash: { verdict: 'malicious' },
                '360_ti': { verdict: 'malicious' },
                kaspersky: { verdict: 'malicious' }
            };
            const decision = JSON.parse(JSON.stringify(baseDecision));
            decision.maliciousScore = 0.7;
            decision.confidence = 0.8;
            decision.verdict = 'malicious';

            const result = multiEngineScanService._ganVoteMerge(engineResultsMap, decision);

            expect(result.ganConflicted).toBe(true);
            expect(result.confidence).toBeLessThan(0.8);
            expect(result.ganDetail).toContain('GAN判定安全');
            expect(result.ganDetail).toContain('建议人工复核');
        });

        it('规则4: GAN 不可用（skipped）→ 直接返回，不修改决策', () => {
            const engineResultsMap = {
                gan_anomaly: {
                    engine: 'GAN异常检测',
                    status: 'skipped',
                    verdict: 'unknown',
                    detail: 'GAN 引擎未在配置中启用'
                }
            };
            const decision = JSON.parse(JSON.stringify(baseDecision));
            const result = multiEngineScanService._ganVoteMerge(engineResultsMap, decision);

            expect(result.ganBoosted).toBeUndefined();
            expect(result.ganConflicted).toBeUndefined();
            expect(result.verdict).toBe('clean');
            expect(result.confidence).toBe(0.3);
        });

        it('规则4: GAN 不可用（error）→ 直接返回', () => {
            const engineResultsMap = {
                gan_anomaly: {
                    engine: 'GAN异常检测',
                    status: 'error',
                    verdict: 'unknown',
                    detail: 'GAN检测失败: timeout'
                }
            };
            const decision = JSON.parse(JSON.stringify(baseDecision));
            const result = multiEngineScanService._ganVoteMerge(engineResultsMap, decision);

            expect(result.ganBoosted).toBeUndefined();
            expect(result.ganConflicted).toBeUndefined();
        });

        it('规则4: 无 GAN 结果 → 直接返回', () => {
            const engineResultsMap = {};
            const decision = JSON.parse(JSON.stringify(baseDecision));
            const result = multiEngineScanService._ganVoteMerge(engineResultsMap, decision);

            expect(result.ganBoosted).toBeUndefined();
            expect(result.ganConflicted).toBeUndefined();
        });
    });
});
