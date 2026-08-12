const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');
const { config } = require('../config');
const { getDb } = require('../db/database');
const aiService = require('./aiService');
const GANVersionService = require('./ganVersionService');
const wasmSandboxService = require('./wasmSandboxService');

/**
 * 多引擎病毒查杀服务（增强版）
 * 集成引擎:
 * - 本地哈希库 (内置)
 * - 360天眼威胁情报 (API)
 * - 卡巴斯基OpenTIP (API)
 * - AI恶意代码检测 (Python微服务)
 * - AI投毒检测 (Python微服务)
 * - 360病毒特征库 (本地+云端)
 * - GAN异常检测 (Python微服务，Phase 2)
 */
class MultiEngineScanService {

    /**
     * 执行多引擎扫描
     * @param {Object} file - { path, originalname, size, mimetype }
     * @param {number} userId - 操作用户ID
     * @returns {Object} 扫描结果
     */
    async scanFile(file, userId) {
        const scanId = crypto.randomUUID();
        const startTime = Date.now();

        logger.info(`[多引擎扫描] 开始扫描: ${file.originalname} (${(file.size / 1024).toFixed(1)}KB)`);

        // 一次性读取文件，供所有引擎共享（避免各引擎重复 readFileSync）
        let fileData = null;
        try {
            fileData = fs.readFileSync(file.path);
        } catch (e) {
            logger.error(`[多引擎扫描] 文件读取失败: ${e.message}`);
            return { scanId, error: e.message, decision: { verdict: 'unknown', confidence: 0, recommendation: '文件读取失败' } };
        }

        // 1. 计算文件哈希（复用 fileData，不再重复读取）
        const hashes = this._calculateHashes(fileData);
        logger.info(`[多引擎扫描] MD5: ${hashes.md5}, SHA256: ${hashes.sha256}`);

        // 2. 并行执行所有引擎扫描（全部复用 fileData）
        const engineResults = await Promise.allSettled([
            this._scanLocalHash(hashes),
            this._scan360Ti(hashes),
            this._scanKaspersky(fileData, file.originalname),
            this._scanAIMalware(file.path, fileData),
            this._scanAIPoisoning(file.path, hashes, fileData),
            this._scan360VirusDB(hashes),
            this._scanFileEntropy(fileData),
            this._scanGANCHomaly(file.path, fileData)
        ]);

        // 3. 收集各引擎结果
        const engines = [
            { name: '本地哈希库', key: 'local_hash', icon: 'database' },
            { name: '360天眼', key: '360_ti', icon: 'shield' },
            { name: '卡巴斯基OpenTIP', key: 'kaspersky', icon: 'security' },
            { name: 'AI恶意代码检测', key: 'ai_malware', icon: 'cpu' },
            { name: 'AI投毒检测', key: 'ai_poisoning', icon: 'warning' },
            { name: '360病毒特征库', key: '360_virus_db', icon: 'virus' },
            { name: '文件熵值分析', key: 'entropy', icon: 'chart' },
            { name: 'GAN异常检测', key: 'gan_anomaly', icon: 'brain' }
        ];

        const engineResultsMap = {};
        const engineLogParts = [];
        engineResults.forEach((result, index) => {
            const engine = engines[index];
            if (result.status === 'fulfilled') {
                engineResultsMap[engine.key] = result.value;
                const r = result.value;
                engineLogParts.push(`[${engine.name}] ${r.status ?? r.verdict ?? 'completed'}(${(r.responseTime ?? 0)}ms)`);
                if (r.verdict === 'malicious' || r.verdict === 'poisoned') {
                    logger.info(`[多引擎扫描] 🔴 引擎命中: ${engine.name} → ${r.verdict} | 置信度: ${(r.confidence * 100).toFixed(1)}% | ${r.detail}`);
                } else if (r.verdict === 'suspicious') {
                    logger.info(`[多引擎扫描] 🟡 引擎可疑: ${engine.name} → ${r.verdict} | 置信度: ${(r.confidence * 100).toFixed(1)}% | ${r.detail}`);
                } else if (r.verdict === 'clean') {
                    logger.info(`[多引擎扫描] 🟢 引擎安全: ${engine.name} | 置信度: ${(r.confidence * 100).toFixed(1)}%`);
                } else if (r.status === 'skipped') {
                    logger.info(`[多引擎扫描] ⚪ 引擎跳过: ${engine.name} | ${r.detail}`);
                }
            } else {
                engineResultsMap[engine.key] = {
                    engine: engine.name, status: 'error',
                    verdict: 'unknown', confidence: 0,
                    detail: result.reason?.message || '引擎调用失败',
                    responseTime: 0
                };
                logger.warn(`[多引擎扫描] ❌ 引擎异常: ${engine.name} | ${result.reason?.message || '未知错误'}`);
            }
        });
        logger.info(`[多引擎扫描] 引擎结果汇总: ${engineLogParts.join(', ')}`);

        // 4. AI驱动决策仲裁
        let decision = this._aiArbitrate(engineResultsMap, hashes, file);
        logger.info(`[多引擎扫描] 仲裁结果: verdict=${decision.verdict} | maliciousScore=${decision.maliciousScore.toFixed(3)} | suspiciousScore=${decision.suspiciousScore.toFixed(3)} | confidence=${(decision.confidence * 100).toFixed(1)}% | primaryEngine=${decision.primaryEngine}`);

        // 4.5 GAN 专项投票融合（Phase 2）
        const ganDecision = this._ganVoteMerge(engineResultsMap, decision);
        logger.info(`[GAN投票] 最终仲裁: verdict=${ganDecision.verdict} | confidence=${(ganDecision.confidence * 100).toFixed(1)}% | ganBoosted=${!!ganDecision.ganBoosted} | ganConflicted=${!!ganDecision.ganConflicted}`);
        decision = ganDecision;

        // 4.6 记录 GAN 扫描指标（Phase 4）
        this._recordGANMetrics(file, hashes, engineResultsMap, decision);

        // 4.5 零日威胁动态沙箱分析（当所有引擎均为 unknown 但熵值异常时触发）
        if (decision.verdict === 'clean' || decision.verdict === 'suspicious') {
            const allUnknown = Object.values(engineResultsMap).every(
                e => e.verdict === 'unknown' || e.status === 'skipped' || e.status === 'error'
            );
            const entropyResult = engineResultsMap['entropy'];
            const highEntropy = entropyResult && entropyResult.verdict === 'suspicious';
            if (allUnknown && highEntropy) {
                logger.info('[多引擎扫描] 所有引擎 unknown + 熵值异常，触发沙箱分析');
                const sandboxResult = await this._sandboxAnalysis(file, hashes, fileData);
                engineResultsMap['sandbox'] = sandboxResult;
                if (sandboxResult.verdict === 'malicious') {
                    decision.verdict = 'malicious';
                    decision.confidence = sandboxResult.confidence;
                    decision.primaryEngine = '动态沙箱';
                    decision.recommendation = '沙箱分析判定为恶意，建议立即隔离';
                } else if (sandboxResult.verdict === 'suspicious' && decision.verdict === 'clean') {
                    decision.verdict = 'suspicious';
                    decision.confidence = sandboxResult.confidence;
                    decision.primaryEngine = '动态沙箱';
                }
            }
        }

        // 5. 生成查杀报告
        const report = await this._generateScanReport(file, hashes, engineResultsMap, decision, startTime);

        // 6. 保存到数据库
        const db = getDb();
        try {
            const dbResult = db.prepare(`
                INSERT INTO virus_scan_records
                (file_name, file_hash_md5, file_hash_sha256, file_size, detection_result, detection_source, model_score, uploaded_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            `).run(
                file.originalname,
                hashes.md5,
                hashes.sha256,
                file.size,
                decision.verdict,
                decision.primaryEngine,
                decision.confidence,
                userId
            );

            // 保存多引擎详细结果
            const detailDir = path.join(__dirname, '../../data/scan_reports');
            if (!fs.existsSync(detailDir)) fs.mkdirSync(detailDir, { recursive: true });
            const detailPath = path.join(detailDir, `scan_${scanId}.json`);
            fs.writeFileSync(detailPath, JSON.stringify({
                scanId, file: file.originalname, filePath: file.path, hashes, engineResults: engineResultsMap,
                decision, report, scannedAt: new Date().toISOString(), scannedBy: userId
            }, null, 2));

            const totalTime = ((Date.now() - startTime) / 1000).toFixed(1);
            logger.info(`[多引擎扫描] 扫描完成: ${file.originalname} -> ${decision.verdict} (${totalTime}s)`);

            return {
                scanId,
                recordId: dbResult.lastInsertRowid,
                fileName: file.originalname,
                fileSize: file.size,
                hashes,
                engines: engineResultsMap,
                decision,
                report,
                detailPath,
                totalTime: parseFloat(totalTime)
            };
        } catch (dbErr) {
            logger.error(`[多引擎扫描] 数据库保存失败: ${dbErr.message}`);
            return {
                scanId,
                recordId: null,
                fileName: file.originalname,
                fileSize: file.size,
                hashes,
                engines: engineResultsMap,
                decision,
                report,
                totalTime: ((Date.now() - startTime) / 1000).toFixed(1)
            };
        }
    }

    /**
     * 计算文件哈希（一次读取，并行计算 MD5/SHA1/SHA256）
     * @param {Buffer} data - 已读取的文件数据
     */
    _calculateHashes(data) {
        return {
            md5: crypto.createHash('md5').update(data).digest('hex'),
            sha1: crypto.createHash('sha1').update(data).digest('hex'),
            sha256: crypto.createHash('sha256').update(data).digest('hex')
        };
    }

    /**
     * 计算文件熵值（统一实现，供各引擎复用）
     */
    _calcEntropy(data) {
        const freq = new Uint32Array(256);
        for (let i = 0; i < data.length; i++) freq[data[i]]++;
        let ent = 0;
        const len = data.length;
        for (let i = 0; i < 256; i++) {
            if (freq[i] > 0) {
                const p = freq[i] / len;
                ent -= p * Math.log2(p);
            }
        }
        return ent;
    }

    /**
     * 引擎1: 本地哈希库比对
     */
    _scanLocalHash(hashes) {
        const start = Date.now();
        try {
            const db = getDb();
            const md5Match = db.prepare('SELECT * FROM virus_hashes WHERE hash_value = ? AND hash_type = ?').get(hashes.md5, 'md5');
            const sha256Match = db.prepare('SELECT * FROM virus_hashes WHERE hash_value = ? AND hash_type = ?').get(hashes.sha256, 'sha256');
            const match = md5Match || sha256Match;

            return {
                engine: '本地哈希库', status: 'completed',
                verdict: match ? 'malicious' : 'clean',
                confidence: match ? 1.0 : 0,
                detail: match
                    ? `匹配已知威胁: ${match.threat_name} (来源: ${match.source || '本地库'})`
                    : '未在本地病毒库中找到匹配',
                threatName: match?.threat_name || null,
                responseTime: Date.now() - start
            };
        } catch (e) {
            return { engine: '本地哈希库', status: 'error', verdict: 'unknown', confidence: 0, detail: e.message, responseTime: Date.now() - start };
        }
    }

    /**
     * 引擎2: 360天眼API查询
     */
    async _scan360Ti(hashes) {
        const start = Date.now();
        try {
            const db = getDb();
            const apiKey = db.prepare("SELECT value FROM sys_config WHERE key = 'ti360_api_key'").get()?.value;
            const apiSalt = db.prepare("SELECT value FROM sys_config WHERE key = 'ti360_api_salt'").get()?.value;

            if (!apiKey) {
                return { engine: '360天眼', status: 'skipped', verdict: 'unknown', confidence: 0, detail: '未配置360天眼API Key', responseTime: Date.now() - start };
            }

            const timestamp = Math.floor(Date.now() / 1000);
            const sign = crypto.createHash('md5').update(String(timestamp) + (apiSalt || '')).digest('hex');

            const sampleStr = hashes.md5 + '+' + hashes.sha1;
            const response = await axios.post('https://api.ti.360.net/safe/api/v2/file',
                { samples: [{ sample: sampleStr }] },
                {
                    headers: {
                        'X-Api-Key': apiKey,
                        'sign': sign,
                        'timestamp': String(timestamp),
                        'Content-Type': 'application/json'
                    },
                    timeout: 15000
                }
            );

            const result = response.data?.results?.[0];
            if (!result) {
                return { engine: '360天眼', status: 'completed', verdict: 'unknown', confidence: 0, detail: 'API未返回结果', responseTime: Date.now() - start };
            }

            const level = result.info?.level || 40;
            const levelMap = { 10: 'clean', 20: 'clean', 30: 'clean', 40: 'unknown', 50: 'suspicious', 60: 'suspicious', 70: 'malicious' };
            const confidenceMap = { 10: 0, 20: 0.1, 30: 0.2, 40: 0, 50: 0.5, 60: 0.7, 70: 0.95 };

            return {
                engine: '360天眼', status: 'completed',
                verdict: levelMap[level] || 'unknown',
                confidence: confidenceMap[level] || 0,
                detail: result.info?.malware
                    ? `检测到威胁: ${result.info.malware} (级别: ${level}, 类型: ${result.info?.exts?.threat_type || '未知'})`
                    : `安全级别: ${level} (${this._levelDescription(level)})`,
                threatName: result.info?.malware || null,
                threatType: result.info?.exts?.threat_type || null,
                rawLevel: level,
                responseTime: Date.now() - start
            };
        } catch (error) {
            logger.warn(`[360天眼] API调用失败: ${error.message}`);
            return { engine: '360天眼', status: 'error', verdict: 'unknown', confidence: 0, detail: `API调用失败: ${error.message}`, responseTime: Date.now() - start };
        }
    }

    /**
     * 引擎3: 卡巴斯基OpenTIP API
     * @param {Buffer} fileData - 已读取的文件数据
     */
    async _scanKaspersky(fileData, fileName) {
        const start = Date.now();
        try {
            const db = getDb();
            const apiKey = db.prepare("SELECT value FROM sys_config WHERE key = 'kaspersky_api_key'").get()?.value;

            if (!apiKey) {
                return { engine: '卡巴斯基OpenTIP', status: 'skipped', verdict: 'unknown', confidence: 0, detail: '未配置卡巴斯基API Key', responseTime: Date.now() - start };
            }

            if (fileData.length > 50 * 1024 * 1024) {
                return { engine: '卡巴斯基OpenTIP', status: 'skipped', verdict: 'unknown', confidence: 0, detail: '文件超过50MB限制', responseTime: Date.now() - start };
            }

            const response = await axios.post(
                `https://opentip.kaspersky.com/api/v1/scan/file?filename=${encodeURIComponent(fileName)}`,
                fileData,
                {
                    headers: {
                        'x-api-key': apiKey,
                        'Content-Type': 'application/octet-stream'
                    },
                    timeout: 60000
                }
            );

            const data = response.data;
            const zoneMap = { 'Red': 'malicious', 'Yellow': 'suspicious', 'Green': 'clean', 'Grey': 'unknown' };
            const confidenceMap = { 'Red': 0.95, 'Yellow': 0.6, 'Green': 0.05, 'Grey': 0 };

            const zone = data.Zone || 'Grey';
            const detections = data.DetectionsInfo || [];
            const detectionNames = detections.map(d => d.DetectionName).filter(Boolean);

            logger.info(`[卡巴斯基] API响应: zone=${zone} | detections=${detectionNames.length > 0 ? detectionNames.join(',') : 'none'} | fileStatus=${data.FileStatus || 'N/A'}`);

            return {
                engine: '卡巴斯基OpenTIP', status: 'completed',
                verdict: zoneMap[zone] || 'unknown',
                confidence: confidenceMap[zone] || 0,
                detail: data.FileStatus
                    ? `状态: ${data.FileStatus}, 区域: ${zone}${detectionNames.length > 0 ? ', 检测到: ' + detectionNames.join(', ') : ''}`
                    : `区域: ${zone}`,
                threatName: detectionNames[0] || null,
                fileStatus: data.FileStatus,
                firstSeen: data.FirstSeen,
                lastSeen: data.LastSeen,
                packer: data.Packer,
                signer: data.Signer,
                hitsCount: data.HitsCount,
                dynamicDetections: data.DynamicDetections,
                rawZone: zone,
                responseTime: Date.now() - start
            };
        } catch (error) {
            logger.warn(`[卡巴斯基] API调用失败: ${error.message}`);
            return { engine: '卡巴斯基OpenTIP', status: 'error', verdict: 'unknown', confidence: 0, detail: `API调用失败: ${error.message}`, responseTime: Date.now() - start };
        }
    }

    /**
     * 引擎4: AI恶意代码检测
     * @param {string} filePath - 文件路径（用于 aiService 内部处理）
     * @param {Buffer} fileData - 已读取的文件数据，避免重复读取
     */
    async _scanAIMalware(filePath, fileData) {
        const start = Date.now();
        try {
            logger.info(`[AI恶意代码检测] 开始AI检测: ${filePath}`);
            const result = await aiService.detectMalware(filePath, fileData);
            logger.info(`[AI恶意代码检测] 完成 | is_malicious=${result.is_malicious} | score=${result.score.toFixed(4)} | method=${result.method || 'unknown'} | anomalies=${JSON.stringify(result.anomalies || [])}`);
            return {
                engine: 'AI恶意代码检测', status: 'completed',
                verdict: result.is_malicious ? 'malicious' : 'clean',
                confidence: result.score || 0,
                detail: result.is_malicious
                    ? `AI判定为恶意 (置信度: ${(result.score * 100).toFixed(1)}%), 检测方法: ${result.method || '混合检测'}`
                    : `AI判定为安全 (置信度: ${((1 - (result.score || 0)) * 100).toFixed(1)}%)`,
                method: result.method,
                responseTime: Date.now() - start
            };
        } catch (error) {
            return { engine: 'AI恶意代码检测', status: 'error', verdict: 'unknown', confidence: 0, detail: `AI检测失败: ${error.message}`, responseTime: Date.now() - start };
        }
    }

    /**
     * 引擎5: AI投毒检测
     * @param {string} filePath - 文件路径
     * @param {Object} hashes - 文件哈希
     * @param {Buffer} fileData - 已读取的文件数据，避免重复读取
     */
    async _scanAIPoisoning(filePath, hashes, fileData) {
        const start = Date.now();
        try {
            const result = await aiService.detectPoisoning(filePath, fileData);
            return {
                engine: 'AI投毒检测', status: 'completed',
                verdict: result.is_poisoned ? 'poisoned' : 'clean',
                confidence: result.poisoning_probability || 0,
                detail: result.is_poisoned
                    ? `检测到投毒特征 (概率: ${(result.poisoning_probability * 100).toFixed(1)}%), 孤立森林异常: ${result.isolation_forest_anomaly ? '是' : '否'}`
                    : `未检测到投毒特征 (概率: ${((result.poisoning_probability || 0) * 100).toFixed(1)}%)`,
                poisoningProbability: result.poisoning_probability,
                isolationForestAnomaly: result.isolation_forest_anomaly,
                isolationForestScore: result.isolation_forest_score,
                responseTime: Date.now() - start
            };
        } catch (error) {
            return { engine: 'AI投毒检测', status: 'error', verdict: 'unknown', confidence: 0, detail: `投毒检测失败: ${error.message}`, responseTime: Date.now() - start };
        }
    }

    /**
     * 引擎6: 360病毒特征库检测
     * 基于360威胁情报中心的病毒特征库，通过哈希和特征匹配
     */
    async _scan360VirusDB(hashes) {
        const start = Date.now();
        try {
            const db = getDb();
            const apiKey = db.prepare("SELECT value FROM sys_config WHERE key = 'ti360_api_key'").get()?.value;
            const apiSalt = db.prepare("SELECT value FROM sys_config WHERE key = 'ti360_api_salt'").get()?.value;

            if (!apiKey) {
                return { engine: '360病毒特征库', status: 'skipped', verdict: 'unknown', confidence: 0, detail: '未配置360API Key', responseTime: Date.now() - start };
            }

            const timestamp = Math.floor(Date.now() / 1000);
            const sign = crypto.createHash('md5').update(String(timestamp) + (apiSalt || '')).digest('hex');

            // 查询文件信息
            const sampleStr = hashes.md5 + '+' + hashes.sha1;
            const response = await axios.post('https://api.ti.360.net/safe/api/v2/file',
                { samples: [{ sample: sampleStr }] },
                {
                    headers: {
                        'X-Api-Key': apiKey,
                        'sign': sign,
                        'timestamp': String(timestamp),
                        'Content-Type': 'application/json'
                    },
                    timeout: 15000
                }
            );

            const result = response.data?.results?.[0];
            if (!result || !result.info?.malware) {
                logger.info(`[360病毒特征库] 未匹配到已知特征，判定为安全`);
                return {
                    engine: '360病毒特征库', status: 'completed',
                    verdict: 'clean', confidence: 0.05,
                    detail: '360病毒库未匹配到已知特征',
                    responseTime: Date.now() - start
                };
            }

            const info = result.info;
            const features = info.exts || {};
            logger.info(`[360病毒特征库] 命中: ${info.malware} | family=${features.family || '未知'} | type=${features.threat_type || '未知'}`);

            return {
                engine: '360病毒特征库', status: 'completed',
                verdict: 'malicious',
                confidence: info.level >= 70 ? 0.98 : 0.9,
                detail: `360特征库匹配: ${info.malware} (家族: ${info.exts?.family || '未知'}, 类型: ${info.exts?.threat_type || '未知'}, 行为: ${info.exts?.behavior || '未知'})`,
                threatName: info.malware,
                family: info.exts?.family || null,
                threatType: info.exts?.threat_type || null,
                behavior: info.exts?.behavior || null,
                firstSeen: info.exts?.first_seen || null,
                responseTime: Date.now() - start
            };
        } catch (error) {
            logger.warn(`[360病毒特征库] 查询失败: ${error.message}`);
            return { engine: '360病毒特征库', status: 'error', verdict: 'unknown', confidence: 0, detail: `查询失败: ${error.message}`, responseTime: Date.now() - start };
        }
    }

    /**
     * 引擎7: 文件熵值分析（无Key，内置）
     * 通过文件熵值和统计特征判断是否可疑
     * @param {Buffer|null} fileData - 已读取的文件数据（由 scanFile 传入，避免重复读取）
     */
    _scanFileEntropy(fileData) {
        const start = Date.now();
        try {
            // 支持两种入参：文件路径字符串（由 scanFile 传入）或已读取的 Buffer
            let data;
            let label = 'unknown';
            if (Buffer.isBuffer(fileData)) {
                data = fileData;
                label = `buffer(${fileData.length}B)`;
            } else if (typeof fileData === 'string' && fileData) {
                data = fs.readFileSync(fileData);
                label = fileData;
            } else {
                return { engine: '文件熵值分析', status: 'error', verdict: 'unknown', confidence: 0, detail: '缺少文件数据或路径', responseTime: Date.now() - start };
            }
            const fileSize = data.length;
            logger.info(`[文件熵值分析] 开始分析: ${label} | 文件大小: ${fileSize} bytes`);
            if (fileSize === 0) {
                return { engine: '文件熵值分析', status: 'completed', verdict: 'unknown', confidence: 0, detail: '空文件', responseTime: Date.now() - start };
            }

            const ent = this._calcEntropy(data);
            const entropy = ent;

            let verdict = 'clean';
            let confidence = 0;
            let detail = '';

            if (entropy > 7.8) {
                verdict = 'suspicious';
                confidence = 0.6;
                detail = `文件熵值极高(${entropy.toFixed(2)})，高度疑似加密/混淆恶意代码`;
            } else if (entropy > 7.0) {
                verdict = 'suspicious';
                confidence = 0.3;
                detail = `文件熵值偏高(${entropy.toFixed(2)})，可能存在编码/压缩内容`;
            } else if (entropy < 3.0 && fileSize > 1024) {
                verdict = 'suspicious';
                confidence = 0.2;
                detail = `文件熵值极低(${entropy.toFixed(2)})，异常低信息密度`;
            } else {
                detail = `文件熵值正常(${entropy.toFixed(2)})，未发现异常`;
            }

            logger.info(`[文件熵值分析] 熵值计算完成: entropy=${entropy.toFixed(4)} | verdict=${verdict} | confidence=${confidence} | ${detail}`);

            return {
                engine: '文件熵值分析', status: 'completed',
                verdict, confidence, detail,
                entropy: entropy.toFixed(4),
                responseTime: Date.now() - start
            };
        } catch (e) {
            return { engine: '文件熵值分析', status: 'error', verdict: 'unknown', confidence: 0, detail: e.message, responseTime: Date.now() - start };
        }
    }

    _levelDescription(level) {
        const map = { 10: '纯白', 20: '白', 30: '灰白', 40: '灰', 50: '低疑似', 60: '高疑似', 70: '恶意' };
        return map[level] || '未知';
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 2: GAN 引擎（AnomalyGAN 异常检测）
    // ═══════════════════════════════════════════════════════════════

    /**
     * 引擎8: GAN 异常检测
     * @param {string} filePath - 文件路径
     * @param {Buffer} fileData - 已读取的文件数据，避免重复读取
     */
    async _scanGANCHomaly(filePath, fileData) {
        const start = Date.now();
        const ganConfig = config.gan;

        // 配置关闭时直接跳过
        if (!ganConfig || !ganConfig.enabled) {
            return {
                engine: 'GAN异常检测',
                status: 'skipped',
                verdict: 'unknown',
                confidence: 0,
                detail: 'GAN 引擎未在配置中启用 (GAN_SCAN_ENABLED=false)',
                responseTime: Date.now() - start
            };
        }

        // 大文件跳过（复用 fileData.length，去除重复 statSync）
        if (fileData.length > 5 * 1024 * 1024) {
            return {
                engine: 'GAN异常检测',
                status: 'skipped',
                verdict: 'unknown',
                confidence: 0,
                detail: `文件过大(${(fileData.length / 1024 / 1024).toFixed(1)}MB)，跳过 GAN 分析`,
                responseTime: Date.now() - start
            };
        }

        try {
            const result = await aiService.callGANAnalysis(filePath, fileData);

            if (!result) {
                return {
                    engine: 'GAN异常检测',
                    status: 'error',
                    verdict: 'unknown',
                    confidence: 0,
                    detail: 'AI 服务无响应',
                    responseTime: Date.now() - start
                };
            }

            const reconError = parseFloat(result.reconstruction_error || 0);
            const isAnomaly = result.is_anomaly === true;
            const ganConfidence = parseFloat(result.confidence || 0);
            const threshold = ganConfig.anomalyThreshold || 0.02;

            let verdict, confidence, detail;
            if (isAnomaly) {
                verdict = 'suspicious';
                confidence = Math.min(0.95, ganConfidence * 0.8 + 0.2);
                detail = `GAN异常检测: 重构误差=${reconError.toFixed(6)}(阈值=${threshold}), 判定为异常`;
            } else {
                verdict = 'clean';
                confidence = Math.max(0.05, 1.0 - reconError);
                detail = `GAN异常检测: 重构误差=${reconError.toFixed(6)}(阈值=${threshold}), 判定为安全`;
            }

            logger.info(`[GAN异常检测] filePath=${filePath} | recon_error=${reconError.toFixed(6)} | verdict=${verdict} | confidence=${confidence.toFixed(4)} | elapsed=${Date.now() - start}ms`);

            return {
                engine: 'GAN异常检测',
                status: 'completed',
                verdict,
                confidence,
                detail,
                reconstructionError: reconError,
                ganModelVersion: result.model_version || 'unknown',
                anomalyScore: result.anomaly_score || 0,
                responseTime: Date.now() - start
            };
        } catch (error) {
            logger.warn(`[GAN异常检测] 调用失败: ${error.message}`);
            return {
                engine: 'GAN异常检测',
                status: 'error',
                verdict: 'unknown',
                confidence: 0,
                detail: `GAN检测失败: ${error.message}`,
                responseTime: Date.now() - start
            };
        }
    }

    /**
     * GAN 专项投票融合
     * 在 _aiArbitrate 之后调用，调整 verdict 和 recommendation
     * 规则:
     *   1. GAN异常 + 低恶意分数 → 升级为 suspicious
     *   2. GAN异常 + 高恶意分数 → 提升 confidence
     *   3. GAN clean + 高恶意分数 → 降级确认（误报检查）
     *   4. GAN 不可用 → 跳过
     */
    _ganVoteMerge(engineResultsMap, decision) {
        const ganConfig = config.gan;
        const ganResult = engineResultsMap['gan_anomaly'];

        // 规则4: GAN 不可用 → 直接返回
        if (!ganResult || ganResult.status === 'skipped' || ganResult.status === 'error') {
            logger.info('[GAN投票] GAN引擎不可用（skipped/error），跳过GAN投票逻辑');
            return decision;
        }

        const ganAnomaly = ganResult.verdict === 'suspicious';
        const ganConfidence = ganResult.confidence || 0;
        const malformedScore = decision.maliciousScore || 0;

        // 规则1: GAN异常 + 规则未命中（maliciousScore < 0.3）→ suspicious
        if (ganAnomaly && malformedScore < 0.3) {
            decision.verdict = 'suspicious';
            decision.confidence = Math.max(decision.confidence, ganConfidence * 0.5);
            decision.ganBoosted = true;
            decision.ganDetail = `GAN重构误差异常(${ganResult.reconstructionError?.toFixed(6) || 'N/A'})触发升级`;
            logger.info(`[GAN投票] 规则1触发: GAN异常 + 低恶意分数(maliciousScore=${malformedScore.toFixed(3)}) → 升级为suspicious`);
        }

        // 规则2: GAN异常 + 规则已命中（maliciousScore >= 0.3）→ 提升置信度
        else if (ganAnomaly && malformedScore >= 0.3) {
            const boostedConf = Math.min(0.99, decision.confidence + ganConfidence * 0.15);
            decision.confidence = boostedConf;
            decision.ganBoosted = true;
            decision.ganDetail = `GAN与规则引擎双重命中，置信度提升至${(boostedConf * 100).toFixed(1)}%`;
            logger.info(`[GAN投票] 规则2触发: GAN+规则双重命中, confidence ${decision.confidence.toFixed(3)} → ${boostedConf.toFixed(3)}`);
        }

        // 规则3: GAN clean + 规则恶意 → 降级确认
        else if (!ganAnomaly && malformedScore >= 0.6) {
            const maliciousEngineCount = Object.values(engineResultsMap).filter(
                e => e.verdict === 'malicious' || e.verdict === 'poisoned'
            ).length;
            if (maliciousEngineCount >= 3) {
                const reducedConf = decision.confidence * 0.9;
                decision.confidence = reducedConf;
                decision.ganConflicted = true;
                decision.ganDetail = `GAN判定安全但${maliciousEngineCount}个规则引擎命中，建议人工复核`;
                logger.info(`[GAN投票] 规则3触发: GAN与规则冲突, maliciousEngines=${maliciousEngineCount}, confidence ${(decision.confidence * 0.9).toFixed(3)}`);
            }
        }

        return decision;
    }

    /**
     * 记录 GAN 扫描指标（Phase 4）
     * 将 GAN 引擎结果写入 gan_scan_metrics 表，供监控看板使用
     */
    _recordGANMetrics(file, hashes, engineResultsMap, decision) {
        const ganResult = engineResultsMap['gan_anomaly'];
        // 仅 GAN 引擎明确跳过时才不记录（error 状态也要记录，便于监控可见性）
        if (!ganResult || ganResult.status === 'skipped') {
            return;
        }

        try {
            const db = getDb();
            db.prepare(`
                INSERT INTO gan_scan_metrics
                  (scan_id, file_path, file_hash_md5, file_size_bytes, model_version,
                   recon_error, is_anomaly, anomaly_score, confidence, verdict,
                   engine_verdict, engine_confidence, vote_merged, gan_boosted,
                   gan_conflicted, response_time_ms, skipped, skip_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).run(
                null,  // scan_id: 暂无关联
                file.path || '',
                hashes.md5 || null,
                file.size || 0,
                ganResult.ganModelVersion || 'unknown',
                ganResult.reconstructionError || 0,
                ganResult.verdict === 'suspicious' ? 1 : 0,
                ganResult.anomalyScore || 0,
                ganResult.confidence || 0,
                decision.verdict || 'unknown',
                ganResult.verdict || null,
                ganResult.confidence || null,
                (decision.ganBoosted || decision.ganConflicted) ? 1 : 0,
                decision.ganBoosted ? 1 : 0,
                decision.ganConflicted ? 1 : 0,
                ganResult.responseTime || 0,
                ganResult.status === 'error' ? 1 : 0,
                ganResult.status === 'error' ? `gan_engine_error: ${ganResult.reason?.message || 'unknown'}` : null,
            );
            logger.debug(`[GAN指标] 记录成功: ${file.path} | verdict=${decision.verdict} | recon_error=${(ganResult.reconstructionError || 0).toFixed(6)} | status=${ganResult.status}`);
        } catch (error) {
            logger.debug(`[GAN指标] 记录跳过（表未就绪）: ${error.message}`);
        }
    }

    /**
     * AI驱动决策仲裁
     */
    _aiArbitrate(engineResults, hashes, file) {
        const verdicts = [];
        let totalWeight = 0;
        let maliciousWeight = 0;
        let suspiciousWeight = 0;
        let primaryEngine = '无';
        let primaryConfidence = 0;

        const engineWeights = {
            'local_hash': 1.0,
            '360_ti': 0.9,
            'kaspersky': 0.95,
            'ai_malware': 0.7,
            'ai_poisoning': 0.6,
            '360_virus_db': 0.95,
            'entropy': 0.3
        };

        for (const [key, result] of Object.entries(engineResults)) {
            if (result.status === 'skipped' || result.status === 'error') {
                logger.info(`[仲裁引擎] ${result.engine || key}: ${result.status} (${result.detail})`);
                continue;
            }

            const weight = engineWeights[key] || 0.5;
            totalWeight += weight;

            if (result.verdict === 'malicious' || result.verdict === 'poisoned') {
                maliciousWeight += weight * result.confidence;
                logger.info(`[仲裁引擎] ${result.engine}: malicious | weight=${weight} | confidence=${result.confidence.toFixed(2)} | 累计maliciousWeight=${maliciousWeight.toFixed(3)}`);
                if (result.confidence > primaryConfidence) {
                    primaryConfidence = result.confidence;
                    primaryEngine = result.engine;
                }
            } else if (result.verdict === 'suspicious') {
                suspiciousWeight += weight * result.confidence;
                logger.info(`[仲裁引擎] ${result.engine}: suspicious | weight=${weight} | confidence=${result.confidence.toFixed(2)} | 累计suspiciousWeight=${suspiciousWeight.toFixed(3)}`);
            } else {
                logger.info(`[仲裁引擎] ${result.engine}: ${result.verdict} | weight=${weight}`);
            }
        }

        logger.info(`[仲裁汇总] totalWeight=${totalWeight.toFixed(2)} | maliciousWeight=${maliciousWeight.toFixed(3)} | suspiciousWeight=${suspiciousWeight.toFixed(3)}`);
        const maliciousScore = totalWeight > 0 ? maliciousWeight / totalWeight : 0;
        const suspiciousScore = totalWeight > 0 ? suspiciousWeight / totalWeight : 0;
        logger.info(`[仲裁评分] maliciousScore=${maliciousScore.toFixed(3)} | suspiciousScore=${suspiciousScore.toFixed(3)} | 阈值0.6(malicious)/0.3(可疑)`);

        let verdict, confidence, recommendation;

        if (maliciousScore >= 0.6) {
            verdict = 'malicious';
            confidence = Math.min(0.99, maliciousScore + 0.1);
            recommendation = '立即隔离并删除文件，建议提交至安全团队进行深度分析';
        } else if (maliciousScore >= 0.3 || suspiciousScore >= 0.5) {
            verdict = 'suspicious';
            confidence = Math.max(maliciousScore, suspiciousScore);
            recommendation = '建议隔离文件并提交至沙箱进行动态行为分析';
        } else if (maliciousScore > 0 || suspiciousScore > 0) {
            verdict = 'suspicious';
            confidence = Math.max(maliciousScore, suspiciousScore);
            recommendation = '低风险，建议持续监控并定期复查';
        } else {
            verdict = 'clean';
            confidence = totalWeight > 0 ? 1 - (maliciousScore + suspiciousScore) : 0.5;
            recommendation = '文件安全，未检测到威胁';
        }

        if (confidence >= 0.3 && confidence <= 0.6 && verdict !== 'clean') {
            recommendation += ' [注意: 置信度处于模糊区间，建议进行人工复核或沙箱动态分析]';
        }

        return { verdict, confidence, recommendation, primaryEngine, maliciousScore, suspiciousScore };
    }

    /**
     * 生成查杀报告
     */
    async _generateScanReport(file, hashes, engineResults, decision, startTime) {
        const scanTime = new Date().toLocaleString('zh-CN');
        const totalTime = ((Date.now() - startTime) / 1000).toFixed(1);

        const engineSummary = Object.values(engineResults).map(e => ({
            engine: e.engine,
            status: e.status,
            verdict: e.verdict,
            confidence: e.confidence,
            detail: e.detail,
            responseTime: (e.responseTime / 1000).toFixed(1) + 's'
        }));

        // 尝试AI润色报告
        let aiSummary = null;
        try {
            aiSummary = await aiService.generateVirusReport({
                fileName: file.originalname,
                fileSize: file.size,
                hashes,
                engineSummary,
                decision,
                scanTime,
                totalTime
            });
        } catch (e) {
            logger.warn(`[AI报告] 生成失败，使用模板: ${e.message}`);
        }

        return {
            title: `病毒查杀报告 - ${file.originalname}`,
            scanTime,
            totalTime,
            file: {
                name: file.originalname,
                size: file.size,
                sizeFormatted: file.size < 1024 ? file.size + ' B' : (file.size < 1048576 ? (file.size / 1024).toFixed(1) + ' KB' : (file.size / 1048576).toFixed(1) + ' MB'),
                md5: hashes.md5,
                sha256: hashes.sha256
            },
            engineResults: engineSummary,
            decision,
            aiSummary: aiSummary || this._generateTemplateSummary(file, hashes, engineSummary, decision, scanTime, totalTime)
        };
    }

    /**
     * 模板报告（AI不可用时）
     */
    _generateTemplateSummary(file, hashes, engineSummary, decision, scanTime, totalTime) {
        const maliciousEngines = engineSummary.filter(e => e.verdict === 'malicious' || e.verdict === 'poisoned');
        const cleanEngines = engineSummary.filter(e => e.verdict === 'clean');
        const skippedEngines = engineSummary.filter(e => e.status === 'skipped');

        let summary = `## 查杀结论\n\n`;
        summary += `**最终判定**: ${decision.verdict === 'malicious' ? '恶意' : (decision.verdict === 'suspicious' ? '疑似' : '安全')}\n`;
        summary += `**置信度**: ${(decision.confidence * 100).toFixed(1)}%\n`;
        summary += `**主要判定引擎**: ${decision.primaryEngine}\n\n`;

        summary += `## 文件信息\n\n`;
        summary += `- 文件名: ${file.originalname}\n`;
        summary += `- 文件大小: ${file.size < 1048576 ? (file.size / 1024).toFixed(1) + ' KB' : (file.size / 1048576).toFixed(1) + ' MB'}\n`;
        summary += `- MD5: ${hashes.md5}\n`;
        summary += `- SHA256: ${hashes.sha256}\n\n`;

        summary += `## 各引擎扫描结果\n\n`;
        summary += `| 引擎 | 状态 | 判定 | 置信度 | 耗时 |\n`;
        summary += `|------|------|------|--------|------|\n`;
        for (const e of engineSummary) {
            const verdictText = e.verdict === 'malicious' ? '恶意' : (e.verdict === 'suspicious' ? '疑似' : (e.verdict === 'poisoned' ? '投毒' : (e.verdict === 'clean' ? '安全' : '未知')));
            summary += `| ${e.engine} | ${e.status === 'completed' ? '完成' : (e.status === 'skipped' ? '跳过' : '错误')} | ${verdictText} | ${(e.confidence * 100).toFixed(0)}% | ${e.responseTime} |\n`;
        }

        if (maliciousEngines.length > 0) {
            summary += `\n## 检测详情\n\n`;
            for (const e of maliciousEngines) {
                summary += `### ${e.engine}\n${e.detail}\n\n`;
            }
        }

        summary += `\n## 处置建议\n\n${decision.recommendation}\n\n`;
        summary += `---\n*报告生成时间: ${scanTime} | 扫描耗时: ${totalTime}s*\n`;
        summary += `*玄鉴安全智能体 - 多引擎协同病毒查杀系统*\n`;

        return summary;
    }

    /**
     * 零日威胁动态沙箱分析
     * 当所有静态引擎均返回 unknown 且文件熵值异常时触发
     * 优先级：Python AI 微服务 → WASM/软 WASM 分析 → 启发式本地分析
     * @param {Object} file - 文件对象
     * @param {Object} hashes - 文件哈希
     * @param {Buffer|null} fileData - 已读取的文件数据（由 scanFile 传入，避免重复读文件）
     */
    async _sandboxAnalysis(file, hashes, fileData = null) {
        const start = Date.now();

        // 1. 优先尝试 WASM/软 WASM 沙箱分析（本地，无需 Python 服务）
        try {
            const wasmResult = await wasmSandboxService.analyzeWithWasmSandbox(file.path);
            if (wasmResult && wasmResult.verdict) {
                logger.info(`[沙箱] WASM 沙箱分析完成: verdict=${wasmResult.verdict} | confidence=${wasmResult.confidence.toFixed(2)} | engine=${wasmResult.engine}`);
                return {
                    engine: 'WASM沙箱',
                    status: 'completed',
                    verdict: wasmResult.verdict,
                    confidence: wasmResult.confidence,
                    detail: `WASM沙箱(${wasmResult.engine}): ${wasmResult.verdict}`,
                    behavior_summary: wasmResult.behaviors || null,
                    responseTime: Date.now() - start
                };
            }
        } catch (e) {
            logger.warn(`[沙箱] WASM 沙箱分析失败，降级: ${e.message}`);
        }

        // 2. 降级：Python AI 微服务沙箱分析
        try {
            const result = await aiService.callAiServiceFileDetection('/api/analyze/sandbox', file.path);
            if (result && typeof result.verdict === 'string') {
                const verdictMap = { 'malicious': 'malicious', 'suspicious': 'suspicious', 'clean': 'clean', 'unknown': 'suspicious' };
                return {
                    engine: '动态沙箱',
                    status: 'completed',
                    verdict: verdictMap[result.verdict] || 'suspicious',
                    confidence: result.confidence || 0.5,
                    detail: result.detail || `沙箱分析: ${result.verdict}`,
                    behavior_summary: result.behavior_summary || null,
                    responseTime: Date.now() - start
                };
            }
        } catch (e) {
            logger.warn(`[沙箱] Python 微服务调用失败，降级为启发式分析: ${e.message}`);
        }

        // 3. 最终降级：启发式本地沙箱分析
        const info = this._heuristicSandboxAnalysis(file.path, hashes, fileData);
        logger.info(`[沙箱] 启发式分析完成: verdict=${info.verdict} | confidence=${info.confidence.toFixed(2)}`);
        return {
            engine: '动态沙箱',
            status: 'completed',
            ...info,
            responseTime: Date.now() - start
        };
    }

    /**
     * 启发式本地沙箱分析（Python 服务不可用时的降级方案）
     * @param {string} filePath - 文件路径
     * @param {Object} hashes - 文件哈希
     * @param {Buffer|null} fileData - 已读取的文件数据（由 scanFile 传入）
     */
    _heuristicSandboxAnalysis(filePath, hashes, fileData = null) {
        try {
            const data = fileData || fs.readFileSync(filePath);
            const fileSize = data.length;
            const entropy = require('./aiService').calculateEntropy ?
                this._calcEntropy(data) : 0;

            let score = 0;
            const behaviors = [];

            // PE 特征分析
            if (data.length >= 2 && data[0] === 0x4d && data[1] === 0x5a) {
                score += 0.2;
                behaviors.push('PE可执行文件');

                // 检查可疑导入
                const text = data.toString('utf8', 0, Math.min(65536, fileSize));
                const suspiciousApis = [
                    'VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread',
                    'NtUnmapViewOfSection', 'SetWindowsHookEx', 'GetAsyncKeyState',
                    'URLDownloadToFile', 'InternetOpen', 'WinExec', 'system('
                ];
                for (const api of suspiciousApis) {
                    if (text.includes(api)) {
                        score += 0.1;
                        behaviors.push(`疑似调用API:${api}`);
                    }
                }
            }

            // 高熵 + 加密特征
            const ent = this._calcEntropy(data);
            if (ent > 7.8) { score += 0.3; behaviors.push(`高熵(${ent.toFixed(2)})，可能加密/混淆`); }
            else if (ent > 7.0) { score += 0.15; behaviors.push(`熵值偏高(${ent.toFixed(2)})`); }

            // 已知恶意字符串
            const malwareStrings = ['powershell', '-enc', '-encodedcommand', 'cmd.exe', '/c',
                'eval(', 'exec(', 'base64', 'wscript', 'cscript', 'mshta', 'regsvr32'];
            for (const s of malwareStrings) {
                if (data.includes(s)) { score += 0.15; behaviors.push(`含可疑字符串:${s}`); }
            }

            const verdict = score >= 0.5 ? 'malicious' : (score >= 0.25 ? 'suspicious' : 'clean');
            return { verdict, confidence: Math.min(score, 1.0), detail: behaviors.join('; ') || '未发现异常行为特征' };
        } catch (e) {
            return { verdict: 'unknown', confidence: 0, detail: `沙箱分析失败: ${e.message}` };
        }
    }

    _calcEntropy(data) {
        if (!data || data.length === 0) return 0;
        const freq = new Map();
        for (const byte of data) freq.set(byte, (freq.get(byte) || 0) + 1);
        let entropy = 0;
        const len = data.length;
        for (const count of freq.values()) {
            const p = count / len;
            entropy -= p * Math.log2(p);
        }
        return entropy;
    }

    /**
     * 获取历史扫描记录（N-02：非管理员仅可见本组织记录）
     */
    getScanHistory(page = 1, pageSize = 20, tenant) {
        try {
            const db = getDb();
            const records = db.prepare('SELECT * FROM virus_scan_records').all();

            const { inOrg } = require('../utils/tenantHelpers');
            const filtered = inOrg(records, tenant, 'uploaded_by')
                .sort((a, b) => String(b.created_at || '').localeCompare(String(a.created_at || '')));

            const offset = (page - 1) * pageSize;
            return { list: filtered.slice(offset, offset + pageSize), total: filtered.length, page, pageSize };
        } catch (e) {
            return { list: [], total: 0, page, pageSize };
        }
    }

    /**
     * 读取扫描报告文件（内部助手，不含租户校验）
     */
    _readReportFile(scanId) {
        const reportDir = path.join(__dirname, '../../data/scan_reports');
        const reportPath = path.join(reportDir, `scan_${scanId}.json`);
        if (!fs.existsSync(reportPath)) return null;
        try {
            return JSON.parse(fs.readFileSync(reportPath, 'utf-8'));
        } catch (e) {
            return null;
        }
    }

    /**
     * 根据报告中的文件哈希定位 virus_scan_records 台账记录
     */
    _findRecordByReport(data) {
        const db = getDb();
        const hashes = data.hashes || {};
        let record = null;
        if (hashes.sha256) {
            record = db.prepare('SELECT * FROM virus_scan_records WHERE file_hash_sha256 = ? ORDER BY id DESC LIMIT 1').get(hashes.sha256);
        }
        if (!record && hashes.md5) {
            record = db.prepare('SELECT * FROM virus_scan_records WHERE file_hash_md5 = ? ORDER BY id DESC LIMIT 1').get(hashes.md5);
        }
        return record || null;
    }

    /**
     * 获取扫描报告（N-01：对象级校验，非管理员仅本人扫描可见）
     * 合并处置台账（status/action_type/handled_at 等来自 virus_scan_records）
     */
    getScanReport(scanId, tenant) {
        const data = this._readReportFile(scanId);
        if (!data) return null;
        if (!require('../utils/tenantHelpers').isOwner(tenant, { uploaded_by: data.scannedBy }, 'uploaded_by')) {
            return null;
        }
        const record = this._findRecordByReport(data);
        if (record) {
            data.disposal = {
                status: record.status || 'pending',
                action_type: record.action_type || null,
                handled_at: record.handled_at || null,
                handled_by: record.handled_by || null,
                quarantine_path: record.quarantine_path || null
            };
        }
        return data;
    }

    /**
     * 处置前置校验：报告存在 + 租户/对象级权限 + 台账记录存在
     */
    _requireDisposal(scanId, tenant) {
        const data = this._readReportFile(scanId);
        if (!data) return { error: '未找到扫描报告' };
        if (!require('../utils/tenantHelpers').isOwner(tenant, { uploaded_by: data.scannedBy }, 'uploaded_by')) {
            return { error: '无权访问该扫描记录' };
        }
        const record = this._findRecordByReport(data);
        if (!record) return { error: '未找到扫描台账记录' };
        return { data, record };
    }

    /** 处置审计：action_logs + audit_logs 双落库 */
    _writeDisposalAudit({ action, record, detail, userId, username }) {
        const db = getDb();
        db.prepare('INSERT INTO action_logs (policy_id, action_type, action_detail, result) VALUES (?, ?, ?, ?)')
            .run(null, `${action}_file`, detail, 'success');
        db.prepare('INSERT INTO audit_logs (user_id, username, operation_type, operation_target, operation_detail, result) VALUES (?, ?, ?, ?, ?, ?)')
            .run(userId, username || 'system', 'virus_disposal', `scan:${record.file_name || record.id}`, detail, 'success');
    }

    /**
     * 隔离恶意文件（API 处置）：移动物理文件 + 更新台账 + 审计
     */
    async quarantineScanRecord(scanId, tenant, userId, username) {
        const { data, record, error } = this._requireDisposal(scanId, tenant);
        if (error) return { error };
        if (record.status === 'deleted') return { error: '该记录已删除，无法隔离' };
        if (record.status === 'quarantined') return { error: '该记录已处于隔离状态' };

        const db = getDb();
        const { config } = require('../config');
        const quarantineDir = (config.virusScan && config.virusScan.quarantineDir) || './data/quarantine';
        let quarantinePath = null;
        let detail = '';

        const srcPath = data.filePath;
        if (srcPath && fs.existsSync(srcPath)) {
            fs.mkdirSync(quarantineDir, { recursive: true });
            const fileName = typeof data.file === 'string' ? data.file : 'unknown';
            const dest = path.join(quarantineDir, `${Date.now()}-${path.basename(fileName)}`);
            try {
                fs.renameSync(srcPath, dest);
            } catch (moveErr) {
                if (moveErr.code === 'EXDEV') {
                    fs.copyFileSync(srcPath, dest);
                    fs.unlinkSync(srcPath);
                } else {
                    throw moveErr;
                }
            }
            quarantinePath = dest;
            detail = `隔离恶意文件 ${fileName} -> ${dest}`;
        } else {
            detail = `隔离台账更新（原文件路径未知或已不存在: ${srcPath || 'N/A'}）`;
        }

        const now = new Date().toISOString();
        db.prepare('UPDATE virus_scan_records SET status = ?, action_type = ?, handled_at = ?, handled_by = ?, quarantine_path = ? WHERE id = ?')
            .run('quarantined', 'quarantine', now, userId, quarantinePath, record.id);
        this._writeDisposalAudit({ action: 'quarantine', record, detail, userId, username });
        logger.info(`[病毒处置] 隔离完成: ${record.file_name} (scanId=${scanId})`);
        return { scanId, status: 'quarantined', action_type: 'quarantine', quarantine_path: quarantinePath, handled_at: now, handled_by: userId, detail };
    }

    /**
     * 恢复隔离文件（API 处置）：移回原路径/上传目录 + 更新台账 + 审计
     */
    async restoreScanRecord(scanId, tenant, userId, username) {
        const { data, record, error } = this._requireDisposal(scanId, tenant);
        if (error) return { error };
        if (record.status !== 'quarantined') return { error: '仅隔离状态的记录可恢复' };

        const db = getDb();
        const quarantinePath = record.quarantine_path;
        let detail = '';
        if (quarantinePath && fs.existsSync(quarantinePath)) {
            const srcPath = data.filePath;
            const target = (srcPath && fs.existsSync(path.dirname(srcPath)))
                ? srcPath
                : path.join('uploads', 'virus', path.basename(quarantinePath));
            try {
                fs.renameSync(quarantinePath, target);
            } catch (moveErr) {
                if (moveErr.code === 'EXDEV') {
                    fs.copyFileSync(quarantinePath, target);
                    fs.unlinkSync(quarantinePath);
                } else {
                    throw moveErr;
                }
            }
            detail = `恢复文件: ${quarantinePath} -> ${target}`;
        } else {
            detail = '恢复台账（隔离文件已不存在，仅更新状态）';
        }

        const now = new Date().toISOString();
        db.prepare('UPDATE virus_scan_records SET status = ?, action_type = ?, handled_at = ?, handled_by = ?, quarantine_path = NULL WHERE id = ?')
            .run('restored', 'restore', now, userId, record.id);
        this._writeDisposalAudit({ action: 'restore', record, detail, userId, username });
        logger.info(`[病毒处置] 恢复完成: ${record.file_name} (scanId=${scanId})`);
        return { scanId, status: 'restored', action_type: 'restore', handled_at: now, handled_by: userId, detail };
    }

    /**
     * 删除恶意文件（API 处置，需二次确认 confirm=true）：删除物理文件 + 更新台账 + 审计
     */
    async deleteScanRecord(scanId, tenant, userId, username, confirm = false) {
        if (confirm !== true) return { error: '删除操作需要二次确认（confirm=true）' };
        const { data, record, error } = this._requireDisposal(scanId, tenant);
        if (error) return { error };
        if (record.status === 'deleted') return { error: '该记录已删除' };

        const db = getDb();
        const srcPath = data.filePath;
        let detail = '';
        if (srcPath && fs.existsSync(srcPath)) {
            fs.unlinkSync(srcPath);
            detail = `删除恶意文件: ${srcPath}`;
        } else if (record.quarantine_path && fs.existsSync(record.quarantine_path)) {
            fs.unlinkSync(record.quarantine_path);
            detail = `删除隔离区文件: ${record.quarantine_path}`;
        } else {
            detail = '删除台账（原文件已不存在，仅更新状态）';
        }

        const now = new Date().toISOString();
        db.prepare('UPDATE virus_scan_records SET status = ?, action_type = ?, handled_at = ?, handled_by = ? WHERE id = ?')
            .run('deleted', 'delete', now, userId, record.id);
        this._writeDisposalAudit({ action: 'delete', record, detail, userId, username });
        logger.warn(`[病毒处置] 删除完成: ${record.file_name} (scanId=${scanId})`);
        return { scanId, status: 'deleted', action_type: 'delete', handled_at: now, handled_by: userId, detail };
    }
}

module.exports = new MultiEngineScanService();
