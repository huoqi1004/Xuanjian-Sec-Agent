const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');
const { getDb } = require('../db/database');
const aiService = require('./aiService');

/**
 * 多引擎病毒查杀服务（增强版）
 * 集成引擎:
 * - 本地哈希库 (内置)
 * - 360天眼威胁情报 (API)
 * - 卡巴斯基OpenTIP (API)
 * - AI恶意代码检测 (Python微服务)
 * - AI投毒检测 (Python微服务)
 * - 360病毒特征库 (本地+云端)
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

        // 1. 计算文件哈希
        const hashes = this._calculateHashes(file.path);
        logger.info(`[多引擎扫描] MD5: ${hashes.md5}, SHA256: ${hashes.sha256}`);

        // 2. 并行执行所有引擎扫描
        const engineResults = await Promise.allSettled([
            this._scanLocalHash(hashes),
            this._scan360Ti(hashes),
            this._scanKaspersky(file.path, file.originalname),
            this._scanAIMalware(file.path),
            this._scanAIPoisoning(file.path, hashes),
            this._scan360VirusDB(hashes),
            this._scanFileEntropy(file.path)
        ]);

        // 3. 收集各引擎结果
        const engines = [
            { name: '本地哈希库', key: 'local_hash', icon: 'database' },
            { name: '360天眼', key: '360_ti', icon: 'shield' },
            { name: '卡巴斯基OpenTIP', key: 'kaspersky', icon: 'security' },
            { name: 'AI恶意代码检测', key: 'ai_malware', icon: 'cpu' },
            { name: 'AI投毒检测', key: 'ai_poisoning', icon: 'warning' },
            { name: '360病毒特征库', key: '360_virus_db', icon: 'virus' },
            { name: '文件熵值分析', key: 'entropy', icon: 'chart' }
        ];

        const engineResultsMap = {};
        engineResults.forEach((result, index) => {
            const engine = engines[index];
            if (result.status === 'fulfilled') {
                engineResultsMap[engine.key] = result.value;
            } else {
                engineResultsMap[engine.key] = {
                    engine: engine.name, status: 'error',
                    verdict: 'unknown', confidence: 0,
                    detail: result.reason?.message || '引擎调用失败',
                    responseTime: 0
                };
            }
        });

        // 4. AI驱动决策仲裁
        const decision = this._aiArbitrate(engineResultsMap, hashes, file);

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
                scanId, file: file.originalname, hashes, engineResults: engineResultsMap,
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
     * 计算文件哈希
     */
    _calculateHashes(filePath) {
        const data = fs.readFileSync(filePath);
        return {
            md5: crypto.createHash('md5').update(data).digest('hex'),
            sha1: crypto.createHash('sha1').update(data).digest('hex'),
            sha256: crypto.createHash('sha256').update(data).digest('hex')
        };
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
     */
    async _scanKaspersky(filePath, fileName) {
        const start = Date.now();
        try {
            const db = getDb();
            const apiKey = db.prepare("SELECT value FROM sys_config WHERE key = 'kaspersky_api_key'").get()?.value;

            if (!apiKey) {
                return { engine: '卡巴斯基OpenTIP', status: 'skipped', verdict: 'unknown', confidence: 0, detail: '未配置卡巴斯基API Key', responseTime: Date.now() - start };
            }

            const fileData = fs.readFileSync(filePath);

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
     */
    async _scanAIMalware(filePath) {
        const start = Date.now();
        try {
            const result = await aiService.detectMalware(filePath);
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
     */
    async _scanAIPoisoning(filePath, hashes) {
        const start = Date.now();
        try {
            const result = await aiService.detectPoisoning(filePath);
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
                return {
                    engine: '360病毒特征库', status: 'completed',
                    verdict: 'clean', confidence: 0.05,
                    detail: '360病毒库未匹配到已知特征',
                    responseTime: Date.now() - start
                };
            }

            const info = result.info;
            const features = info.exts || {};
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
     */
    _scanFileEntropy(filePath) {
        const start = Date.now();
        try {
            const data = fs.readFileSync(filePath);
            const fileSize = data.length;
            if (fileSize === 0) {
                return { engine: '文件熵值分析', status: 'completed', verdict: 'unknown', confidence: 0, detail: '空文件', responseTime: Date.now() - start };
            }

            const byteFreq = new Uint32Array(256);
            for (let i = 0; i < data.length; i++) {
                byteFreq[data[i]]++;
            }

            let entropy = 0;
            for (let i = 0; i < 256; i++) {
                if (byteFreq[i] > 0) {
                    const p = byteFreq[i] / fileSize;
                    entropy -= p * Math.log2(p);
                }
            }

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
            if (result.status === 'skipped' || result.status === 'error') continue;

            const weight = engineWeights[key] || 0.5;
            totalWeight += weight;

            if (result.verdict === 'malicious' || result.verdict === 'poisoned') {
                maliciousWeight += weight * result.confidence;
                if (result.confidence > primaryConfidence) {
                    primaryConfidence = result.confidence;
                    primaryEngine = result.engine;
                }
            } else if (result.verdict === 'suspicious') {
                suspiciousWeight += weight * result.confidence;
            }
        }

        const maliciousScore = totalWeight > 0 ? maliciousWeight / totalWeight : 0;
        const suspiciousScore = totalWeight > 0 ? suspiciousWeight / totalWeight : 0;

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
     * 获取扫描报告（N-01：对象级校验，非管理员仅本人扫描可见）
     */
    getScanReport(scanId, tenant) {
        const reportDir = path.join(__dirname, '../../data/scan_reports');
        const reportPath = path.join(reportDir, `scan_${scanId}.json`);
        if (!fs.existsSync(reportPath)) {
            return null;
        }
        const data = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));
        if (!require('../utils/tenantHelpers').isOwner(tenant, { uploaded_by: data.scannedBy }, 'uploaded_by')) {
            return null;
        }
        return data;
    }
}

module.exports = new MultiEngineScanService();
