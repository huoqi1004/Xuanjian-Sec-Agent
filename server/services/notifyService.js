const axios = require('axios');
const nodemailer = require('nodemailer');
const logger = require('../utils/logger');

/**
 * 通知服务 - 支持邮件和Webhook通知
 */
class NotifyService {
    constructor() {
        this.transporter = null;
    }

    /**
     * 初始化邮件传输器
     */
    _initMailer() {
        if (this.transporter) return;
        try {
            const db = require('../db/database').getDb();
            const smtpHost = (db.prepare("SELECT value FROM sys_config WHERE key = 'smtp_host'").get()?.value) || '';
            const smtpPort = (db.prepare("SELECT value FROM sys_config WHERE key = 'smtp_port'").get()?.value) || '587';
            const smtpUser = (db.prepare("SELECT value FROM sys_config WHERE key = 'smtp_user'").get()?.value) || '';
            const smtpPass = (db.prepare("SELECT value FROM sys_config WHERE key = 'smtp_pass'").get()?.value) || '';

            if (smtpHost && smtpUser) {
                this.transporter = nodemailer.createTransport({
                    host: smtpHost, port: parseInt(smtpPort),
                    secure: parseInt(smtpPort) === 465,
                    auth: { user: smtpUser, pass: smtpPass }
                });
                logger.info('[通知] 邮件服务已初始化');
            }
        } catch(e) {
            logger.warn('[通知] 邮件服务初始化失败: ' + e.message);
        }
    }

    /**
     * 发送通知
     * @param {Object} params - { channel, message, severity, target }
     */
    async send(params) {
        const { channel = 'email', message, severity = 'medium', target = '' } = params;

        if (channel === 'email' || channel === 'all') {
            await this._sendEmail(message, severity, target);
        }
        if (channel === 'webhook' || channel === 'all') {
            await this._sendWebhook(message, severity, target);
        }
    }

    /**
     * 发送邮件通知
     */
    async _sendEmail(message, severity, target) {
        this._initMailer();
        if (!this.transporter) {
            logger.warn('[通知] 邮件服务未配置，跳过邮件发送');
            return;
        }
        try {
            const db = require('../db/database').getDb();
            const notifyEmail = (db.prepare("SELECT value FROM sys_config WHERE key = 'notify_email'").get()?.value) || '';
            if (!notifyEmail) { logger.warn('[通知] 未配置通知邮箱'); return; }

            const severityMap = { low: '低', medium: '中', high: '高', critical: '严重' };
            await this.transporter.sendMail({
                from: '"玄鉴安全智能体" <' + (this.transporter.options.auth?.user || '') + '>',
                to: notifyEmail,
                subject: `[安全告警][${severityMap[severity] || severity}] ${message.substring(0, 50)}`,
                text: `安全告警通知\n\n级别: ${severityMap[severity] || severity}\n目标: ${target}\n详情: ${message}\n时间: ${new Date().toLocaleString('zh-CN')}\n\n---\n玄鉴安全智能体 自动发送`
            });
            logger.info('[通知] 邮件发送成功');
        } catch(e) {
            logger.error('[通知] 邮件发送失败: ' + e.message);
        }
    }

    /**
     * 发送Webhook通知
     */
    async _sendWebhook(message, severity, target) {
        try {
            const db = require('../db/database').getDb();
            const webhookUrl = (db.prepare("SELECT value FROM sys_config WHERE key = 'webhook_url'").get()?.value) || '';
            if (!webhookUrl) { logger.warn('[通知] 未配置Webhook URL'); return; }

            await axios.post(webhookUrl, {
                alert: { message, severity, target },
                timestamp: new Date().toISOString(),
                source: 'xuanjian-security-agent'
            }, { timeout: 10000 });
            logger.info('[通知] Webhook发送成功');
        } catch(e) {
            logger.error('[通知] Webhook发送失败: ' + e.message);
        }
    }
}

module.exports = new NotifyService();
