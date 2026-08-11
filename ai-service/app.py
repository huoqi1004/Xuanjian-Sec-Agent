# -*- coding: utf-8 -*-
"""
玄鉴安全智能体 - AI微服务
提供恶意代码检测、投毒检测、LLM报告生成等AI能力
"""

import os
import sys
import logging
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

from malware_detector import MalwareDetector
from poisoning_detector import PoisoningDetector
from llm_report import LLMReportGenerator
from rag import kb as knowledge_base

# GAN 模块导入（可选，模型未加载时降级为规则引擎）
try:
    from gan.detector import GANAnomalyDetector, GANAdversarialGenerator
    from gan.prompt_adversarial import PromptAdversarialGenerator, PromptGuardTester
    GAN_AVAILABLE = True
except ImportError:
    GAN_AVAILABLE = False
    GANAnomalyDetector = None
    GANAdversarialGenerator = None
    PromptAdversarialGenerator = None
    PromptGuardTester = None

# 加载环境变量
load_dotenv()

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# 初始化检测器
malware_detector = MalwareDetector()
poisoning_detector = PoisoningDetector()
report_generator = LLMReportGenerator()

# 初始化 GAN 检测器
gan_anomaly_detector = None
gan_adv_generator = None
if GAN_AVAILABLE:
    gan_model_path = os.getenv('GAN_ANOMALY_MODEL', 'models/anomaly_gan.pt')
    adv_model_path = os.getenv('GAN_ADV_MODEL', 'models/adversarial_gan.pt')
    if os.path.isfile(gan_model_path):
        try:
            gan_anomaly_detector = GANAnomalyDetector(model_path=gan_model_path)
            logger.info('AnomalyGAN 模型已加载: %s', gan_model_path)
        except Exception as e:
            logger.warning('AnomalyGAN 加载失败（将使用规则引擎）: %s', e)
    if os.path.isfile(adv_model_path):
        try:
            gan_adv_generator = GANAdversarialGenerator(model_path=adv_model_path)
            logger.info('AdversarialGAN 模型已加载: %s', adv_model_path)
        except Exception as e:
            logger.warning('AdversarialGAN 加载失败: %s', e)


@app.route('/health', methods=['GET'])
def health_check():
    """健康检查接口"""
    return jsonify({
        'status': 'healthy',
        'service': 'xuanjian-ai-service',
        'version': '1.0.0',
        'models_loaded': {
            'malware_detector': malware_detector.is_loaded(),
            'poisoning_detector': poisoning_detector.is_loaded()
        },
        'knowledge_base_items': len(knowledge_base.items),
        'gan_models_loaded': {
            'anomaly_gan': gan_anomaly_detector is not None if GAN_AVAILABLE else False,
            'adversarial_gan': gan_adv_generator is not None if GAN_AVAILABLE else False,
        }
    })


@app.route('/api/knowledge/search', methods=['POST'])
def knowledge_search():
    """知识库向量检索（RAG）：POST { query, top_k? }"""
    try:
        body = request.get_json(silent=True) or {}
        query = (body.get('query') or '').strip()
        if not query:
            return jsonify({'code': 1, 'message': 'query 不能为空', 'data': []})
        top_k = int(body.get('top_k') or 5)
        results = knowledge_base.search(query, top_k=min(max(top_k, 1), 20))
        return jsonify({'code': 0, 'message': '检索成功', 'data': results})
    except Exception as e:  # noqa: BLE001
        logger.error('知识库检索失败: %s', e)
        return jsonify({'code': 1, 'message': f'检索失败: {e}', 'data': []})


@app.route('/api/knowledge', methods=['GET'])
def knowledge_list():
    """知识库条目列表：GET ?category=&limit=&offset="""
    try:
        category = request.args.get('category') or None
        limit = int(request.args.get('limit') or 100)
        offset = int(request.args.get('offset') or 0)
        items, total = knowledge_base.list_items(category=category, limit=limit, offset=offset)
        return jsonify({'code': 0, 'message': '获取成功', 'data': {'items': items, 'total': total}})
    except Exception as e:  # noqa: BLE001
        logger.error('知识库列表失败: %s', e)
        return jsonify({'code': 1, 'message': f'获取失败: {e}', 'data': None})


def save_upload_to_temp(file, prefix):
    """将上传文件保存到系统临时目录（跨平台，使用 tempfile）"""
    import tempfile
    suffix = os.path.splitext(file.filename or '')[1][:16]
    fd, temp_path = tempfile.mkstemp(prefix=prefix, suffix=suffix)
    file.save(temp_path)
    os.close(fd)
    return temp_path


@app.route('/api/detect/malware', methods=['POST'])
def detect_malware():
    """
    恶意代码检测接口
    接收文件上传，返回检测结果
    """
    if 'file' not in request.files:
        return jsonify({'error': '未上传文件'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': '文件名为空'}), 400

    temp_path = None
    try:
        # 保存临时文件（跨平台临时目录）
        temp_path = save_upload_to_temp(file, 'malware_scan_')

        # 执行检测
        result = malware_detector.detect(temp_path)
        return jsonify(result)

    except Exception as e:
        logger.error(f'恶意代码检测失败: {str(e)}')
        return jsonify({
            'is_malicious': False,
            'score': 0,
            'error': str(e),
            'message': '检测过程中发生错误'
        }), 500
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


@app.route('/api/detect/poisoning', methods=['POST'])
def detect_poisoning():
    """
    投毒检测接口
    检测文件是否为投毒样本（对抗性攻击）
    """
    if 'file' not in request.files:
        return jsonify({'error': '未上传文件'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': '文件名为空'}), 400

    temp_path = None
    try:
        # 保存临时文件（跨平台临时目录）
        temp_path = save_upload_to_temp(file, 'poison_scan_')

        # 执行检测
        result = poisoning_detector.detect(temp_path)
        return jsonify(result)

    except Exception as e:
        logger.error(f'投毒检测失败: {str(e)}')
        return jsonify({
            'is_poisoned': False,
            'score': 0,
            'error': str(e),
            'message': '检测过程中发生错误'
        }), 500
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


@app.route('/api/report/security', methods=['POST'])
def generate_security_report():
    """
    安全报告生成接口
    基于仪表盘数据生成安全评估报告
    """
    try:
        data = request.get_json()
        dashboard = data.get('dashboard', {})
        report_type = data.get('report_type', 'weekly')

        content = report_generator.generate_security_report(dashboard, report_type)

        return jsonify({
            'content': content,
            'type': report_type,
            'generated_at': data.get('timestamp', '')
        })

    except Exception as e:
        logger.error(f'安全报告生成失败: {str(e)}')
        return jsonify({
            'error': str(e),
            'content': '报告生成失败'
        }), 500


@app.route('/api/report/baseline', methods=['POST'])
def generate_baseline_report():
    """
    基线检查报告生成接口
    """
    try:
        data = request.get_json()
        results = data.get('results', {})

        content = report_generator.generate_baseline_report(results)

        return jsonify({
            'content': content,
            'generated_at': data.get('timestamp', '')
        })

    except Exception as e:
        logger.error(f'基线报告生成失败: {str(e)}')
        return jsonify({
            'error': str(e),
            'content': '报告生成失败'
        }), 500


@app.route('/api/report/scan', methods=['POST'])
def generate_scan_report():
    """
    病毒扫描报告生成接口
    基于多引擎扫描结果生成专业的病毒扫描报告
    """
    try:
        data = request.get_json()
        scan_data = data.get('scan_data', {})

        content = report_generator.generate_scan_report(scan_data)

        return jsonify({
            'content': content,
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })

    except Exception as e:
        logger.error(f'扫描报告生成失败: {str(e)}')
        return jsonify({
            'error': str(e),
            'content': '报告生成失败'
        }), 500


# ═══════════════════════════════════════════════════════════════
# GAN 接口
# ═══════════════════════════════════════════════════════════════

@app.route('/api/gan/anomaly', methods=['POST'])
def gan_anomaly_detect():
    """
    GAN 异常检测接口
    POST { file_path: str } 或 multipart 文件上传
    """
    if not GAN_AVAILABLE or gan_anomaly_detector is None:
        return jsonify({
            'is_anomaly': False,
            'reconstruction_error': 0.0,
            'anomaly_score': 0.0,
            'confidence': 0.0,
            'model_version': 'none',
            'error': 'AnomalyGAN 模型未加载，使用降级检测',
        })

    try:
        data = request.get_json(silent=True) or {}
        file_path = data.get('file_path', '')

        if not file_path:
            # 支持文件上传模式
            if 'file' not in request.files:
                return jsonify({'error': '未提供 file_path 或文件上传'}), 400
            file = request.files['file']
            import tempfile
            fd, tmp = tempfile.mkstemp(prefix='gan_scan_', suffix=os.path.splitext(file.filename or '')[-1])
            file.save(tmp)
            os.close(fd)
            file_path = tmp

        result = gan_anomaly_detector.detect(file_path)

        # 清理上传的临时文件
        if 'file' in request.files and os.path.exists(file_path):
            try:
                os.remove(file_path)
            except OSError:
                pass

        return jsonify({'code': 0, 'message': '检测成功', 'data': result})

    except Exception as e:
        logger.error('GAN 异常检测失败: %s', e)
        return jsonify({'code': 1, 'message': f'检测失败: {e}', 'data': None}), 500


@app.route('/api/gan/anomaly/batch', methods=['POST'])
def gan_anomaly_batch():
    """
    批量 GAN 异常检测
    POST { file_paths: [str, ...] }
    """
    if not GAN_AVAILABLE or gan_anomaly_detector is None:
        return jsonify({
            'code': 0,
            'message': 'AnomalyGAN 未加载，返回空结果',
            'data': {'results': [], 'total': 0}
        })

    try:
        data = request.get_json(silent=True) or {}
        file_paths = data.get('file_paths', [])
        if not file_paths:
            return jsonify({'error': 'file_paths 不能为空'}), 400

        results = gan_anomaly_detector.detect_batch(file_paths)
        anomaly_count = sum(1 for r in results if r.get('is_anomaly'))

        return jsonify({
            'code': 0,
            'message': '批量检测成功',
            'data': {'results': results, 'total': len(results), 'anomaly_count': anomaly_count}
        })

    except Exception as e:
        logger.error('GAN 批量检测失败: %s', e)
        return jsonify({'code': 1, 'message': f'批量检测失败: {e}', 'data': None}), 500


@app.route('/api/gan/adv-generate', methods=['POST'])
def gan_adv_generate():
    """
    生成对抗样本（红队测试）
    POST { file_path: str, n_variants?: int, eps?: float }
    """
    if not GAN_AVAILABLE or gan_adv_generator is None:
        return jsonify({
            'code': 1,
            'message': 'AdversarialGAN 模型未加载',
            'data': None
        })

    try:
        data = request.get_json(silent=True) or {}
        file_path = data.get('file_path', '')
        n_variants = int(data.get('n_variants') or 5)
        eps = float(data.get('eps') or 0.15)

        if not file_path:
            return jsonify({'error': 'file_path 不能为空'}), 400

        result = gan_adv_generator.generate(file_path, n_variants=n_variants, eps=eps)
        return jsonify({'code': 0, 'message': '生成成功', 'data': result})

    except Exception as e:
        logger.error('对抗样本生成失败: %s', e)
        return jsonify({'code': 1, 'message': f'生成失败: {e}', 'data': None}), 500


@app.route('/api/gan/model-status', methods=['GET'])
def gan_model_status():
    """查询 GAN 模型状态"""
    status = {
        'gan_available': GAN_AVAILABLE,
        'anomaly_gan': gan_anomaly_detector.get_status() if gan_anomaly_detector else {'loaded': False},
        'adversarial_gan': gan_adv_generator.get_status() if gan_adv_generator else {'loaded': False},
    }
    return jsonify({'code': 0, 'message': '查询成功', 'data': status})


@app.route('/api/gan/metrics', methods=['GET'])
def gan_metrics():
    """查询 GAN 监控指标"""
    metrics = {
        'anomaly_gan': gan_anomaly_detector.get_status() if gan_anomaly_detector else {},
        'adversarial_gan': gan_adv_generator.get_status() if gan_adv_generator else {},
        'note': '详细指标将在模型训练后填入',
    }
    return jsonify({'code': 0, 'message': '查询成功', 'data': metrics})


# ═══════════════════════════════════════════════════════════════
# Phase 3: 红队测试接口
# ═══════════════════════════════════════════════════════════════

@app.route('/api/gan/redteam/test', methods=['POST'])
def gan_redteam_test():
    """
    红队测试 — 生成对抗变体并测试 PromptGuard 逃逸率
    POST { base_prompt: str, n_variants: int=20, variant_types: list|null }
    """
    try:
        data = request.get_json(silent=True) or {}
        base_prompt = data.get('base_prompt', '你好，请帮我处理这个文件')
        n_variants = int(data.get('n_variants') or 20)
        variant_types = data.get('variant_types')

        tester = PromptGuardTester()
        result = tester.test(base_prompt, n_variants=n_variants,
                             variant_types=variant_types)

        return jsonify({
            'code': 0,
            'message': '红队测试完成',
            'data': result
        })
    except Exception as e:
        logger.error('红队测试失败: %s', e)
        return jsonify({'code': 1, 'message': f'红队测试失败: {e}', 'data': None}), 500


@app.route('/api/gan/redteam/report', methods=['GET'])
def gan_redteam_report():
    """查询最近一次红队测试报告"""
    try:
        tester = PromptGuardTester()
        report = tester.get_report()
        return jsonify({'code': 0, 'message': '查询成功', 'data': report})
    except Exception as e:
        return jsonify({'code': 1, 'message': str(e)}), 500


if __name__ == '__main__':
    logger.info('玄鉴安全智能体 AI微服务启动中...')
    logger.info('初始化AI模型...')

    # 预加载模型
    try:
        malware_detector.load_model()
        logger.info('恶意代码检测模型加载完成')
    except Exception as e:
        logger.warning(f'恶意代码检测模型加载失败（将使用规则引擎）: {str(e)}')

    try:
        poisoning_detector.load_model()
        logger.info('投毒检测模型加载完成')
    except Exception as e:
        logger.warning(f'投毒检测模型加载失败（将使用统计检测）: {str(e)}')

    port = int(os.getenv('AI_SERVICE_PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
