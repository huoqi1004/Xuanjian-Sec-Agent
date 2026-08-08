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
        'knowledge_base_items': len(knowledge_base.items)
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
