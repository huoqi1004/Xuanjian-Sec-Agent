from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models import Base, Asset, Threat, Vulnerability, ThreatIntelligence, DefenseRule
import os

# 获取数据库路径
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./security_agent.db")

# 创建数据库引擎
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

# 创建会话工厂
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 依赖项，用于获取数据库会话
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# 初始化数据库
def init_db():
    # 创建所有表
    Base.metadata.create_all(bind=engine)
    
    # 初始化默认数据
    db = SessionLocal()
    try:
        # 检查是否已有数据
        if db.query(Asset).count() == 0:
            # 添加默认资产
            default_assets = [
                Asset(name="Web服务器", ip="192.168.1.100", type="服务器", status="在线", risk_level="低"),
                Asset(name="数据库服务器", ip="192.168.1.101", type="服务器", status="在线", risk_level="中"),
                Asset(name="防火墙", ip="192.168.1.1", type="安全设备", status="在线", risk_level="低"),
                Asset(name="交换机", ip="192.168.1.2", type="网络设备", status="在线", risk_level="低"),
                Asset(name="邮件服务器", ip="192.168.1.102", type="服务器", status="离线", risk_level="高"),
            ]
            db.add_all(default_assets)
        
        if db.query(DefenseRule).count() == 0:
            # 添加默认防御规则
            default_rules = [
                DefenseRule(rule_id="RULE-001", name="SQL注入防护", type="WAF", status="启用", priority="高", description="检测并阻止SQL注入攻击"),
                DefenseRule(rule_id="RULE-002", name="XSS防护", type="WAF", status="启用", priority="高", description="检测并阻止跨站脚本攻击"),
                DefenseRule(rule_id="RULE-003", name="DDoS防护", type="网络", status="启用", priority="高", description="检测并缓解DDoS攻击"),
                DefenseRule(rule_id="RULE-004", name="异常登录检测", type="身份认证", status="启用", priority="中", description="检测并阻止异常登录尝试"),
                DefenseRule(rule_id="RULE-005", name="恶意IP拦截", type="网络", status="启用", priority="中", description="拦截已知恶意IP地址"),
            ]
            db.add_all(default_rules)
        
        db.commit()
    except Exception as e:
        print(f"初始化数据库时出错: {e}")
        db.rollback()
    finally:
        db.close()