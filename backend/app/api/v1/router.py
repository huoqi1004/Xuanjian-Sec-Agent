"""
玄鉴安全智能体 - API路由聚合
整合所有API端点
"""

from fastapi import APIRouter

from .dashboard import router as dashboard_router
from .assets import router as assets_router
from .threats import router as threats_router
from .vulnerabilities import router as vulnerabilities_router
from .defense import router as defense_router
from .forensics import router as forensics_router
from .workflow import router as workflow_router
from .ai import router as ai_router
from .security import router as security_router
from .local_defense import router as local_defense_router
from .advanced_defense import router as advanced_defense_router

api_router = APIRouter()

# 注册各模块路由
api_router.include_router(dashboard_router, prefix="/dashboard", tags=["Dashboard"])
api_router.include_router(assets_router, prefix="/assets", tags=["Assets"])
api_router.include_router(threats_router, prefix="/threats", tags=["Threats"])
api_router.include_router(vulnerabilities_router, prefix="/vulns", tags=["Vulnerabilities"])
api_router.include_router(defense_router, prefix="/defense", tags=["Defense"])
api_router.include_router(local_defense_router, prefix="/local-defense", tags=["Local Defense"])
api_router.include_router(advanced_defense_router, prefix="/advanced-defense", tags=["Advanced Defense"])
api_router.include_router(forensics_router, prefix="/forensics", tags=["Forensics"])
api_router.include_router(workflow_router, prefix="/workflow", tags=["Workflow"])
api_router.include_router(ai_router, prefix="/ai", tags=["AI"])
api_router.include_router(security_router, prefix="/security", tags=["Security Tools"])
