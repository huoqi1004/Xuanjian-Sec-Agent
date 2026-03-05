"""
玄鉴安全智能体 - FastAPI 应用入口
AI驱动的企业级网络安全解决方案
"""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.api.v1.router import api_router
from app.database import init_db

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """应用生命周期管理"""
    # 启动时执行
    logger.info(f"Starting {settings.app_name} v{settings.app_version}")
    logger.info(f"Environment: {settings.environment}")
    
    # 初始化数据库
    init_db()
    logger.info("Database initialized")
    
    # 初始化Redis连接池
    # await init_redis()
    
    # 初始化Elasticsearch客户端
    # await init_elasticsearch()
    
    # 注册安全工具
    # await init_security_tools()
    
    logger.info("Application startup complete")
    
    yield
    
    # 关闭时执行
    logger.info("Shutting down application...")
    
    # 关闭数据库连接
    # await close_database()
    
    # 关闭Redis连接
    # await close_redis()
    
    logger.info("Application shutdown complete")


def create_app() -> FastAPI:
    """创建FastAPI应用实例"""
    app = FastAPI(
        title=settings.app_name,
        description="AI驱动的企业级网络安全解决方案，集成多种安全工具和AI模型，实现自动化安全防护",
        version=settings.app_version,
        docs_url="/api/docs" if settings.server.debug else None,
        redoc_url="/api/redoc" if settings.server.debug else None,
        openapi_url="/api/openapi.json" if settings.server.debug else None,
        lifespan=lifespan
    )
    
    # 配置CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.server.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # 注册API路由
    app.include_router(api_router, prefix="/api/v1")
    
    # 全局异常处理
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error(f"Unhandled exception: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "error_code": "INTERNAL_ERROR",
                "message": "服务器内部错误",
                "detail": str(exc) if settings.server.debug else None
            }
        )
    
    # 健康检查端点
    @app.get("/health", tags=["Health"])
    async def health_check():
        """健康检查"""
        return {
            "status": "healthy",
            "app_name": settings.app_name,
            "version": settings.app_version,
            "environment": settings.environment
        }
    
    # 根路径
    @app.get("/", tags=["Root"])
    async def root():
        """API根路径"""
        return {
            "name": settings.app_name,
            "version": settings.app_version,
            "description": "AI驱动的企业级网络安全解决方案",
            "docs": "/api/docs" if settings.server.debug else None
        }
    
    return app


# 创建应用实例
app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.server.host,
        port=settings.server.port,
        reload=settings.server.debug,
        workers=1 if settings.server.debug else settings.server.workers
    )
