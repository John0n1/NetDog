from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import structlog
from app.config import get_settings
from app.database import init_db
from app.api import scans, devices, vulnerabilities, netutil, auth, logs
from app.api import metrics

settings = get_settings()
logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle events"""
    # Startup
    logger.info("application_starting", version=settings.version)
    await init_db()
    logger.info("database_initialized")
    yield
    # Shutdown
    logger.info("application_stopping")


app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="Network Security Scanner with Vulnerability Assessment",
    lifespan=lifespan,
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],  # Frontend URLs
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(scans.router, prefix="/api/v1", tags=["Scans"])
app.include_router(devices.router, prefix="/api/v1", tags=["Devices"])
app.include_router(vulnerabilities.router, prefix="/api/v1", tags=["Vulnerabilities"])
app.include_router(netutil.router, prefix="/api/v1/netutil", tags=["Network Utilities"])
app.include_router(logs.router, prefix="/api/v1", tags=["Logs"])
app.include_router(metrics.router, prefix="/api/v1", tags=["Metrics"])


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": settings.app_name,
        "version": settings.version,
        "status": "operational",
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler"""
    logger.error("unhandled_exception", error=str(exc), path=str(request.url))
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )
