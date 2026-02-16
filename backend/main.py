import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from database import create_all_tables
from rate_limit import limiter
from routers.auth import router as auth_router
from routers.projects import router as projects_router
from routers.entities import router as entities_router
from routers.findings import router as findings_router
from routers.analysis import router as analysis_router
from routers.stats import router as stats_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting Valkyrie OSINT Operating System...")
    create_all_tables()
    logger.info("Database tables created/verified.")
    yield
    logger.info("Shutting down Valkyrie OSINT Operating System.")


app = FastAPI(
    title="Valkyrie OSINT Operating System",
    version="1.0.0",
    description="Automated OSINT intelligence gathering and analysis platform.",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount routers under /api/v1
app.include_router(auth_router, prefix="/api/v1")
app.include_router(projects_router, prefix="/api/v1")
app.include_router(entities_router, prefix="/api/v1")
app.include_router(findings_router, prefix="/api/v1")
app.include_router(analysis_router, prefix="/api/v1")
app.include_router(stats_router, prefix="/api/v1")


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "valkyrie-osint", "version": "1.0.0"}


@app.get("/")
def root():
    return {
        "name": "Valkyrie OSINT Operating System",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health",
        "api": "/api/v1",
    }
