from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.scanner import router as scanner_router
from app.api.assessment import router as assessment_router
from app.api.instructions import router as instructions_router
from app.api.scope import router as scope_router
from app.api.proposals import router as proposals_router
from app.api.integrations import router as integrations_router

from app.core.database import Base, SessionLocal, engine
from app.models import (
    Project, Transcript, TranscriptEvent, InstructionDefinition,
    InstructionExecution, ScopeRevision, ScanExecution,
    ActionProposalVersion, ActionApproval, ToolIntegration,
    ToolIntegrationVersion,
)
from app.services.instruction_library import seed_builtin_instructions


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Development bootstrap only; use Alembic migrations before production.
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_builtin_instructions(db)
    finally:
        db.close()
    yield


app = FastAPI(
    title="SENTINEL",
    description="Adaptive Security Assessment Platform",
    version="0.5.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scanner_router)
app.include_router(assessment_router)
app.include_router(instructions_router)
app.include_router(scope_router)
app.include_router(proposals_router)
app.include_router(integrations_router)


@app.get("/")
async def root():
    return {"name": "SENTINEL", "status": "operational", "version": "0.5.0"}


@app.get("/health")
async def health():
    return {"status": "healthy"}
