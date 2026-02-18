from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

from database import get_db
from rate_limit import limiter
from auth import get_current_user_id, get_current_user
from models.project import Project
from models.user import User
from models.entity import Entity
from models.pattern import Pattern
from services.anon_stats import record_run, record_analysis, record_error

router = APIRouter(prefix="/projects", tags=["projects"])


# --- Pydantic Schemas ---

class ProjectCreate(BaseModel):
    name: str = Field(..., max_length=255)
    description: Optional[str] = None
    target_summary: Optional[str] = None


class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None
    target_summary: Optional[str] = None
    status: Optional[str] = None


class ProjectResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    target_summary: Optional[str]
    status: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ProjectWithEntities(ProjectResponse):
    entity_count: int = 0
    pattern_count: int = 0


class RunResponse(BaseModel):
    project_id: str
    entities_processed: int
    findings_created: int
    message: str


class AnalysisResponse(BaseModel):
    project_id: str
    patterns_created: int
    message: str


# --- Routes ---

@router.post("", response_model=ProjectResponse, status_code=201)
def create_project(payload: ProjectCreate, db: Session = Depends(get_db)):
    project = Project(
        name=payload.name,
        description=payload.description,
        target_summary=payload.target_summary,
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


@router.get("", response_model=list[ProjectResponse])
def list_projects(db: Session = Depends(get_db)):
    return db.query(Project).filter(Project.status != "archived").all()


@router.get("/{project_id}", response_model=ProjectWithEntities)
def get_project(project_id: str, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    entity_count = db.query(Entity).filter(Entity.project_id == project_id).count()
    pattern_count = db.query(Pattern).filter(Pattern.project_id == project_id).count()
    resp = ProjectWithEntities.model_validate(project)
    resp.entity_count = entity_count
    resp.pattern_count = pattern_count
    return resp


@router.put("/{project_id}", response_model=ProjectResponse)
def update_project(project_id: str, payload: ProjectUpdate, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    update_data = payload.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(project, key, value)
    db.commit()
    db.refresh(project)
    return project


@router.delete("/{project_id}", response_model=ProjectResponse)
def delete_project(project_id: str, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    project.status = "archived"
    db.commit()
    db.refresh(project)
    return project


_ADMIN_EMAIL = "tcmherd@proton.me"


@router.post("/{project_id}/run", response_model=RunResponse)
@limiter.limit("10/minute")
def run_project(
    project_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    is_premium = (
        current_user.tier in ("pro", "enterprise")
        or current_user.email == _ADMIN_EMAIL
    )

    entities = db.query(Entity).filter(Entity.project_id == project_id).all()
    entity_types = [e.entity_type for e in entities]

    from services.osint_runner import OSINTRunner
    runner = OSINTRunner(db, is_premium=is_premium)
    try:
        result = runner.run_project(project_id)
    except Exception as exc:
        record_error()
        raise exc
    record_run(entity_types)
    return RunResponse(
        project_id=project_id,
        entities_processed=result["entities_processed"],
        findings_created=result["findings_created"],
        message=result["message"],
    )


@router.post("/{project_id}/analyze", response_model=AnalysisResponse)
@limiter.limit("10/minute")
def analyze_project(project_id: str, request: Request, db: Session = Depends(get_db), user_id: str = Depends(get_current_user_id)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    from services.llm_analyzer import LLMAnalyzer
    analyzer = LLMAnalyzer(db)
    try:
        result = analyzer.analyze_project(project_id)
    except Exception as exc:
        record_error()
        raise exc
    record_analysis()
    return AnalysisResponse(
        project_id=project_id,
        patterns_created=result["patterns_created"],
        message=result["message"],
    )


@router.get("/{project_id}/report")
def get_project_report(project_id: str, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    entities = db.query(Entity).filter(Entity.project_id == project_id).all()
    patterns = db.query(Pattern).filter(Pattern.project_id == project_id).all()

    entity_reports = []
    total_links = 0
    for entity in entities:
        findings = [
            {
                "id": f.id,
                "tool_name": f.tool_name,
                "tool_category": f.tool_category,
                "summary": f.summary,
                "severity": f.severity,
                "tags": f.tags,
                "raw_data": f.raw_data,
                "links": f.links or [],
                "created_at": f.created_at.isoformat() if f.created_at else None,
            }
            for f in entity.findings
        ]
        total_links += sum(len(f["links"]) for f in findings if f["links"])
        entity_reports.append({
            "id": entity.id,
            "entity_type": entity.entity_type,
            "value": entity.value,
            "label": entity.label,
            "status": entity.status,
            "findings": findings,
        })

    pattern_reports = [
        {
            "id": p.id,
            "pattern_type": p.pattern_type,
            "description": p.description,
            "confidence": p.confidence,
            "entities_involved": p.entities_involved,
            "llm_model": p.llm_model,
            "created_at": p.created_at.isoformat() if p.created_at else None,
        }
        for p in patterns
    ]

    return {
        "project": {
            "id": project.id,
            "name": project.name,
            "description": project.description,
            "target_summary": project.target_summary,
            "status": project.status,
            "created_at": project.created_at.isoformat() if project.created_at else None,
        },
        "entities": entity_reports,
        "patterns": pattern_reports,
        "summary": {
            "total_entities": len(entities),
            "total_findings": sum(len(e.findings) for e in entities),
            "total_patterns": len(patterns),
            "total_links": total_links,
        },
    }
