from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

from database import get_db
from rate_limit import limiter
from auth import get_current_user_id
from models.project import Project
from models.pattern import Pattern
from models.entity import Entity
from models.finding import Finding

router = APIRouter(tags=["analysis"])


# --- Pydantic Schemas ---

class PatternResponse(BaseModel):
    id: str
    project_id: str
    pattern_type: str
    description: Optional[str]
    entities_involved: Optional[list | dict]
    confidence: float
    llm_model: Optional[str]
    raw_llm_output: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class AnalysisResponse(BaseModel):
    project_id: str
    patterns_created: int
    message: str


# --- Routes ---

@router.post("/projects/{project_id}/analyze", response_model=AnalysisResponse)
@limiter.limit("10/minute")
def analyze_project(project_id: str, request: Request, db: Session = Depends(get_db), user_id: str = Depends(get_current_user_id)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    from services.llm_analyzer import LLMAnalyzer
    analyzer = LLMAnalyzer(db)
    result = analyzer.analyze_project(project_id)
    return AnalysisResponse(
        project_id=project_id,
        patterns_created=result["patterns_created"],
        message=result["message"],
    )


@router.get("/projects/{project_id}/patterns", response_model=list[PatternResponse])
def list_patterns(project_id: str, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return db.query(Pattern).filter(Pattern.project_id == project_id).all()


@router.get("/projects/{project_id}/summary")
def get_project_summary(project_id: str, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    entities = db.query(Entity).filter(Entity.project_id == project_id).all()
    entity_ids = [e.id for e in entities]

    findings = []
    if entity_ids:
        findings = db.query(Finding).filter(Finding.entity_id.in_(entity_ids)).all()

    patterns = db.query(Pattern).filter(Pattern.project_id == project_id).all()

    # Build summary from existing patterns
    summary_patterns = [p for p in patterns if p.pattern_type == "summary"]
    summary_text = summary_patterns[0].description if summary_patterns else "No AI summary generated yet. Run POST /api/v1/projects/{id}/analyze to generate."

    severity_counts = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    entity_type_counts = {}
    for e in entities:
        entity_type_counts[e.entity_type] = entity_type_counts.get(e.entity_type, 0) + 1

    return {
        "project_id": project_id,
        "project_name": project.name,
        "summary": summary_text,
        "statistics": {
            "total_entities": len(entities),
            "total_findings": len(findings),
            "total_patterns": len(patterns),
            "severity_breakdown": severity_counts,
            "entity_type_breakdown": entity_type_counts,
        },
    }
