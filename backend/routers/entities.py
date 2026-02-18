from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

from database import get_db
from auth import get_current_user
from models.project import Project
from models.entity import Entity
from models.finding import Finding
from models.user import User

_ADMIN_EMAIL = "tcmherd@proton.me"

router = APIRouter(prefix="/projects/{project_id}/entities", tags=["entities"])


# --- Pydantic Schemas ---

class EntityCreate(BaseModel):
    entity_type: str = Field(..., max_length=50)
    value: str = Field(..., max_length=500)
    label: Optional[str] = Field(None, max_length=255)


class EntityResponse(BaseModel):
    id: str
    project_id: str
    entity_type: str
    value: str
    label: Optional[str]
    status: str
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingBrief(BaseModel):
    id: str
    tool_name: str
    tool_category: str
    summary: Optional[str]
    severity: str
    created_at: datetime

    model_config = {"from_attributes": True}


class EntityWithFindings(EntityResponse):
    findings: list[FindingBrief] = []


class RunEntityResponse(BaseModel):
    entity_id: str
    findings_created: int
    message: str


# --- Routes ---

@router.post("", response_model=EntityResponse, status_code=201)
def add_entity(project_id: str, payload: EntityCreate, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    valid_types = {"phone", "email", "username", "domain", "ip", "name", "social", "file"}
    if payload.entity_type not in valid_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid entity_type. Must be one of: {', '.join(sorted(valid_types))}",
        )

    entity = Entity(
        project_id=project_id,
        entity_type=payload.entity_type,
        value=payload.value,
        label=payload.label,
    )
    db.add(entity)
    db.commit()
    db.refresh(entity)
    return entity


@router.get("", response_model=list[EntityResponse])
def list_entities(project_id: str, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return db.query(Entity).filter(Entity.project_id == project_id).all()


@router.get("/{entity_id}", response_model=EntityWithFindings)
def get_entity(project_id: str, entity_id: str, db: Session = Depends(get_db)):
    entity = (
        db.query(Entity)
        .filter(Entity.id == entity_id, Entity.project_id == project_id)
        .first()
    )
    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")

    findings = db.query(Finding).filter(Finding.entity_id == entity_id).all()
    resp = EntityWithFindings.model_validate(entity)
    resp.findings = [FindingBrief.model_validate(f) for f in findings]
    return resp


@router.delete("/{entity_id}", status_code=204)
def delete_entity(project_id: str, entity_id: str, db: Session = Depends(get_db)):
    entity = (
        db.query(Entity)
        .filter(Entity.id == entity_id, Entity.project_id == project_id)
        .first()
    )
    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")
    db.delete(entity)
    db.commit()


@router.post("/{entity_id}/run", response_model=RunEntityResponse)
def run_entity(
    project_id: str,
    entity_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    entity = (
        db.query(Entity)
        .filter(Entity.id == entity_id, Entity.project_id == project_id)
        .first()
    )
    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")

    is_premium = (
        current_user.tier in ("pro", "enterprise")
        or current_user.email == _ADMIN_EMAIL
    )

    from services.osint_runner import OSINTRunner
    runner = OSINTRunner(db, is_premium=is_premium)
    result = runner.run_entity(entity_id)
    return RunEntityResponse(
        entity_id=entity_id,
        findings_created=result["findings_created"],
        message=result["message"],
    )
