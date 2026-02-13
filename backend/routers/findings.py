from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

from database import get_db
from models.finding import Finding

router = APIRouter(tags=["findings"])


# --- Pydantic Schemas ---

class FindingResponse(BaseModel):
    id: str
    entity_id: str
    tool_name: str
    tool_category: str
    raw_data: Optional[dict]
    summary: Optional[str]
    severity: str
    tags: Optional[list]
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingBriefResponse(BaseModel):
    id: str
    entity_id: str
    tool_name: str
    tool_category: str
    summary: Optional[str]
    severity: str
    created_at: datetime

    model_config = {"from_attributes": True}


# --- Routes ---

@router.get("/entities/{entity_id}/findings", response_model=list[FindingBriefResponse])
def list_findings(entity_id: str, db: Session = Depends(get_db)):
    findings = db.query(Finding).filter(Finding.entity_id == entity_id).all()
    return findings


@router.get("/findings/{finding_id}", response_model=FindingResponse)
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding
