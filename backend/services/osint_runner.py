import logging
from sqlalchemy.orm import Session

from models.entity import Entity
from models.finding import Finding
from services.tool_dispatcher import ToolDispatcher
from services.cross_ref import CrossRefDetector

logger = logging.getLogger(__name__)


class OSINTRunner:
    """Orchestrates OSINT tool execution across entities."""

    def __init__(self, db: Session, is_premium: bool = False):
        self.db = db
        self.is_premium = is_premium
        self.dispatcher = ToolDispatcher()
        self.cross_ref = CrossRefDetector(db)

    def run_project(self, project_id: str) -> dict:
        entities = self.db.query(Entity).filter(Entity.project_id == project_id).all()
        if not entities:
            return {
                "entities_processed": 0,
                "findings_created": 0,
                "message": "No entities found in project",
            }

        total_findings = 0
        for entity in entities:
            result = self._run_single_entity(entity)
            total_findings += result["findings_created"]

        tier_note = "premium tools included" if self.is_premium else "upgrade to premium for enriched results"
        return {
            "entities_processed": len(entities),
            "findings_created": total_findings,
            "message": (
                f"Processed {len(entities)} entities, created {total_findings} findings "
                f"({tier_note})"
            ),
        }

    def run_entity(self, entity_id: str) -> dict:
        entity = self.db.query(Entity).filter(Entity.id == entity_id).first()
        if not entity:
            return {"findings_created": 0, "message": "Entity not found"}
        return self._run_single_entity(entity)

    def _run_single_entity(self, entity: Entity) -> dict:
        entity.status = "running"
        self.db.commit()

        try:
            raw_findings = self.dispatcher.dispatch(
                entity.entity_type, entity.value, is_premium=self.is_premium
            )
        except Exception as e:
            logger.error(f"Dispatch failed for entity {entity.id}: {e}")
            entity.status = "failed"
            self.db.commit()
            return {"findings_created": 0, "message": f"Dispatch error: {str(e)}"}

        # Detect cross-references against other projects BEFORE committing findings
        # (so we don't self-match on findings just created in this same run)
        try:
            links = self.cross_ref.detect_for_entity(entity, raw_findings)
        except Exception as e:
            logger.warning(f"Cross-ref detection failed for entity {entity.id}: {e}")
            links = []

        findings_created = 0
        for raw in raw_findings:
            finding = Finding(
                entity_id=entity.id,
                tool_name=raw.get("tool_name", "unknown"),
                tool_category=raw.get("category", "unknown"),
                raw_data=raw.get("raw_data"),
                summary=raw.get("summary", ""),
                severity=raw.get("severity", "info"),
                tags=raw.get("tags"),
                links=links if links else None,
            )
            self.db.add(finding)
            findings_created += 1

        entity.status = "complete"
        self.db.commit()

        return {
            "findings_created": findings_created,
            "message": f"Created {findings_created} findings for entity {entity.value}",
        }
