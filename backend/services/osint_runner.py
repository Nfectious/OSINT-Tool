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
        all_entities = self.db.query(Entity).filter(Entity.project_id == project_id).all()
        if not all_entities:
            return {
                "entities_processed": 0,
                "findings_created": 0,
                "message": "No entities found in project",
            }

        # Only process entities that haven't completed yet — skip already-complete ones
        # so that adding a new target and re-running doesn't duplicate existing findings.
        pending = [e for e in all_entities if e.status not in ("complete",)]
        skipped = len(all_entities) - len(pending)

        total_findings = 0
        for entity in pending:
            result = self._run_single_entity(entity)
            total_findings += result["findings_created"]

        tier_note = "premium tools included" if self.is_premium else "upgrade to premium for enriched results"
        skip_note = f", {skipped} already-complete target(s) skipped" if skipped else ""
        return {
            "entities_processed": len(pending),
            "findings_created": total_findings,
            "message": (
                f"Processed {len(pending)} entities, created {total_findings} findings"
                f"{skip_note} ({tier_note})"
            ),
        }

    def run_entity(self, entity_id: str) -> dict:
        """Re-run a single entity — clears existing findings first for a clean refresh."""
        entity = self.db.query(Entity).filter(Entity.id == entity_id).first()
        if not entity:
            return {"findings_created": 0, "message": "Entity not found"}

        # Wipe old findings so re-run produces a clean, non-duplicated result
        self.db.query(Finding).filter(Finding.entity_id == entity_id).delete()
        entity.status = "pending"
        self.db.commit()

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
