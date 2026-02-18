import logging
from sqlalchemy.orm import Session
from sqlalchemy import func

from models.entity import Entity
from models.project import Project

logger = logging.getLogger(__name__)


class CrossRefDetector:
    """
    Detects cross-references between entities across different investigations.

    For each entity run, it searches other projects for:
      1. Exact value+type matches (e.g., same email address in two investigations)
      2. Values extracted from tool raw_data (e.g., an email address found in WHOIS output)
    """

    def __init__(self, db: Session):
        self.db = db

    def detect_for_entity(
        self, entity: Entity, raw_findings: list[dict]
    ) -> list[dict]:
        """
        Return a list of cross-reference link dicts for this entity.
        Each dict: {entity_id, entity_type, entity_value, project_id, project_name, match_reason}
        """
        search_pairs = self._build_search_pairs(entity, raw_findings)
        links: list[dict] = []
        seen_entity_ids: set[str] = set()

        for etype, evalue, reason in search_pairs:
            try:
                matches = (
                    self.db.query(Entity, Project)
                    .join(Project, Entity.project_id == Project.id)
                    .filter(
                        func.lower(Entity.value) == evalue.lower(),
                        Entity.entity_type == etype,
                        Entity.project_id != entity.project_id,
                        Project.status != "archived",
                    )
                    .all()
                )
            except Exception as e:
                logger.warning(f"Cross-ref query failed for ({etype}, {evalue}): {e}")
                continue

            for ent, proj in matches:
                if ent.id not in seen_entity_ids:
                    seen_entity_ids.add(ent.id)
                    links.append({
                        "entity_id": ent.id,
                        "entity_type": ent.entity_type,
                        "entity_value": ent.value,
                        "project_id": proj.id,
                        "project_name": proj.name,
                        "match_reason": reason,
                    })

        if links:
            logger.info(
                f"Cross-ref: '{entity.value}' matched {len(links)} entity/entities "
                f"across {len({l['project_id'] for l in links})} other project(s)"
            )

        return links

    def _build_search_pairs(
        self, entity: Entity, raw_findings: list[dict]
    ) -> list[tuple[str, str, str]]:
        """
        Build (entity_type, value, reason) triples to query for cross-refs.
        """
        pairs: dict[tuple[str, str], str] = {}

        def add(etype: str, val: str, reason: str) -> None:
            val = val.strip()
            if val:
                key = (etype, val.lower())
                if key not in pairs:
                    pairs[key] = reason

        # Primary: the entity itself
        add(entity.entity_type, entity.value, f"Shared {entity.entity_type}")

        # Secondary: mine raw_data for extractable identifiers
        for finding in raw_findings:
            raw = finding.get("raw_data") or {}
            tool = finding.get("tool_name", "")

            # WHOIS emails field
            emails = raw.get("emails", [])
            if isinstance(emails, str):
                emails = [emails]
            for e in (emails or []):
                if isinstance(e, str) and "@" in e and len(e) < 255:
                    add("email", e, f"Email from {tool} WHOIS data")

            # WHOIS org / registrant name
            for key in ("org", "name"):
                val = raw.get(key)
                if isinstance(val, str) and 3 < len(val) < 120:
                    add("name", val, f"Org/name from {tool} WHOIS data")

            # IP-Geo: the queried IP itself (already covered by primary, but just in case)
            ip_val = raw.get("query")
            if isinstance(ip_val, str) and ip_val != entity.value:
                add("ip", ip_val, f"IP from {tool}")

            # VirusTotal / DomainRep: domain
            resource = raw.get("resource")
            if isinstance(resource, str) and "." in resource and resource != entity.value:
                add("domain", resource, f"Domain from {tool}")

            # EmailRep profiles (social handles)
            profiles = raw.get("profiles", [])
            for p in (profiles or []):
                if isinstance(p, str) and len(p) < 100:
                    add("username", p, f"Profile from {tool} EmailRep")

        return [(etype, val, reason) for (etype, val), reason in pairs.items()]
