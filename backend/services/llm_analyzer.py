import json
import logging
import requests
from sqlalchemy.orm import Session

from config import get_settings
from models.entity import Entity
from models.finding import Finding
from models.pattern import Pattern

logger = logging.getLogger(__name__)


class LLMAnalyzer:
    """Analyzes OSINT findings using a local Ollama LLM."""

    def __init__(self, db: Session):
        self.db = db
        self.settings = get_settings()

    def analyze_project(self, project_id: str) -> dict:
        entities = self.db.query(Entity).filter(Entity.project_id == project_id).all()
        if not entities:
            return {"patterns_created": 0, "message": "No entities to analyze"}

        entity_ids = [e.id for e in entities]
        findings = (
            self.db.query(Finding).filter(Finding.entity_id.in_(entity_ids)).all()
        )

        if not findings:
            return {"patterns_created": 0, "message": "No findings to analyze"}

        # Clear previous patterns for re-analysis
        self.db.query(Pattern).filter(Pattern.project_id == project_id).delete()
        self.db.flush()

        prompt = self._build_prompt(entities, findings)
        llm_response = self._call_ollama(prompt)

        if not llm_response:
            return {"patterns_created": 0, "message": "LLM analysis failed"}

        patterns = self._parse_and_store_patterns(project_id, entities, llm_response)
        return {
            "patterns_created": len(patterns),
            "message": f"Generated {len(patterns)} patterns from LLM analysis",
        }

    def _build_prompt(self, entities: list[Entity], findings: list[Finding]) -> str:
        # Cap entities shown in prompt to stay under model context window
        MAX_ENTITIES = 8
        MAX_FINDINGS_PER_ENTITY = 2
        MAX_FINDINGS_TOTAL = 15
        RAW_SNIPPET_LEN = 150

        # Severity priority order for selecting most important findings
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "error": 5}

        # Sort all findings by severity, take top MAX_FINDINGS_TOTAL
        sorted_findings = sorted(findings, key=lambda f: sev_order.get(f.severity, 9))
        top_findings = sorted_findings[:MAX_FINDINGS_TOTAL]
        top_finding_ids = {f.id for f in top_findings}

        # Take top MAX_ENTITIES entities that have findings in the top set
        entities_with_findings = [
            e for e in entities
            if any(f.entity_id == e.id for f in top_findings)
        ][:MAX_ENTITIES]

        target_descriptions = [f"{e.entity_type}: {e.value}" for e in entities_with_findings]
        targets_str = ", ".join(target_descriptions) if target_descriptions else "multiple targets"

        if len(entities) > MAX_ENTITIES:
            targets_str += f" (+ {len(entities) - MAX_ENTITIES} more entities, showing top {MAX_ENTITIES} by finding severity)"

        data_sections = []
        for entity in entities_with_findings:
            entity_findings = [f for f in top_findings if f.entity_id == entity.id]
            entity_findings = entity_findings[:MAX_FINDINGS_PER_ENTITY]
            if not entity_findings:
                continue

            findings_text = []
            for f in entity_findings:
                raw_snippet = json.dumps(f.raw_data, default=str)[:RAW_SNIPPET_LEN] if f.raw_data else "N/A"
                findings_text.append(
                    f"  - Tool: {f.tool_name} | Severity: {f.severity}\n"
                    f"    Summary: {f.summary or 'N/A'}\n"
                    f"    Data: {raw_snippet}"
                )

            data_sections.append(
                f"Entity: {entity.entity_type} = {entity.value} "
                f"(label: {entity.label or 'N/A'})\n"
                + "\n".join(findings_text)
            )

        total_findings = len(findings)
        shown_findings = len(top_findings)
        scope_note = (
            f"(Showing top {shown_findings} of {total_findings} total findings by severity)"
            if total_findings > shown_findings else f"({total_findings} total findings)"
        )

        cross_ref_section = self._build_cross_ref_section(entities)
        intra_links_section = self._build_intra_project_links(entities, findings)

        prompt = (
            f"You are a senior OSINT intelligence analyst. Analyze these OSINT findings "
            f"for targets [{targets_str}]. {scope_note}\n\n"
            "Detect patterns, risks, connections between targets, and threat indicators. "
            "Pay close attention to shared data (same phone in multiple tools, "
            "same email in WHOIS and breach data, shared addresses, etc.).\n\n"
            "Respond with ONLY a JSON object containing exactly these keys:\n"
            '{\n'
            '  "risk_score": "low"|"medium"|"high"|"critical",\n'
            '  "summary": "detailed paragraph summarizing all findings and how targets connect",\n'
            '  "relationships": "specific connections found between targets — shared data, overlapping identifiers, common associations",\n'
            '  "anomalies": "suspicious patterns, inconsistencies, or red flags",\n'
            '  "leads": "recommended next investigation steps based on the connections found",\n'
            '  "recommendations": "actionable security or investigative recommendations"\n'
            '}\n\n'
            "Be specific. Reference actual values from the data. Do not fabricate.\n\n"
            "=== INTELLIGENCE DATA ===\n\n"
            + "\n\n".join(data_sections)
            + "\n\n=== END DATA ==="
            + (f"\n\n=== CONNECTIONS WITHIN THIS INVESTIGATION ===\n{intra_links_section}\n=== END CONNECTIONS ===" if intra_links_section else "")
            + (f"\n\n=== CROSS-REFERENCES (other investigations) ===\n{cross_ref_section}\n=== END CROSS-REFERENCES ===" if cross_ref_section else "")
            + "\n\nRespond with ONLY the JSON object. No markdown, no explanation."
        )
        return prompt

    def _build_intra_project_links(self, entities: list[Entity], findings: list[Finding]) -> str:
        """
        Detect connections between entities within this project by mining shared
        values in their findings raw_data (e.g., same email in WHOIS + breach data,
        shared org name across two domain lookups, same area code across phones).
        """
        connections: list[str] = []

        # Build a lookup of entity values (lowercased) to entity labels
        entity_map = {e.id: e for e in entities}

        # Collect extractable values per entity from raw_data
        entity_extracted: dict[str, set[str]] = {e.id: set() for e in entities}
        for finding in findings:
            raw = finding.raw_data or {}
            eid = finding.entity_id
            if eid not in entity_extracted:
                continue

            # Pull notable identifiers from raw data
            for key in ("emails", "email"):
                val = raw.get(key)
                if isinstance(val, list):
                    entity_extracted[eid].update(v.lower() for v in val if isinstance(v, str) and "@" in v)
                elif isinstance(val, str) and "@" in val:
                    entity_extracted[eid].add(val.lower())

            for key in ("org", "name", "registrar"):
                val = raw.get(key)
                if isinstance(val, str) and 3 < len(val) < 80:
                    entity_extracted[eid].add(f"org:{val.lower()}")

            for key in ("isp", "asname"):
                val = raw.get(key)
                if isinstance(val, str) and 3 < len(val) < 80:
                    entity_extracted[eid].add(f"isp:{val.lower()}")

            # Area code from phone values
            parent_entity = entity_map.get(eid)
            if parent_entity and parent_entity.entity_type == "phone":
                phone = parent_entity.value.replace("+", "").replace(" ", "")
                if len(phone) >= 10:
                    entity_extracted[eid].add(f"areacode:{phone[1:4] if phone.startswith('1') else phone[:3]}")

            # Country code from ip-api data
            cc = raw.get("country_code")
            if isinstance(cc, str) and len(cc) == 2:
                entity_extracted[eid].add(f"country:{cc.lower()}")

            # Email domain
            email_val = entity_map.get(eid)
            if email_val and email_val.entity_type == "email" and "@" in email_val.value:
                domain = email_val.value.split("@", 1)[1].lower()
                if domain not in ("gmail.com", "yahoo.com", "hotmail.com", "outlook.com"):
                    entity_extracted[eid].add(f"domain:{domain}")

        # Find pairs of entities that share extracted values
        entity_ids = list(entity_extracted.keys())
        seen_pairs: set[frozenset] = set()
        for i, eid_a in enumerate(entity_ids):
            for eid_b in entity_ids[i + 1:]:
                shared = entity_extracted[eid_a] & entity_extracted[eid_b]
                if not shared:
                    continue
                pair_key = frozenset([eid_a, eid_b])
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)
                ea = entity_map[eid_a]
                eb = entity_map[eid_b]
                for sv in list(shared)[:3]:  # cap per pair to keep prompt short
                    label = sv.split(":", 1)[1] if ":" in sv else sv
                    kind = sv.split(":", 1)[0] if ":" in sv else "value"
                    connections.append(
                        f"  - [{ea.entity_type}: {ea.value}] ↔ [{eb.entity_type}: {eb.value}]"
                        f" share {kind} '{label}'"
                    )

        if not connections:
            return ""

        header = f"Found {len(connections)} internal connection(s) between targets in this investigation:"
        return header + "\n" + "\n".join(connections[:20])  # cap at 20

    def _build_cross_ref_section(self, entities: list[Entity]) -> str:
        """Summarise cross-investigation links for inclusion in the LLM prompt."""
        entity_ids = [e.id for e in entities]
        try:
            findings_with_links = (
                self.db.query(Finding)
                .filter(
                    Finding.entity_id.in_(entity_ids),
                    Finding.links.isnot(None),
                )
                .all()
            )
        except Exception:
            return ""

        seen: set[str] = set()
        all_links: list[dict] = []
        for f in findings_with_links:
            for link in (f.links or []):
                key = link.get("entity_id", "")
                if key and key not in seen:
                    seen.add(key)
                    all_links.append(link)

        if not all_links:
            return ""

        lines = [
            f"This investigation has {len(all_links)} cross-reference(s) to other investigations:",
        ]
        for link in all_links[:10]:  # cap to stay within context budget
            lines.append(
                f"  - {link.get('entity_type')} '{link.get('entity_value')}' "
                f"also appears in project '{link.get('project_name')}' "
                f"({link.get('match_reason', 'value match')})"
            )
        if len(all_links) > 10:
            lines.append(f"  ... and {len(all_links) - 10} more cross-reference(s).")
        lines.append(
            "Factor these cross-references into your analysis. "
            "If the same entity appears in multiple investigations, this may indicate "
            "a pattern, shared infrastructure, or a recurring threat actor."
        )
        return "\n".join(lines)

    def _call_ollama(self, prompt: str) -> str | None:
        url = f"{self.settings.OLLAMA_BASE_URL}/api/generate"
        payload = {
            "model": self.settings.OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.3,
                "num_predict": 1024,
                "num_ctx": 8192,  # Override default 4096 context to prevent prompt truncation
            },
        }

        try:
            logger.info(f"Calling Ollama at {url} with model {self.settings.OLLAMA_MODEL}")
            resp = requests.post(url, json=payload, timeout=600)
            resp.raise_for_status()
            data = resp.json()
            response_text = data.get("response", "")
            logger.info(f"Ollama response length: {len(response_text)} chars")
            return response_text
        except requests.RequestException as e:
            logger.error(f"Ollama API call failed: {e}")
            return None

    def _parse_and_store_patterns(
        self, project_id: str, entities: list[Entity], llm_response: str
    ) -> list[Pattern]:
        entity_ids = [e.id for e in entities]
        model_name = self.settings.OLLAMA_MODEL

        # Try to parse JSON response
        parsed = {}
        try:
            # Find JSON in the response (skip any markdown fences)
            text = llm_response
            if "```json" in text:
                text = text.split("```json", 1)[1]
                text = text.split("```", 1)[0]
            elif "```" in text:
                text = text.split("```", 1)[1]
                text = text.split("```", 1)[0]

            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                parsed = json.loads(text[start:end])
                logger.info(f"Parsed LLM JSON with keys: {list(parsed.keys())}")
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Could not parse LLM response as JSON: {e}, using raw text")

        patterns = []

        # Risk score stored as its own pattern type
        risk_score = parsed.get("risk_score", "unknown")
        if isinstance(risk_score, str) and risk_score.lower() in ("low", "medium", "high", "critical"):
            confidence_map = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 0.95}
            risk_pattern = Pattern(
                project_id=project_id,
                pattern_type="risk_score",
                description=risk_score.lower(),
                entities_involved=entity_ids,
                confidence=confidence_map.get(risk_score.lower(), 0.5),
                llm_model=model_name,
                raw_llm_output=llm_response,
            )
            self.db.add(risk_pattern)
            patterns.append(risk_pattern)

        # Standard pattern types — only use fallback raw text if JSON fully failed
        fallback_summary = llm_response[:800] if not parsed and llm_response.startswith(("{", "[")) else ""
        pattern_mapping = {
            "summary": parsed.get("summary", fallback_summary),
            "relationship": parsed.get("relationships", ""),
            "anomaly": parsed.get("anomalies", ""),
            "lead": parsed.get("leads", ""),
            "recommendation": parsed.get("recommendations", ""),
        }

        for ptype, description in pattern_mapping.items():
            if not description:
                continue
            desc_str = str(description).strip()
            if not desc_str or desc_str.lower() in ("none", "n/a", "null", ""):
                continue
            pattern = Pattern(
                project_id=project_id,
                pattern_type=ptype,
                description=desc_str,
                entities_involved=entity_ids,
                confidence=0.6,
                llm_model=model_name,
                raw_llm_output=llm_response,
            )
            self.db.add(pattern)
            patterns.append(pattern)

        self.db.commit()
        return patterns
