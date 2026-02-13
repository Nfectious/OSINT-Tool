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
        entity_map = {e.id: e for e in entities}

        data_sections = []
        for entity in entities:
            entity_findings = [f for f in findings if f.entity_id == entity.id]
            if not entity_findings:
                continue

            findings_text = []
            for f in entity_findings:
                findings_text.append(
                    f"  - Tool: {f.tool_name} | Severity: {f.severity}\n"
                    f"    Summary: {f.summary or 'N/A'}\n"
                    f"    Data: {json.dumps(f.raw_data, default=str)[:500]}"
                )

            data_sections.append(
                f"Entity: {entity.entity_type} = {entity.value} "
                f"(label: {entity.label or 'N/A'})\n"
                + "\n".join(findings_text)
            )

        prompt = (
            "You are an OSINT analyst. Analyze the following intelligence data and produce:\n"
            "1. A SUMMARY of all findings\n"
            "2. Any RELATIONSHIPS between entities\n"
            "3. Any ANOMALIES or suspicious patterns\n"
            "4. Recommended LEADS for further investigation\n\n"
            "Format your response as JSON with keys: summary, relationships, anomalies, leads.\n"
            "Each should be a string with your analysis.\n\n"
            "=== INTELLIGENCE DATA ===\n\n"
            + "\n\n".join(data_sections)
        )
        return prompt

    def _call_ollama(self, prompt: str) -> str | None:
        url = f"{self.settings.OLLAMA_BASE_URL}/api/generate"
        payload = {
            "model": self.settings.OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
        }

        try:
            resp = requests.post(url, json=payload, timeout=120)
            resp.raise_for_status()
            data = resp.json()
            return data.get("response", "")
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
            # Find JSON in the response
            start = llm_response.find("{")
            end = llm_response.rfind("}") + 1
            if start >= 0 and end > start:
                parsed = json.loads(llm_response[start:end])
        except (json.JSONDecodeError, ValueError):
            logger.warning("Could not parse LLM response as JSON, using raw text")

        patterns = []
        pattern_types = {
            "summary": parsed.get("summary", llm_response[:1000]),
            "relationship": parsed.get("relationships", ""),
            "anomaly": parsed.get("anomalies", ""),
            "lead": parsed.get("leads", ""),
        }

        for ptype, description in pattern_types.items():
            if not description:
                continue
            pattern = Pattern(
                project_id=project_id,
                pattern_type=ptype,
                description=str(description),
                entities_involved=entity_ids,
                confidence=0.5,
                llm_model=model_name,
                raw_llm_output=llm_response,
            )
            self.db.add(pattern)
            patterns.append(pattern)

        self.db.commit()
        return patterns
