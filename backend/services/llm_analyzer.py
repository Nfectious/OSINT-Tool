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
        target_descriptions = []
        for entity in entities:
            target_descriptions.append(f"{entity.entity_type}: {entity.value}")
        targets_str = ", ".join(target_descriptions)

        data_sections = []
        for entity in entities:
            entity_findings = [f for f in findings if f.entity_id == entity.id]
            if not entity_findings:
                continue

            findings_text = []
            for f in entity_findings:
                raw_snippet = json.dumps(f.raw_data, default=str)[:800] if f.raw_data else "N/A"
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

        prompt = (
            f"You are a senior OSINT intelligence analyst. Analyze these OSINT findings "
            f"for targets [{targets_str}].\n\n"
            "Detect patterns, risks, entity links, and threat indicators.\n\n"
            "Produce your response as a JSON object with exactly these keys:\n"
            '- "risk_score": one of "low", "medium", "high", or "critical"\n'
            '- "summary": a detailed paragraph summarizing all findings and their significance\n'
            '- "relationships": entity links and connections discovered between targets or data points\n'
            '- "anomalies": suspicious patterns, inconsistencies, or red flags\n'
            '- "leads": recommended next steps for further investigation\n'
            '- "recommendations": actionable security or investigative recommendations\n\n'
            "Be specific. Reference actual data from the findings. Do not fabricate information.\n\n"
            "=== INTELLIGENCE DATA ===\n\n"
            + "\n\n".join(data_sections)
            + "\n\n=== END DATA ===\n\n"
            "Respond with ONLY the JSON object, no markdown formatting."
        )
        return prompt

    def _call_ollama(self, prompt: str) -> str | None:
        url = f"{self.settings.OLLAMA_BASE_URL}/api/generate"
        payload = {
            "model": self.settings.OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.3,
                "num_predict": 2048,
            },
        }

        try:
            logger.info(f"Calling Ollama at {url} with model {self.settings.OLLAMA_MODEL}")
            resp = requests.post(url, json=payload, timeout=300)
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

        # Standard pattern types
        pattern_mapping = {
            "summary": parsed.get("summary", llm_response[:1500] if not parsed else ""),
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
