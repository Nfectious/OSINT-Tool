import requests
import logging
from tools.base_tool import BaseTool

logger = logging.getLogger(__name__)


class EmailRepTool(BaseTool):
    """Email reputation, breach flags, and social profiles via emailrep.io (free, no key)."""

    premium_only = True

    @property
    def name(self) -> str:
        return "EmailRep"

    @property
    def category(self) -> str:
        return "email"

    def run(self, entity_value: str) -> dict:
        url = f"https://emailrep.io/{entity_value}"
        headers = {
            "User-Agent": "Valkyrie-OSINT/1.0",
            "Accept": "application/json",
        }

        try:
            resp = requests.get(url, headers=headers, timeout=15)
        except requests.RequestException as e:
            return self._make_finding(
                raw_data={"error": str(e)},
                summary=f"EmailRep lookup failed: {e}",
                severity="error",
                tags=["error", "email", "reputation"],
            )

        if resp.status_code == 429:
            return self._make_finding(
                raw_data={"error": "Rate limited by emailrep.io"},
                summary="EmailRep: daily rate limit reached",
                severity="info",
                tags=["email", "reputation", "rate-limited"],
            )

        if resp.status_code != 200:
            return self._make_finding(
                raw_data={"error": f"HTTP {resp.status_code}", "body": resp.text[:300]},
                summary=f"EmailRep returned status {resp.status_code}",
                severity="error",
                tags=["error", "email", "reputation"],
            )

        data = resp.json()
        details = data.get("details", {})

        reputation = data.get("reputation", "unknown")
        suspicious = data.get("suspicious", False)
        references = data.get("references", 0)
        blacklisted = details.get("blacklisted", False)
        malicious_activity = details.get("malicious_activity", False)
        credentials_leaked = details.get("credentials_leaked", False)
        data_breach = details.get("data_breach", False)
        last_seen = details.get("last_seen", "never")
        domain_reputation = details.get("domain_reputation", "unknown")
        profiles = details.get("profiles", [])
        disposable = details.get("disposable", False)
        free_provider = details.get("free_provider", False)
        spam = details.get("spam", False)

        tags = ["email", "reputation", "emailrep"]
        if suspicious:
            tags.append("suspicious")
        if blacklisted:
            tags.append("blacklisted")
        if malicious_activity:
            tags.append("malicious-activity")
        if credentials_leaked:
            tags.append("credentials-leaked")
        if data_breach:
            tags.append("data-breach")
        if disposable:
            tags.append("disposable")
        if spam:
            tags.append("spam")

        if malicious_activity or blacklisted:
            severity = "high"
        elif suspicious or credentials_leaked or data_breach:
            severity = "medium"
        elif reputation in ("low", "none"):
            severity = "medium"
        else:
            severity = "info"

        notes = []
        if data_breach:
            notes.append("data breach detected")
        if credentials_leaked:
            notes.append("credentials leaked")
        if malicious_activity:
            notes.append("malicious activity")
        if spam:
            notes.append("spam activity")

        summary = (
            f"EmailRep: {reputation} reputation, "
            f"{'suspicious' if suspicious else 'clean'}, "
            f"{references} web references, last seen {last_seen}"
        )
        if notes:
            summary += f" | Alerts: {', '.join(notes)}"
        if profiles:
            summary += f" | Profiles: {', '.join(profiles[:5])}"

        return self._make_finding(
            raw_data={
                "email": entity_value,
                "reputation": reputation,
                "suspicious": suspicious,
                "references": references,
                "blacklisted": blacklisted,
                "malicious_activity": malicious_activity,
                "credentials_leaked": credentials_leaked,
                "data_breach": data_breach,
                "last_seen": last_seen,
                "domain_reputation": domain_reputation,
                "profiles": profiles,
                "disposable": disposable,
                "free_provider": free_provider,
                "spam": spam,
            },
            summary=summary,
            severity=severity,
            tags=tags,
        )
