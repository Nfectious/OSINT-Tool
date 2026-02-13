import logging
import whois
from tools.base_tool import BaseTool

logger = logging.getLogger(__name__)


class WHOISTool(BaseTool):
    """Performs WHOIS lookups on domains and IP addresses."""

    @property
    def name(self) -> str:
        return "WHOIS"

    @property
    def category(self) -> str:
        return "network"

    def run(self, entity_value: str) -> dict:
        try:
            w = whois.whois(entity_value)
        except Exception as e:
            return self._make_finding(
                raw_data={"error": str(e), "query": entity_value},
                summary=f"WHOIS lookup failed for {entity_value}: {str(e)}",
                severity="error",
                tags=["error", "network", "whois"],
            )

        # Convert whois object to serializable dict
        raw_data = {}
        fields = [
            "domain_name", "registrar", "whois_server", "referral_url",
            "updated_date", "creation_date", "expiration_date",
            "name_servers", "status", "emails", "dnssec",
            "name", "org", "address", "city", "state", "country",
            "registrant_postal_code",
        ]
        for key in fields:
            val = getattr(w, key, None)
            if val is not None:
                if isinstance(val, list):
                    raw_data[key] = [str(v) for v in val]
                else:
                    raw_data[key] = str(val)

        registrar = raw_data.get("registrar", "Unknown")
        creation = raw_data.get("creation_date", "Unknown")
        expiry = raw_data.get("expiration_date", "Unknown")
        org = raw_data.get("org", "Unknown")
        country = raw_data.get("country", "Unknown")
        name_servers = raw_data.get("name_servers", [])
        dnssec = raw_data.get("dnssec", "Unknown")

        summary = (
            f"Domain registered by {org} via {registrar}, "
            f"created {creation}"
        )

        return self._make_finding(
            raw_data=raw_data,
            summary=summary,
            severity="info",
            tags=["domain", "whois", "network"],
        )
