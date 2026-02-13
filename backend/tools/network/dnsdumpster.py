import logging
import dns.resolver
from tools.base_tool import BaseTool

logger = logging.getLogger(__name__)


class DNSDumpsterTool(BaseTool):
    """Performs DNS enumeration for a domain using dnspython."""

    @property
    def name(self) -> str:
        return "DNSDumpster"

    @property
    def category(self) -> str:
        return "network"

    def run(self, entity_value: str) -> dict:
        records = {}
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(entity_value, rtype)
                records[rtype] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.NXDOMAIN:
                return self._make_finding(
                    raw_data={"error": f"Domain {entity_value} does not exist (NXDOMAIN)"},
                    summary=f"DNS: Domain {entity_value} does not exist",
                    severity="info",
                    tags=["network", "dns", "nxdomain"],
                )
            except dns.resolver.NoNameservers:
                continue
            except Exception as e:
                logger.warning(f"DNS query {rtype} for {entity_value} failed: {e}")
                continue

        if not records:
            return self._make_finding(
                raw_data={"domain": entity_value, "records": {}},
                summary=f"DNS enumeration returned no records for {entity_value}",
                severity="info",
                tags=["network", "dns"],
            )

        raw_data = {
            "domain": entity_value,
            "records": records,
            "record_types_found": list(records.keys()),
            "total_records": sum(len(v) for v in records.values()),
        }

        summary_parts = []
        for rtype, values in records.items():
            summary_parts.append(f"{rtype}: {', '.join(values[:3])}")

        summary = f"DNS for {entity_value}: " + " | ".join(summary_parts[:5])

        return self._make_finding(
            raw_data=raw_data,
            summary=summary,
            severity="info",
            tags=["network", "dns", "enumeration"],
        )
