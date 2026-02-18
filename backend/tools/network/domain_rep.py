import requests
import logging
from tools.base_tool import BaseTool

logger = logging.getLogger(__name__)


class DomainRepTool(BaseTool):
    """Domain reputation via HackerTarget DNSBL check and URLScan.io (free, no key)."""

    premium_only = True

    @property
    def name(self) -> str:
        return "DomainRep"

    @property
    def category(self) -> str:
        return "network"

    def run(self, entity_value: str) -> dict:
        results: dict = {}
        tags = ["domain", "reputation"]
        severity = "info"

        # 1. HackerTarget DNS Blacklist check
        try:
            ht_resp = requests.get(
                "https://api.hackertarget.com/dnsbl/",
                params={"q": entity_value},
                timeout=15,
            )
            if ht_resp.status_code == 200:
                dnsbl_text = ht_resp.text.strip()
                listed_on = [
                    line.split(" ")[0]
                    for line in dnsbl_text.splitlines()
                    if "listed" in line.lower()
                ]
                results["dnsbl"] = {
                    "raw": dnsbl_text[:1000],
                    "listed_on": listed_on,
                    "list_count": len(listed_on),
                }
                if listed_on:
                    severity = "high"
                    tags.append("blacklisted")
            else:
                results["dnsbl"] = {"error": f"HTTP {ht_resp.status_code}"}
        except Exception as e:
            results["dnsbl"] = {"error": str(e)}
            logger.warning(f"DomainRep DNSBL check failed for {entity_value}: {e}")

        # 2. URLScan.io recent scan history
        try:
            us_resp = requests.get(
                "https://urlscan.io/api/v1/search/",
                params={"q": f"domain:{entity_value}", "size": 10},
                headers={"Accept": "application/json"},
                timeout=15,
            )
            if us_resp.status_code == 200:
                us_data = us_resp.json()
                total = us_data.get("total", 0)
                raw_results = us_data.get("results", [])
                scans = [
                    {
                        "url": s.get("page", {}).get("url", ""),
                        "country": s.get("page", {}).get("country", ""),
                        "malicious": s.get("verdicts", {}).get("overall", {}).get("malicious", False),
                        "score": s.get("verdicts", {}).get("overall", {}).get("score", 0),
                        "date": s.get("task", {}).get("time", ""),
                    }
                    for s in raw_results[:10]
                ]
                malicious_count = sum(1 for s in scans if s.get("malicious"))
                results["urlscan"] = {
                    "total_historical_scans": total,
                    "recent_scans": scans,
                    "malicious_count": malicious_count,
                }
                if malicious_count > 0 and severity == "info":
                    severity = "high"
                    tags.append("urlscan-malicious")
                elif total > 100 and severity == "info":
                    severity = "medium"
                    tags.append("high-scan-volume")
            else:
                results["urlscan"] = {"error": f"HTTP {us_resp.status_code}"}
        except Exception as e:
            results["urlscan"] = {"error": str(e)}
            logger.warning(f"DomainRep URLScan check failed for {entity_value}: {e}")

        dnsbl_listed = results.get("dnsbl", {}).get("listed_on", [])
        urlscan_total = results.get("urlscan", {}).get("total_historical_scans", "N/A")
        malicious_scans = results.get("urlscan", {}).get("malicious_count", 0)

        summary = (
            f"DomainRep: {entity_value} | DNSBL: {len(dnsbl_listed)} list(s) | "
            f"URLScan: {urlscan_total} historical scan(s)"
        )
        if dnsbl_listed:
            summary += f" | Blacklisted on: {', '.join(dnsbl_listed[:3])}"
        if malicious_scans:
            summary += f" | {malicious_scans} malicious scan verdict(s)"

        return self._make_finding(
            raw_data=results,
            summary=summary,
            severity=severity,
            tags=tags,
        )
