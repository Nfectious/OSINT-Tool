import requests
import logging
from tools.base_tool import BaseTool

logger = logging.getLogger(__name__)

_FIELDS = (
    "status,message,country,countryCode,region,regionName,"
    "city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
)


class IPGeoTool(BaseTool):
    """IP geolocation, ASN, and ISP enrichment via ip-api.com (free, no key)."""

    premium_only = True

    @property
    def name(self) -> str:
        return "IP-Geo"

    @property
    def category(self) -> str:
        return "network"

    def run(self, entity_value: str) -> dict:
        url = f"http://ip-api.com/json/{entity_value}"
        try:
            resp = requests.get(url, params={"fields": _FIELDS}, timeout=10)
            resp.raise_for_status()
        except requests.RequestException as e:
            return self._make_finding(
                raw_data={"error": str(e), "query": entity_value},
                summary=f"IP geolocation failed for {entity_value}: {e}",
                severity="error",
                tags=["error", "network", "geo"],
            )

        data = resp.json()

        if data.get("status") == "fail":
            return self._make_finding(
                raw_data={"error": data.get("message"), "query": entity_value},
                summary=f"IP-API: {data.get('message', 'lookup failed')} for {entity_value}",
                severity="info",
                tags=["network", "geo", "no-data"],
            )

        country = data.get("country", "Unknown")
        city = data.get("city", "Unknown")
        region = data.get("regionName", "")
        isp = data.get("isp", "Unknown")
        org = data.get("org", "Unknown")
        asn = data.get("as", "Unknown")
        proxy = data.get("proxy", False)
        hosting = data.get("hosting", False)
        mobile = data.get("mobile", False)
        timezone = data.get("timezone", "Unknown")
        lat = data.get("lat")
        lon = data.get("lon")

        flags = []
        if proxy:
            flags.append("proxy/vpn")
        if hosting:
            flags.append("datacenter/hosting")
        if mobile:
            flags.append("mobile")

        severity = "high" if (proxy or hosting) else "info"
        location = f"{city}, {region}, {country}" if region else f"{city}, {country}"
        summary = f"{entity_value} → {location} | ISP: {isp} | {asn}"
        if flags:
            summary += f" | Flags: {', '.join(flags)}"

        tags = ["network", "geo", "asn", "isp", "ip-api"] + flags

        return self._make_finding(
            raw_data={
                "query": entity_value,
                "country": country,
                "country_code": data.get("countryCode"),
                "region": region,
                "city": city,
                "zip": data.get("zip"),
                "lat": lat,
                "lon": lon,
                "timezone": timezone,
                "isp": isp,
                "org": org,
                "asn": asn,
                "asname": data.get("asname"),
                "reverse_dns": data.get("reverse"),
                "mobile": mobile,
                "proxy": proxy,
                "hosting": hosting,
            },
            summary=summary,
            severity=severity,
            tags=tags,
        )
