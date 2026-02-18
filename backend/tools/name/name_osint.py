import requests
import logging
from tools.base_tool import BaseTool

logger = logging.getLogger(__name__)

# Platforms to probe for social presence (username-based public URLs)
_PLATFORMS = [
    ("GitHub", "https://github.com/{u}"),
    ("Twitter/X", "https://x.com/{u}"),
    ("Instagram", "https://www.instagram.com/{u}/"),
    ("Reddit", "https://www.reddit.com/user/{u}"),
    ("TikTok", "https://www.tiktok.com/@{u}"),
    ("Pinterest", "https://www.pinterest.com/{u}/"),
    ("Tumblr", "https://{u}.tumblr.com/"),
    ("Medium", "https://medium.com/@{u}"),
]

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; Valkyrie-OSINT/1.0)"}


def _name_to_variants(full_name: str) -> list[str]:
    """Generate probable username variants from a full name."""
    parts = full_name.lower().replace("-", " ").replace("_", " ").replace(".", " ").split()
    variants: list[str] = []
    if len(parts) >= 2:
        first, last = parts[0], parts[-1]
        variants = [
            f"{first}{last}",
            f"{first}.{last}",
            f"{first}_{last}",
            f"{first[0]}{last}",
            f"{last}{first}",
            f"{first}{last[0]}",
        ]
    elif len(parts) == 1:
        variants = [parts[0]]

    # Deduplicate while preserving order
    seen: set[str] = set()
    return [v for v in variants if not (v in seen or seen.add(v))]  # type: ignore[func-returns-value]


class NameOSINTTool(BaseTool):
    """Social presence probe for full names — generates username variants and checks platforms."""

    premium_only = True

    @property
    def name(self) -> str:
        return "NameOSINT"

    @property
    def category(self) -> str:
        return "name"

    def run(self, entity_value: str) -> dict:
        variants = _name_to_variants(entity_value)
        if not variants:
            return self._make_finding(
                raw_data={"name": entity_value, "error": "Could not generate username variants"},
                summary=f"NameOSINT: unable to parse name '{entity_value}'",
                severity="info",
                tags=["name", "social"],
            )

        probable_profiles: list[dict] = []
        checked_variants = variants[:3]  # limit to top 3 variants to stay fast

        for variant in checked_variants:
            for platform_name, url_tpl in _PLATFORMS:
                url = url_tpl.format(u=variant)
                try:
                    resp = requests.get(
                        url,
                        headers=_HEADERS,
                        timeout=8,
                        allow_redirects=True,
                    )
                    if resp.status_code == 200:
                        probable_profiles.append({
                            "platform": platform_name,
                            "username": variant,
                            "url": url,
                        })
                except Exception:
                    pass  # network errors per platform are expected; move on

        count = len(probable_profiles)
        severity = "medium" if count > 0 else "info"
        summary = (
            f"NameOSINT: {count} potential profile(s) found for '{entity_value}' "
            f"(variants tried: {', '.join(checked_variants)})"
        )

        return self._make_finding(
            raw_data={
                "name": entity_value,
                "username_variants": variants,
                "variants_checked": checked_variants,
                "platforms_checked": [p[0] for p in _PLATFORMS],
                "probable_profiles": probable_profiles,
            },
            summary=summary,
            severity=severity,
            tags=["name", "social", "profiles"],
        )
