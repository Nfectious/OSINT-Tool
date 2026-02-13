import subprocess
import json
import logging
import requests
from tools.base_tool import BaseTool

logger = logging.getLogger(__name__)


class ExifToolTool(BaseTool):
    """Extracts metadata from files using ExifTool with GPS reverse geocoding."""

    @property
    def name(self) -> str:
        return "ExifTool"

    @property
    def category(self) -> str:
        return "general"

    def run(self, entity_value: str) -> dict:
        try:
            result = subprocess.run(
                ["exiftool", "-j", "-n", entity_value],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            return self._make_finding(
                raw_data={"error": "ExifTool timed out"},
                summary="ExifTool timed out",
                severity="error",
                tags=["error", "general", "timeout"],
            )
        except FileNotFoundError:
            return self._make_finding(
                raw_data={"error": "exiftool binary not found"},
                summary="ExifTool not installed",
                severity="error",
                tags=["error", "general", "missing-tool"],
            )

        stdout = result.stdout or ""
        try:
            metadata_list = json.loads(stdout)
            metadata = metadata_list[0] if metadata_list else {}
        except (json.JSONDecodeError, IndexError):
            return self._make_finding(
                raw_data={"raw_output": stdout[:2000], "error": "Failed to parse JSON"},
                summary=f"ExifTool: could not parse output for {entity_value}",
                severity="error",
                tags=["error", "general"],
            )

        # Extract key fields
        gps_lat = metadata.get("GPSLatitude")
        gps_lon = metadata.get("GPSLongitude")
        make = metadata.get("Make", "")
        model = metadata.get("Model", "")
        software = metadata.get("Software", "")
        timestamp = (
            metadata.get("DateTimeOriginal")
            or metadata.get("CreateDate")
            or ""
        )

        # GPS enrichment path
        if gps_lat is not None and gps_lon is not None:
            lat = float(gps_lat)
            lon = float(gps_lon)

            google_maps_url = f"https://www.google.com/maps?q={lat},{lon}"

            # Reverse geocode via Nominatim
            reverse_geo = {}
            address_str = f"{lat}, {lon}"
            try:
                geo_resp = requests.get(
                    "https://nominatim.openstreetmap.org/reverse",
                    params={
                        "format": "json",
                        "lat": lat,
                        "lon": lon,
                        "zoom": 18,
                        "addressdetails": 1,
                    },
                    headers={"User-Agent": "ValkyrieOSINT/1.0"},
                    timeout=10,
                )
                geo_resp.raise_for_status()
                geo_data = geo_resp.json()
                addr = geo_data.get("address", {})
                road = addr.get("road", "")
                suburb = addr.get("suburb", "")
                city = (
                    addr.get("city")
                    or addr.get("town")
                    or addr.get("village")
                    or ""
                )
                state = addr.get("state", "")
                country = addr.get("country", "")
                parts = [p for p in [road, suburb, city, state, country] if p]
                address_str = ", ".join(parts) if parts else geo_data.get("display_name", address_str)
                reverse_geo = {
                    "address": address_str,
                    "city": city,
                    "state": state,
                    "country": country,
                }
            except Exception as e:
                logger.warning(f"Reverse geocoding failed: {e}")
                reverse_geo = {"address": f"{lat}, {lon}", "error": str(e)}

            device_str = f"{make} {model}".strip() if (make or model) else "Unknown"

            raw_data = {
                "gps_coordinates": {"lat": lat, "lon": lon},
                "google_maps_url": google_maps_url,
                "reverse_geocoded": reverse_geo,
                "device": {"make": make, "model": model},
                "software": software,
                "timestamp": str(timestamp),
                "all_metadata": metadata,
            }

            summary = (
                f"LOCATION DETECTED: {address_str}. "
                f"Device: {device_str}. "
                f"Photo taken: {timestamp}. "
                f"Maps: {google_maps_url}"
            )

            return self._make_finding(
                raw_data=raw_data,
                summary=summary,
                severity="high",
                tags=["file", "metadata", "exiftool", "gps", "location", "GEOLOCATION"],
            )

        # No GPS data path
        device_str = f"{make} {model}".strip() if (make or model) else "Unknown"
        summary = (
            f"Device: {device_str}. "
            f"Software: {software or 'Unknown'}. "
            f"No GPS data found."
        )

        raw_data = {
            "device": {"make": make, "model": model},
            "software": software,
            "timestamp": str(timestamp),
            "all_metadata": metadata,
        }

        return self._make_finding(
            raw_data=raw_data,
            summary=summary,
            severity="info",
            tags=["file", "metadata", "exiftool"],
        )
