#!/usr/bin/env python3
"""Offline DB-IP Lite MMDB enrichment for GeoWAN Console.

The lookup path is optional and never participates in firewall enforcement.
"""
import ipaddress
import json
from pathlib import Path

GEOIP_DIR = Path("/etc/geowan-console/geoip/current")
FILES = {
    "country": "country.mmdb",
    "city": "city.mmdb",
    "asn": "asn.mmdb",
}
ATTRIBUTION_URL = "https://db-ip.com"


def _name(value):
    if not isinstance(value, dict):
        return ""
    for key in ("zh-CN", "en", "zh", "en-US"):
        item = value.get(key)
        if isinstance(item, str) and item.strip():
            return item.strip()[:160]
    for item in value.values():
        if isinstance(item, str) and item.strip():
            return item.strip()[:160]
    return ""


def _mapping(value):
    return value if isinstance(value, dict) else {}


def _text(value, limit=160):
    return value.strip()[:limit] if isinstance(value, str) and value.strip() else ""


def _first(mapping, *keys):
    for key in keys:
        value = mapping.get(key)
        if value not in (None, ""):
            return value
    return None


def read_metadata(directory=GEOIP_DIR):
    path = Path(directory) / "metadata.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except (OSError, ValueError):
        pass
    return {}


class GeoIPResolver:
    def __init__(self, directory=GEOIP_DIR, reader_factory=None):
        self.directory = Path(directory)
        self.metadata = read_metadata(self.directory)
        self.version = _text(self.metadata.get("release"), 32) or "unknown"
        self.provider = _text(self.metadata.get("provider"), 80) or "DB-IP Lite"
        self.readers = {}
        self.errors = []

        if reader_factory is None:
            try:
                import maxminddb
                reader_factory = maxminddb.open_database
            except ImportError:
                self.errors.append("python3-maxminddb is not installed")
                self.available = False
                return

        for kind, filename in FILES.items():
            path = self.directory / filename
            if not path.is_file():
                continue
            try:
                self.readers[kind] = reader_factory(str(path))
            except Exception as exc:
                self.errors.append(f"{kind}: {exc}")

        self.available = bool(self.readers)
        if not self.available and not self.errors:
            self.errors.append("No MMDB files installed")

    def _get(self, kind, ip):
        reader = self.readers.get(kind)
        if reader is None:
            return {}
        try:
            return _mapping(reader.get(str(ip)))
        except Exception as exc:
            self.errors.append(f"{kind} lookup: {exc}")
            return {}

    def lookup(self, value):
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return {"ip": str(value), "lookup_status": "invalid"}

        base = {
            "ip": str(ip),
            "country_code": "",
            "country_name": "",
            "continent_code": "",
            "continent_name": "",
            "region": "",
            "city": "",
            "asn": None,
            "asn_org": "",
            "provider": self.provider,
            "database_version": self.version,
        }
        if not ip.is_global:
            base["lookup_status"] = "non_global"
            return base
        if not self.available:
            base["lookup_status"] = "unavailable"
            return base

        country_record = self._get("country", ip)
        city_record = self._get("city", ip)
        asn_record = self._get("asn", ip)

        # DB-IP City Lite also carries country and continent fields. Prefer the
        # dedicated Country database, then fall back to the City database.
        country = _mapping(country_record.get("country")) or _mapping(city_record.get("country"))
        continent = _mapping(country_record.get("continent")) or _mapping(city_record.get("continent"))
        city = _mapping(city_record.get("city"))
        subdivisions = city_record.get("subdivisions")
        first_subdivision = _mapping(subdivisions[0]) if isinstance(subdivisions, list) and subdivisions else {}

        base["country_code"] = _text(country.get("iso_code"), 2).upper()
        base["country_name"] = _name(country.get("names"))
        base["continent_code"] = _text(continent.get("code"), 2).upper()
        base["continent_name"] = _name(continent.get("names"))
        base["region"] = _name(first_subdivision.get("names"))
        base["city"] = _name(city.get("names"))

        # Support the common MMDB ASN field names and DB-IP's ISP-style traits.
        traits = _mapping(asn_record.get("traits"))
        asn_value = _first(
            asn_record, "autonomous_system_number", "as_number", "asn"
        )
        if asn_value is None:
            asn_value = _first(traits, "autonomous_system_number", "as_number", "asn")
        try:
            base["asn"] = int(asn_value) if asn_value is not None else None
        except (TypeError, ValueError):
            base["asn"] = None
        base["asn_org"] = _text(_first(
            asn_record,
            "autonomous_system_organization",
            "as_organization",
            "as_name",
            "organization",
            "isp",
        ) or _first(
            traits,
            "autonomous_system_organization",
            "as_organization",
            "as_name",
            "organization",
            "isp",
        ))

        base["lookup_status"] = (
            "ok" if base["country_code"] or base["asn"] is not None else "not_found"
        )
        return base

    def close(self):
        for reader in self.readers.values():
            try:
                reader.close()
            except Exception:
                pass
        self.readers.clear()
