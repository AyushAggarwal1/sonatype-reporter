#!/usr/bin/env python3
"""Sonatype IQ API wrapper for application report exports with optional SARIF conversion.

This script follows the flow documented in reqs.txt:
1) Get all applications.
2) Resolve application id from configured publicId.
3) Fetch reports for that application id.
4) Save JSON reports.
5) Optionally convert to SARIF format (when convert_to_sarif flag is enabled).

Environment Variables:
- convert_to_sarif: Enable SARIF conversion (saves both JSON and SARIF files)
- output_dir: Custom output directory (defaults based on convert_to_sarif flag)
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests


REQUIRED_ENV_KEYS = ("base_url", "user_id", "api_key", "application")
VALID_LOG_LEVELS = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"}
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
logger = logging.getLogger(__name__)


@dataclass
class SonatypeConfig:
    base_url: str
    user_id: str
    api_key: str
    application: str  # Sonatype publicId
    timeout: int = 30


def _resolve_env_value(key: str) -> str | None:
    return os.getenv(key) or os.getenv(key.upper())


def setup_logging() -> None:
    level_raw = _resolve_env_value("log_level") or "INFO"
    level_name = level_raw.upper()
    if level_name not in VALID_LOG_LEVELS:
        level_name = "INFO"
        invalid_level = True
    else:
        invalid_level = False

    logging.basicConfig(
        level=getattr(logging, level_name),
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )

    if invalid_level:
        logger.warning("Invalid LOG_LEVEL '%s'. Falling back to INFO.", level_raw)


def load_config() -> SonatypeConfig:
    config_values: dict[str, str] = {}

    for key in REQUIRED_ENV_KEYS:
        value = _resolve_env_value(key)
        if value:
            config_values[key] = value

    missing_keys = [key for key in REQUIRED_ENV_KEYS if key not in config_values]
    if missing_keys:
        raise RuntimeError(
            "Missing required config values: "
            + ", ".join(missing_keys)
            + ". Set them as environment variables."
        )

    timeout_raw = _resolve_env_value("timeout")
    timeout = int(timeout_raw) if timeout_raw else 30

    return SonatypeConfig(
        base_url=config_values["base_url"],
        user_id=config_values["user_id"],
        api_key=config_values["api_key"],
        application=config_values["application"],
        timeout=timeout,
    )


def _sanitize_filename(value: str) -> str:
    clean = re.sub(r"[^a-zA-Z0-9._-]+", "_", value).strip("_")
    return clean or "unknown"


def _extract_report_id(report_data_url: str) -> str:
    match = re.search(r"/reports/([^/]+)/raw/?$", report_data_url.strip())
    if match:
        return match.group(1)
    return report_data_url.rstrip("/").split("/")[-1]


def _severity_to_level(severity: float) -> str:
    """Map CVSS severity score to SARIF level."""
    if severity >= 9.0:
        return "error"
    elif severity >= 7.0:
        return "error"
    elif severity >= 4.0:
        return "warning"
    else:
        return "note"


def _create_sarif_rule(issue: dict[str, Any], component: dict[str, Any]) -> dict[str, Any]:
    """Create a SARIF rule from a security issue."""
    reference = issue.get("reference", "UNKNOWN")
    severity = issue.get("severity", 0.0)
    cwe = issue.get("cwe", "")
    threat_category = issue.get("threatCategory", "unknown")
    url = issue.get("url", "")
    cvss_vector = issue.get("cvssVector", "")

    help_text = f"CVSS Score: {severity}\n"
    help_text += f"Threat Category: {threat_category}\n"
    if cwe:
        help_text += f"CWE: {cwe}\n"
    if cvss_vector:
        help_text += f"CVSS Vector: {cvss_vector}\n"
    help_text += f"\nAffected Package: {component.get('displayName', 'unknown')}\n"
    help_text += f"Package URL: {component.get('packageUrl', 'unknown')}"

    rule = {
        "id": reference,
        "name": reference,
        "shortDescription": {
            "text": f"{reference} in {component.get('displayName', 'unknown')}"
        },
        "fullDescription": {
            "text": help_text
        },
        "help": {
            "text": help_text,
            "markdown": f"**{reference}**\n\n{help_text}"
        },
        "properties": {
            "security-severity": str(severity),
            "precision": "high",
            "tags": ["security", "vulnerability"]
        }
    }

    if cwe:
        rule["properties"]["cwe"] = cwe
    if threat_category:
        rule["properties"]["threat-category"] = threat_category
    if cvss_vector:
        rule["properties"]["cvss-vector"] = cvss_vector
    if url:
        rule["helpUri"] = url

    return rule


def _create_sarif_result(
    issue: dict[str, Any],
    component: dict[str, Any],
    stage: str
) -> dict[str, Any]:
    """Create a SARIF result from a security issue and component."""
    reference = issue.get("reference", "UNKNOWN")
    severity = issue.get("severity", 0.0)
    level = _severity_to_level(severity)
    pathnames = component.get("pathnames", [])
    
    # Use first pathname if available, otherwise use package name
    if pathnames:
        artifact_location = pathnames[0]
    else:
        artifact_location = component.get("displayName", "unknown")

    message_text = (
        f"{reference} found in {component.get('displayName', 'unknown')} "
        f"(severity: {severity}, threat: {issue.get('threatCategory', 'unknown')})"
    )

    # Safely extract component identifier data
    component_id = component.get("componentIdentifier") or {}
    coordinates = component_id.get("coordinates") or {}
    
    # Safely extract license data
    license_data = component.get("licenseData") or {}

    result = {
        "ruleId": reference,
        "level": level,
        "message": {
            "text": message_text
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": artifact_location
                    }
                }
            }
        ],
        "properties": {
            "stage": stage,
            "package": {
                "name": coordinates.get("name", "unknown"),
                "version": coordinates.get("version", "unknown"),
                "format": component_id.get("format", "unknown"),
                "packageUrl": component.get("packageUrl", ""),
                "displayName": component.get("displayName", ""),
                "hash": component.get("hash", ""),
                "proprietary": component.get("proprietary", False),
                "matchState": component.get("matchState", ""),
                "pathnames": component.get("pathnames", []),
                "filenames": component.get("filenames", [])
            },
            "license": {
                "declaredLicenses": license_data.get("declaredLicenses", []),
                "observedLicenses": license_data.get("observedLicenses", []),
                "effectiveLicenses": license_data.get("effectiveLicenses", []),
                "overriddenLicenses": license_data.get("overriddenLicenses", []),
                "status": license_data.get("status", ""),
                "effectiveLicenseThreats": license_data.get("effectiveLicenseThreats", [])
            },
            "vulnerability": {
                "source": issue.get("source", ""),
                "reference": issue.get("reference", ""),
                "severity": issue.get("severity", 0.0),
                "status": issue.get("status", ""),
                "url": issue.get("url", ""),
                "threatCategory": issue.get("threatCategory", ""),
                "cwe": issue.get("cwe", ""),
                "cvssVector": issue.get("cvssVector", ""),
                "cvssVectorSource": issue.get("cvssVectorSource", "")
            }
        }
    }

    return result


def _convert_report_to_sarif(
    report_data: dict[str, Any],
    stage: str,
    application: str,
    base_url: str,
    report_filename: str
) -> dict[str, Any]:
    """Convert Sonatype report JSON to SARIF format."""
    invocation_uri = f"{base_url.rstrip('/')}/{application}/{stage}"
    components = report_data.get("components", [])

    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    
    vulnerability_count = 0
    component_with_vulns = 0

    for component in components:
        security_data = component.get("securityData") or {}
        security_issues = security_data.get("securityIssues", [])
        
        if not security_issues:
            continue
            
        component_with_vulns += 1
        
        for issue in security_issues:
            vulnerability_count += 1
            reference = issue.get("reference", "UNKNOWN")
            
            # Add rule if not already present
            if reference not in rules:
                rules[reference] = _create_sarif_rule(issue, component)
            
            # Create result for this vulnerability
            result = _create_sarif_result(issue, component, stage)
            results.append(result)

    logger.info(
        "Converted stage '%s': %d vulnerabilities in %d components.",
        stage,
        vulnerability_count,
        component_with_vulns
    )

    # Build SARIF structure with invocations at top level
    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "invocations": [
            {
                "executionSuccessful": True,
                "workingDirectory": {
                    "uri": invocation_uri
                },
                "properties": {
                    "application": application,
                    "stage": stage,
                    "reportFile": report_filename
                }
            }
        ],
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Sonatype IQ",
                        "informationUri": base_url,
                        "version": "1.0.0",
                        "rules": list(rules.values())
                    }
                },
                "results": results,
                "properties": {
                    "reportMetadata": {
                        "application": application,
                        "stage": stage,
                        "totalComponents": len(components),
                        "componentsWithVulnerabilities": component_with_vulns,
                        "totalVulnerabilities": vulnerability_count,
                        "matchSummary": report_data.get("matchSummary", {}),
                        "globalInformation": report_data.get("globalInformation", {})
                    }
                }
            }
        ]
    }

    return sarif


class SonatypeClient:
    def __init__(self, config: SonatypeConfig) -> None:
        self.config = config
        self.base_url = config.base_url.rstrip("/") + "/"
        self.session = requests.Session()
        self.session.auth = (config.user_id, config.api_key)
        self.session.headers.update({"Accept": "application/json"})
        logger.debug("Initialized Sonatype client for base URL '%s'.", self.base_url)

    def _build_url(self, path_or_url: str) -> str:
        if path_or_url.startswith(("http://", "https://")):
            return path_or_url
        return urljoin(self.base_url, path_or_url.lstrip("/"))

    def _get_json(self, path_or_url: str) -> Any:
        url = self._build_url(path_or_url)
        logger.debug("GET %s", url)
        start = time.perf_counter()
        response = self.session.get(url, timeout=self.config.timeout)
        response.raise_for_status()
        elapsed = time.perf_counter() - start
        logger.debug("GET %s -> status=%s in %.2fs", url, response.status_code, elapsed)
        return response.json()

    def get_applications(self) -> list[dict[str, Any]]:
        payload = self._get_json("/api/v2/applications/")
        applications = payload.get("applications", [])
        if not isinstance(applications, list):
            raise RuntimeError("Unexpected applications payload format from Sonatype API.")
        logger.info("Fetched %d application(s).", len(applications))
        return applications

    def get_application_by_public_id(self, public_id: str) -> dict[str, Any]:
        applications = self.get_applications()
        for app in applications:
            if app.get("publicId") == public_id:
                logger.info(
                    "Resolved application publicId '%s' to id '%s'.",
                    public_id,
                    app.get("id"),
                )
                return app

        known_ids = sorted(str(app.get("publicId", "")) for app in applications if app.get("publicId"))
        raise LookupError(
            f"Application publicId '{public_id}' not found. "
            f"Available publicIds: {', '.join(known_ids) if known_ids else 'none'}"
        )

    def get_reports(self, application_id: str) -> list[dict[str, Any]]:
        payload = self._get_json(f"/api/v2/reports/applications/{application_id}")
        if not isinstance(payload, list):
            raise RuntimeError("Unexpected reports payload format from Sonatype API.")
        logger.info("Fetched %d report metadata item(s).", len(payload))
        return payload

    def get_report_data(self, report_data_url: str) -> dict[str, Any]:
        payload = self._get_json(report_data_url)
        if not isinstance(payload, dict):
            raise RuntimeError("Unexpected report data payload format from Sonatype API.")
        return payload

    def export_stage_reports(self, output_dir: Path, convert_to_sarif: bool = False) -> dict[str, Any]:
        """Fetch reports and optionally convert to SARIF format.
        
        Args:
            output_dir: Directory to save reports
            convert_to_sarif: If True, save both JSON and SARIF files. If False, save only JSON.
        """
        app = self.get_application_by_public_id(self.config.application)
        application_id = str(app.get("id", "")).strip()
        if not application_id:
            raise RuntimeError("Application is missing 'id' in Sonatype API response.")

        reports = self.get_reports(application_id)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        if convert_to_sarif:
            logger.info(
                "Exporting JSON and SARIF reports for application '%s' into '%s'.",
                app.get("publicId"),
                output_dir,
            )
        else:
            logger.info(
                "Exporting JSON reports for application '%s' into '%s'.",
                app.get("publicId"),
                output_dir,
            )
        logger.info("Processing %d report metadata item(s).", len(reports))

        saved_reports: list[dict[str, str]] = []
        skipped_reports = 0
        for index, report in enumerate(reports, start=1):
            report_data_url = str(report.get("reportDataUrl", "")).strip()
            if not report_data_url:
                logger.warning("Skipping report #%d because reportDataUrl is missing.", index)
                skipped_reports += 1
                continue

            stage_raw = str(report.get("stage", f"stage_{index}"))
            stage = _sanitize_filename(stage_raw)
            report_id = _sanitize_filename(_extract_report_id(report_data_url))
            
            # JSON filename
            json_filename = f"{stage}_{report_id}.json"
            json_path = output_dir / json_filename

            logger.info(
                "Downloading report %d/%d (stage='%s', reportId='%s').",
                index,
                len(reports),
                stage_raw,
                report_id,
            )
            
            # Fetch JSON report data
            report_data = self.get_report_data(report_data_url)
            
            # Always save JSON file
            json_path.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
            logger.info(
                "Saved JSON report %d/%d to '%s'.",
                index,
                len(reports),
                json_path,
            )

            report_entry = {
                "stage": stage_raw,
                "reportDataUrl": report_data_url,
                "jsonFile": str(json_path),
            }

            # Optionally convert to SARIF
            if convert_to_sarif:
                sarif_filename = f"{stage}_{report_id}.sarif.json"
                sarif_path = output_dir / sarif_filename
                
                logger.info(
                    "Converting report %d/%d to SARIF format.",
                    index,
                    len(reports)
                )
                sarif_data = _convert_report_to_sarif(
                    report_data=report_data,
                    stage=stage_raw,
                    application=self.config.application,
                    base_url=self.config.base_url,
                    report_filename=json_filename
                )
                
                sarif_path.write_text(json.dumps(sarif_data, indent=2), encoding="utf-8")
                logger.info(
                    "Saved SARIF report %d/%d to '%s'.",
                    index,
                    len(reports),
                    sarif_path,
                )
                report_entry["sarifFile"] = str(sarif_path)

            saved_reports.append(report_entry)

        if convert_to_sarif:
            logger.info(
                "Export completed: saved=%d (JSON + SARIF) skipped=%d total=%d.",
                len(saved_reports),
                skipped_reports,
                len(reports),
            )
        else:
            logger.info(
                "Export completed: saved=%d (JSON only) skipped=%d total=%d.",
                len(saved_reports),
                skipped_reports,
                len(reports),
            )

        summary = {
            "application": {
                "id": application_id,
                "publicId": app.get("publicId"),
                "name": app.get("name"),
            },
            "totalReports": len(reports),
            "savedReports": saved_reports,
            "sarifEnabled": convert_to_sarif,
        }
        return summary


def _as_bool(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def main() -> int:
    setup_logging()
    logger.debug("Starting Sonatype report export run.")

    try:
        config = load_config()
        logger.info(
            "Loaded config for application '%s' with timeout=%s seconds.",
            config.application,
            config.timeout,
        )
        client = SonatypeClient(config)

        if _as_bool(_resolve_env_value("list_applications")):
            logger.info("list_applications is enabled. Fetching applications only.")
            applications = client.get_applications()
            print(json.dumps(applications, indent=2))
            return 0

        # Check if SARIF conversion is enabled
        convert_to_sarif = _as_bool(_resolve_env_value("convert_to_sarif"))
        
        # Default output directory based on SARIF flag
        default_output_dir = "sarif-reports" if convert_to_sarif else "sonatype-reports"
        output_dir = Path(_resolve_env_value("output_dir") or default_output_dir)
        
        if convert_to_sarif:
            logger.info("SARIF conversion enabled. Will save both JSON and SARIF files.")
        else:
            logger.info("SARIF conversion disabled. Will save only JSON files.")
        
        result = client.export_stage_reports(output_dir, convert_to_sarif=convert_to_sarif)
        
        if convert_to_sarif:
            logger.info(
                "Saved %d report(s) (JSON + SARIF) for application '%s' into '%s'.",
                len(result["savedReports"]),
                result["application"]["publicId"],
                output_dir,
            )
        else:
            logger.info(
                "Saved %d JSON report(s) for application '%s' into '%s'.",
                len(result["savedReports"]),
                result["application"]["publicId"],
                output_dir,
            )
        return 0

    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        logger.error("HTTP error while calling Sonatype API (status=%s): %s", status, exc)
        return 1
    except (RuntimeError, LookupError, ValueError) as exc:
        logger.error("%s", exc)
        return 1
    except requests.RequestException as exc:
        logger.error("Network error while calling Sonatype API: %s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
