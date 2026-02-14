#!/usr/bin/env python3
"""Convert Sonatype IQ report JSON to SARIF format.

SARIF schema includes:
- Rules for each unique CVE/security issue
- Results for each vulnerability with package and license data
- Invocations with URIs pointing to the report source
"""

from __future__ import annotations

import json
import logging
import os
import re
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


@dataclass
class ConversionConfig:
    base_url: str
    application: str
    input_dir: Path
    output_dir: Path


def _resolve_env_value(key: str) -> str | None:
    return os.getenv(key) or os.getenv(key.upper())


def setup_logging() -> None:
    level_raw = _resolve_env_value("log_level") or "INFO"
    level_name = level_raw.upper()
    valid_levels = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"}
    if level_name not in valid_levels:
        level_name = "INFO"

    logging.basicConfig(
        level=getattr(logging, level_name),
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )


def _extract_stage_from_filename(filename: str) -> str:
    """Extract stage name from report filename like 'build_<reportId>.json'."""
    match = re.match(r"^([^_]+)_[^_]+\.json$", filename)
    if match:
        return match.group(1)
    return "unknown"


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


def _create_rule(issue: dict[str, Any], component: dict[str, Any]) -> dict[str, Any]:
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


def _create_result(
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


def convert_report_to_sarif(
    report_path: Path,
    config: ConversionConfig
) -> dict[str, Any]:
    """Convert a single Sonatype report JSON to SARIF format."""
    logger.info("Converting '%s' to SARIF format.", report_path.name)
    
    with report_path.open("r", encoding="utf-8") as f:
        report_data = json.load(f)

    stage = _extract_stage_from_filename(report_path.name)
    invocation_uri = f"{config.base_url.rstrip('/')}/{config.application}/{stage}"
    
    components = report_data.get("components", [])
    logger.info("Processing %d component(s) from report.", len(components))

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
                rules[reference] = _create_rule(issue, component)
            
            # Create result for this vulnerability
            result = _create_result(issue, component, stage)
            results.append(result)

    logger.info(
        "Found %d vulnerabilities in %d components.",
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
                    "application": config.application,
                    "stage": stage,
                    "reportFile": report_path.name
                }
            }
        ],
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Sonatype IQ",
                        "informationUri": config.base_url,
                        "version": "1.0.0",
                        "rules": list(rules.values())
                    }
                },
                "results": results,
                "properties": {
                    "reportMetadata": {
                        "application": config.application,
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


def load_config() -> ConversionConfig:
    """Load conversion configuration from environment variables."""
    base_url = _resolve_env_value("base_url")
    application = _resolve_env_value("application")
    input_dir = Path(_resolve_env_value("input_dir") or "sonatype-reports")
    output_dir = Path(_resolve_env_value("output_dir") or "sarif-reports")

    if not base_url:
        raise RuntimeError("Missing required environment variable: base_url")
    if not application:
        raise RuntimeError("Missing required environment variable: application")

    return ConversionConfig(
        base_url=base_url,
        application=application,
        input_dir=input_dir,
        output_dir=output_dir
    )


def main() -> int:
    setup_logging()
    logger.info("Starting Sonatype to SARIF conversion.")

    try:
        config = load_config()
        logger.info(
            "Loaded config: application='%s', input_dir='%s', output_dir='%s'",
            config.application,
            config.input_dir,
            config.output_dir
        )

        # Create output directory
        config.output_dir.mkdir(parents=True, exist_ok=True)

        # Find all JSON files in input directory
        json_files = sorted(config.input_dir.glob("*.json"))
        if not json_files:
            logger.warning("No JSON files found in '%s'", config.input_dir)
            return 0

        logger.info("Found %d report file(s) to convert.", len(json_files))

        converted_count = 0
        for json_file in json_files:
            try:
                sarif_data = convert_report_to_sarif(json_file, config)
                
                # Write SARIF output
                output_filename = json_file.stem + ".sarif.json"
                output_path = config.output_dir / output_filename
                
                with output_path.open("w", encoding="utf-8") as f:
                    json.dump(sarif_data, f, indent=2)
                
                logger.info("Saved SARIF report to '%s'", output_path)
                converted_count += 1
                
            except Exception as exc:
                logger.error("Failed to convert '%s': %s", json_file.name, exc)
                logger.debug("Exception traceback:\n%s", traceback.format_exc())
                continue

        logger.info(
            "Conversion completed: %d/%d reports converted successfully.",
            converted_count,
            len(json_files)
        )
        return 0

    except Exception as exc:
        logger.error("Conversion failed: %s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
