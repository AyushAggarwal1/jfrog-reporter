#!/usr/bin/env python3
"""
Convert JFrog JSON exports (exposures or vulnerabilities) to SARIF.

Usage:
    # exposures
    python convert_to_sarif.py --input report_output/AccuKnoxReport_exposures_secrets_....json
    # vulnerabilities
    python convert_to_sarif.py --input report_output/AccuKnoxReport_vulnerabilities_....json

If no category is provided the script will emit one SARIF file per category
found in the input. Exposures use the `category` field; vulnerabilities use
`package_type`. When multiple impacted artifacts are present the finding is
expanded into one SARIF result per artifact.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
DEFAULT_REPORT_TYPE = "exposures"


def _severity_to_level(severity: str) -> str:
    """
    Map JFrog severities to SARIF result levels.
    """
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    return mapping.get(severity.lower(), "warning")


def _extract_line(location: Optional[str]) -> int:
    if not location:
        return 0
    match = re.search(r"(\d+)", str(location))
    return int(match.group(1)) if match else 0


def _string_list(value: object) -> List[str]:
    """
    Normalize any scalar or list input into a list of non-empty strings.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]

    text = str(value).strip()
    if not text:
        return []

    # Handle comma/semicolon/newline separated lists while keeping single values intact.
    separators = [",", ";", "\n"]
    if any(sep in text for sep in separators):
        parts = re.split(r"[,\n;]+", text)
        normalized = [part.strip() for part in parts if part.strip()]
        if len(normalized) > 1:
            return normalized
    return [text]


def _artifacts(value: object) -> List[str]:
    """
    Backwards-compatible alias for impacted_artifact normalization.
    """
    return _string_list(value)


def _expand_rows_by_artifact(row: Dict) -> Iterable[Dict]:
    """
    Yield a copy of the row per impacted artifact so SARIF results stay 1:1.
    """
    artifacts = _artifacts(row.get("impacted_artifact"))
    if not artifacts:
        yield {**row, "impacted_artifact": ""}
        return
    for artifact in artifacts:
        yield {**row, "impacted_artifact": artifact}


def _unique_categories(rows: Sequence[Dict]) -> List[str]:
    seen = []
    for row in rows:
        category = str(row.get("category", "")).strip()
        if category and category not in seen:
            seen.append(category)
    return seen


def _exposure_rule(row: Dict) -> Dict:
    description = str(row.get("description", "")).strip()
    cwe = str(row.get("cwe", "")).strip()
    severity = str(row.get("jfrog_severity", "")).strip()
    exposures_id = str(row.get("exposures_id", "")).strip()
    category = str(row.get("category", "")).strip()

    return {
        "id": exposures_id,
        "name": exposures_id,
        "helpUri": "",
        "help": {"text": description, "markdown": description},
        "fullDescription": {"text": description},
        "x-metadata": {"cwe": cwe},
        "properties": {
            "security-severity": severity,
            "name": exposures_id,
            "id": exposures_id,
            "description": description,
            "tags": [category] if category else [],
        },
    }


def _exposure_result(row: Dict) -> Dict:
    description = str(row.get("description", "")).strip()
    severity = str(row.get("jfrog_severity", "")).strip()
    category = str(row.get("category", "")).strip()
    file_path = str(row.get("file_path", "")).strip()
    evidence = row.get("evidence", "") or ""
    repository = str(row.get("repository", "")).strip()
    impacted_artifact = str(row.get("impacted_artifact", "")).strip()

    start_line = _extract_line(row.get("location"))

    return {
        "ruleId": str(row.get("exposures_id", "")).strip(),
        "level": _severity_to_level(severity),
        "message": {"text": description},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path},
                    "region": {
                        "startLine": start_line,
                        "startColumn": 1,
                        "endLine": start_line,
                        "endColumn": 1,
                        "snippet": {"text": evidence},
                    },
                }
            }
        ],
        "partialFingerprints": {
            "commitSha": "",
            "email": "",
            "author": "",
            "date": "",
            "commitMessage": "",
        },
        "properties": {
            "tags": [category] if category else [],
            "repository": repository,
            "impacted_artifact": impacted_artifact,
        },
    }


def _rows_by_artifact(rows: Sequence[Dict]) -> Dict[str, List[Dict]]:
    """
    Group rows by impacted artifact, duplicating rows when multiple artifacts
    are present. Empty artifacts are grouped under "".
    """
    grouped: Dict[str, List[Dict]] = {}
    for row in rows:
        artifacts = _artifacts(row.get("impacted_artifact"))
        if not artifacts:
            artifacts = [""]
        for artifact in artifacts:
            grouped.setdefault(artifact, []).append({**row, "impacted_artifact": artifact})
    return grouped


def _build_exposures_run(rows: Sequence[Dict], category: str) -> Dict:
    rules = []
    seen_rule_ids = set()
    for row in rows:
        rule_id = str(row.get("exposures_id", "")).strip()
        if rule_id in seen_rule_ids:
            continue
        seen_rule_ids.add(rule_id)
        rules.append(_exposure_rule(row))

    results = [_exposure_result(row) for row in rows]

    first_repo = next((row.get("repository") for row in rows if row.get("repository")), "")
    first_artifact = next((row.get("impacted_artifact") for row in rows if row.get("impacted_artifact")), "")
    working_uri = f"{first_artifact}" if first_artifact else ""

    return {
        "tool": {
            "driver": {
                "name": f"Jfrog-exposures-{category}",
                "semanticVersion": "v8.0.0",
                "informationUri": "https://github.com/gitleaks/gitleaks",
                "rules": rules,
            }
        },
        "results": results,
        "invocations": [
            {
                "executionSuccessful": True,
                "notificationConfigurationOverrides": [],
                "ruleConfigurationOverrides": [],
                "toolConfigurationNotifications": [],
                "toolExecutionNotifications": [],
                "workingDirectory": {
                    "index": -1,
                    "uri": working_uri,
                },
            }
        ],
    }


def _vuln_unique_categories(rows: Sequence[Dict]) -> List[str]:
    """
    Use package_type as the category for vulnerabilities; fallback to a single bucket.
    """
    seen: List[str] = []
    for row in rows:
        package_type = str(row.get("package_type", "")).strip()
        if package_type and package_type.lower() not in [c.lower() for c in seen]:
            seen.append(package_type)
    return seen or ["vulnerabilities"]


def _vuln_rule_id(cve: str, issue_id: str) -> str:
    """
    Format rule id as 'CVE-<cve>-Jfrog-<issue_id>'.
    """
    base_cve = cve or "UNKNOWN-CVE"
    base_issue = issue_id or ""
    rule = f"{base_cve}-Jfrog-{base_issue}".strip("-")
    return rule


def _vuln_rule(row: Dict, cve_entry: Dict, category: str) -> Dict:
    summary = str(row.get("summary", "")).strip()
    issue_id = str(row.get("issue_id", "")).strip()
    cwe = str(cve_entry.get("cwe", "")).strip()
    cvss = cve_entry.get("cvss_v3_score") or cve_entry.get("cvss_v2_score") or row.get("cvss3_max_score")
    cvss_text = str(cvss) if cvss is not None else ""
    severity = str(row.get("severity", "")).strip()
    cve = str(cve_entry.get("cve", "")).strip() or "UNKNOWN-CVE"
    rule_id = _vuln_rule_id(cve, issue_id)

    return {
        "id": rule_id,
        "name": rule_id,
        "helpUri": "",
        "help": {"text": summary, "markdown": summary},
        "fullDescription": {"text": summary},
        "x-metadata": {"cwe": cwe, "cvss": cvss_text, "cve": cve},
        "properties": {
            "security-severity": severity,
            "name": rule_id,
            "id": rule_id,
            "description": summary,
            "tags": [category] if category else [],
        },
    }


def _vuln_result(row: Dict, cve_entry: Dict, category: str, impacted_artifact: str) -> Dict:
    summary = str(row.get("summary", "")).strip()
    severity = str(row.get("severity", "")).strip()
    cve_value = str(cve_entry.get("cve", "")).strip() or "UNKNOWN-CVE"
    issue_id = str(row.get("issue_id", "")).strip()
    rule_id = _vuln_rule_id(cve_value, issue_id)

    impact_path = " | ".join(_string_list(row.get("impact_path")))
    fixed_versions = ", ".join(_string_list(row.get("fixed_versions")))
    package_type = str(row.get("package_type", "")).strip()
    component_physical_path = str(row.get("component_physical_path", "")).strip()
    file_path = str(row.get("impacted_artifact", "")).strip() or component_physical_path
    cve = cve_value
    cvss_v2_score = cve_entry.get("cvss_v2_score")
    cvss_v3_score = cve_entry.get("cvss_v3_score")
    cvss_v2_vector = cve_entry.get("cvss_v2_vector")
    cvss_v3_vector = cve_entry.get("cvss_v3_vector")
    project_keys = ", ".join(_string_list(row.get("project_keys")))
    path = str(row.get("path", "")).strip()


    return {
        "ruleId": rule_id,
        "level": _severity_to_level(severity),
        "message": {"text": summary},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path},
                    "region": {
                        "startLine": 1,
                        "startColumn": 1,
                        "endLine": 1,
                        "endColumn": 1,
                        "snippet": {"text": component_physical_path},
                    },
                }
            }
        ],
        "x-metadata": {
            "cve": cve,
            "cvss_v2_score": cvss_v2_score,
            "cvss_v3_score": cvss_v3_score,
            "cvss_v2_vector": cvss_v2_vector,
            "cvss_v3_vector": cvss_v3_vector,
            "impacted_artifact": impacted_artifact,
            "impact_path": impact_path,
            "fixed_versions": fixed_versions,
            "package_type": package_type,
            "project_keys": project_keys,
            "path": path,
        },
        "partialFingerprints": {
            "commitSha": "",
            "email": "",
            "author": "",
            "date": "",
            "commitMessage": "",
        },
        "properties": {"tags": [category] if category else []},
    }


def _iter_vulnerability_rows(rows: Sequence[Dict]) -> Iterable[Dict]:
    """
    Expand each vulnerability row by CVE and impacted artifact so results are granular.
    """
    for row in rows:
        cves = row.get("cves") or [{}]
        artifacts = _string_list(row.get("impacted_artifact")) or [""]
        for cve_entry in cves:
            for artifact in artifacts:
                yield {"row": row, "cve_entry": cve_entry, "impacted_artifact": artifact}


def _build_vulnerabilities_run(rows: Sequence[Dict], category: str, working_uri: str = "") -> Dict:
    expanded = list(_iter_vulnerability_rows(rows))

    # Prefer impacted artifact for working directory; fall back to provided value or path.
    artifact_working_uri = next(
        (entry["impacted_artifact"] for entry in expanded if entry["impacted_artifact"]), ""
    )
    if artifact_working_uri:
        working_uri = artifact_working_uri

    rules = []
    seen_rule_ids = set()
    for entry in expanded:
        rule = _vuln_rule(entry["row"], entry["cve_entry"], category)
        if rule["id"] in seen_rule_ids:
            continue
        seen_rule_ids.add(rule["id"])
        rules.append(rule)

    results = [
        _vuln_result(entry["row"], entry["cve_entry"], category, entry["impacted_artifact"])
        for entry in expanded
    ]

    if not working_uri:
        first_path = next((entry["row"].get("path") for entry in expanded if entry["row"].get("path")), "")
        working_uri = str(first_path).strip()

    return {
        "tool": {
            "driver": {
                "name": f"Jfrog-{category}",
                "semanticVersion": "v8.0.0",
                "informationUri": "https://www.jfrog.com/",
                "rules": rules,
            }
        },
        "results": results,
        "invocations": [
            {
                "executionSuccessful": True,
                "notificationConfigurationOverrides": [],
                "ruleConfigurationOverrides": [],
                "toolConfigurationNotifications": [],
                "toolExecutionNotifications": [],
                "workingDirectory": {
                    "index": -1,
                    "uri": working_uri,
                },
            }
        ],
    }


def _rows_by_path(rows: Sequence[Dict]) -> Dict[str, List[Dict]]:
    """
    Group vulnerability rows by their 'path' field.
    """
    grouped: Dict[str, List[Dict]] = {}
    for row in rows:
        key = str(row.get("path", "")).strip()
        grouped.setdefault(key, []).append(row)
    return grouped


def _infer_report_type(input_path: Path) -> str:
    """
    Infer report type from filename. Defaults to exposures.
    """
    name = input_path.name.lower()
    if "vulnerability" in name or "vulnerabilities" in name:
        return "vulnerabilities"
    if "violation" in name or "violations" in name:
        return "violations"
    if "exposure" in name or "exposures" in name:
        return "exposures"
    return DEFAULT_REPORT_TYPE


def _violation_rule_id(cve: str, issue_id: str) -> str:
    """
    Format rule id as '<cve>-Jfrog-<issue_id>'.
    """
    cve_part = cve or "UNKNOWN-CVE"
    issue_part = issue_id or ""
    return f"{cve_part}-Jfrog-{issue_part}".strip("-")


def _violation_rule(row: Dict, cve_entry: Dict, category: str) -> Dict:
    summary = str(row.get("summary", "")).strip()
    issue_id = str(row.get("issue_id", "")).strip()
    severity = str(row.get("severity", "")).strip()
    severity_source = str(row.get("severity_source", "")).strip()
    cve = str(cve_entry.get("cve", "")).strip() or "UNKNOWN-CVE"
    cvss = (
        cve_entry.get("cvss_v3_score")
        or cve_entry.get("cvss_v2_score")
        or row.get("cvss3_max_score")
        or row.get("cvss2_max_score")
    )
    cvss_text = str(cvss) if cvss is not None else ""
    rule_id = _violation_rule_id(cve, issue_id)

    return {
        "id": rule_id,
        "name": rule_id,
        "helpUri": "",
        "help": {"text": summary, "markdown": summary},
        "fullDescription": {"text": summary},
        "x-metadata": {
            "cves": cve,
            "cvss": cvss_text,
            "severity_source": severity_source,
        },
        "properties": {
            "security-severity": severity,
            "name": rule_id,
            "id": rule_id,
            "description": summary,
            "tags": [category] if category else [],
        },
    }


def _violation_result(row: Dict, cve_entry: Dict, category: str, impacted_artifact: str) -> Dict:
    summary = str(row.get("summary", "")).strip()
    severity = str(row.get("severity", "")).strip()
    cve = str(cve_entry.get("cve", "")).strip() or "UNKNOWN-CVE"
    issue_id = str(row.get("issue_id", "")).strip()
    rule_id = _violation_rule_id(cve, issue_id)

    impact_path = " | ".join(_string_list(row.get("impact_path")))
    fixed_versions = ", ".join(_string_list(row.get("fixed_versions")))
    package_type = str(row.get("package_type", "")).strip()
    component_physical_path = str(row.get("component_physical_path", "")).strip()
    file_path = str(row.get("path", "")).strip() or str(impacted_artifact).strip() or component_physical_path
    severity_source = str(row.get("severity_source", "")).strip()
    policy_names = ", ".join(_string_list(row.get("policy_names")))
    references = ", ".join(_string_list(row.get("references")))
    project_keys = ", ".join(_string_list(row.get("project_keys")))
    path_value = str(row.get("path", "")).strip()
    watch_name = str(row.get("watch_name", "")).strip()
    watch_id = str(row.get("watch_id", "")).strip()
    applicability_result = str(row.get("applicability_result", "")).strip()
    license_name = str(row.get("license_name", "")).strip()
    license_key = str(row.get("license_key", "")).strip()
    vulnerable_component = str(row.get("vulnerable_component", "")).strip()
    vulnerable_component_sha = str(row.get("vulnerable_component_sha", "")).strip()
    status = str(row.get("status", "")).strip()
    references_list = row.get("references")

    return {
        "ruleId": rule_id,
        "level": _severity_to_level(severity),
        "message": {"text": summary},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": impact_path},
                    "region": {
                        "startLine": 1,
                        "startColumn": 1,
                        "endLine": 1,
                        "endColumn": 1,
                        "snippet": {"text": component_physical_path},
                    },
                }
            }
        ],
        "x-metadata": {
            "type": str(row.get("type", "")).strip(),
            "vulnerable_component": vulnerable_component,
            "vulnerable_component_sha": vulnerable_component_sha,
            "impacted_artifact": impacted_artifact,
            "fixed_versions": fixed_versions,
            "package_type": package_type,
            "impact_path": impact_path,
            "policy_names": policy_names,
            "references": references,
            "status": status,
            "license_name": license_name,
            "license_key": license_key,
            "project": project_keys,
            "applicability_result": applicability_result,
            "path": path_value,
            "watch_name": watch_name,
            "watch_id": watch_id,
            "severity_source": severity_source,
            "cve": cve,
            "cvss": str(
                cve_entry.get("cvss_v3_score")
                or cve_entry.get("cvss_v2_score")
                or row.get("cvss3_max_score")
                or row.get("cvss2_max_score")
                or ""
            ),
            "references_list": references_list,
        },
        "partialFingerprints": {
            "commitSha": "",
            "email": "",
            "author": "",
            "date": "",
            "commitMessage": "",
        },
        "properties": {"tags": [category] if category else []},
    }


def _iter_violation_rows(rows: Sequence[Dict]) -> Iterable[Dict]:
    """
    Expand each violation by CVE and impacted artifact.
    """
    for row in rows:
        cves = row.get("cves") or [{}]
        artifacts = _string_list(row.get("impacted_artifact")) or [""]
        for cve_entry in cves:
            for artifact in artifacts:
                yield {"row": row, "cve_entry": cve_entry, "impacted_artifact": artifact}


def _build_violations_run(rows: Sequence[Dict], category: str, working_uri: str = "") -> Dict:
    expanded = list(_iter_violation_rows(rows))

    artifact_working_uri = next((entry["impacted_artifact"] for entry in expanded if entry["impacted_artifact"]), "")
    if artifact_working_uri:
        working_uri = artifact_working_uri
    elif not working_uri:
        working_uri = next((entry["row"].get("path") for entry in expanded if entry["row"].get("path")), "") or ""

    rules = []
    seen_rule_ids = set()
    for entry in expanded:
        rule = _violation_rule(entry["row"], entry["cve_entry"], category)
        if rule["id"] in seen_rule_ids:
            continue
        seen_rule_ids.add(rule["id"])
        rules.append(rule)

    results = [
        _violation_result(entry["row"], entry["cve_entry"], category, entry["impacted_artifact"])
        for entry in expanded
    ]

    return {
        "tool": {
            "driver": {
                "name": f"Jfrog-{category or 'violations'}",
                "semanticVersion": "v8.0.0",
                "informationUri": "https://www.jfrog.com/",
                "rules": rules,
            }
        },
        "results": results,
        "invocations": [
            {
                "executionSuccessful": True,
                "notificationConfigurationOverrides": [],
                "ruleConfigurationOverrides": [],
                "toolConfigurationNotifications": [],
                "toolExecutionNotifications": [],
                "workingDirectory": {
                    "index": -1,
                    "uri": working_uri,
                },
            }
        ],
    }


def convert_file(
    input_path: Path, category: Optional[str], output_path: Optional[Path]
) -> List[Path]:
    with input_path.open("r", encoding="utf-8") as f:
        payload = json.load(f)

    rows = payload.get("rows", [])
    if not isinstance(rows, list):
        raise ValueError("Input JSON missing 'rows' array.")

    report_type = _infer_report_type(input_path)

    if report_type == "exposures":
        categories = [category] if category else _unique_categories(rows)
        if not categories:
            raise ValueError("No categories found in input and none provided.")

        written: List[Path] = []
        for cat in categories:
            cat_rows = [row for row in rows if str(row.get("category", "")).lower() == str(cat).lower()]
            if not cat_rows:
                continue

            runs: List[Dict] = []
            for artifact, rows_for_artifact in _rows_by_artifact(cat_rows).items():
                run = _build_exposures_run(rows_for_artifact, cat)
                runs.append(run)

            sarif_payload = {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": runs}

            target = (
                output_path
                if output_path and len(categories) == 1
                else input_path.with_suffix("").with_name(f"{input_path.stem}_{cat}.sarif.json")
            )
            target.write_text(json.dumps(sarif_payload, indent=2), encoding="utf-8")
            written.append(target)
        return written

    if report_type == "vulnerabilities":
        # Emit a single SARIF file, but multiple runs grouped by unique path.
        cat = category
        cat_rows = (
            [
                row
                for row in rows
                if str(row.get("package_type", "")).lower() == str(cat).lower()
            ]
            if cat
            else list(rows)
        )
        if not cat_rows:
            return []

        runs: List[Dict] = []
        for path_key, rows_for_path in _rows_by_path(cat_rows).items():
            run = _build_vulnerabilities_run(rows_for_path, cat or "vulnerabilities", working_uri=path_key)
            runs.append(run)

        sarif_payload = {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": runs}

        target = output_path or input_path.with_suffix("").with_name(f"{input_path.stem}.sarif.json")
        target.write_text(json.dumps(sarif_payload, indent=2), encoding="utf-8")
        return [target]

    if report_type == "violations":
        cat = category or "violations"
        cat_rows = (
            [row for row in rows if str(row.get("type", "")).lower() == str(category).lower()]
            if category
            else list(rows)
        )
        if not cat_rows:
            return []

        runs: List[Dict] = []
        for path_key, rows_for_path in _rows_by_path(cat_rows).items():
            run = _build_violations_run(rows_for_path, cat, working_uri=path_key)
            runs.append(run)

        sarif_payload = {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": runs}
        target = output_path or input_path.with_suffix("").with_name(f"{input_path.stem}.sarif.json")
        target.write_text(json.dumps(sarif_payload, indent=2), encoding="utf-8")
        return [target]

    raise ValueError(f"Unsupported report type: {report_type}")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Convert JFrog JSON reports to SARIF.")
    parser.add_argument("--input", required=True, type=Path, help="Path to the exposure/vulnerability JSON file.")
    parser.add_argument(
        "--category",
        help="Category filter: exposure category or vulnerability package_type. "
        "If omitted, one SARIF is produced per category present in the input.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Path for the SARIF output. Only used when a single category is being converted.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    written_paths = convert_file(args.input, args.category, args.output)
    for path in written_paths:
        print(f"Wrote {path}")


if __name__ == "__main__":
    main()
