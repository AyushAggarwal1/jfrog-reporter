#!/usr/bin/env python3
"""
JFrog Xray report helper.

Uses environment variables:
  JFROG_URL       Base URL, e.g. https://trialcmqekv.jfrog.io
  JFROG_API_KEY   API key or access token
  JFROG_REPO      Repo name to process

CLI options let you trigger violations, vulnerabilities, or exposures reports,
poll their status, and download the exported ZIP (then extract the JSON).
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
import os
import pathlib
import time
import zipfile
from typing import Dict, List, Optional, Tuple

import requests


class ConfigError(Exception):
    pass


def _env(name: str) -> str:
    val = os.getenv(name)
    if not val:
        raise ConfigError(f"Missing required env var: {name}")
    return val


logger = logging.getLogger(__name__)


def _configure_logging() -> None:
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )


def _headers(api_key: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {api_key}",
        "X-JFrog-Art-Api": api_key,
        "Content-Type": "application/json",
    }


def _timestamp() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _display_name(report_type: str) -> str:
    custom = {
        "operationalRisks": "OperationalRisks",
        "licenses": "Licenses",
        "violations": "Violations",
        "vulnerabilities": "Vulnerabilities",
        "exposures": "Exposures",
    }
    return custom.get(report_type, report_type.title())


def _report_payload(repo: str, report_type: str, category: Optional[str]) -> Dict:
    payload: Dict = {
        "name": f"{_display_name(report_type)}Report-{_timestamp()}",
        "resources": {"repositories": [{"name": repo}]},
    }
    if report_type == "exposures" and category:
        payload["filters"] = {"category": category}
    return payload


def fetch_repos(base_url: str, api_key: str, repo: str) -> List[Dict]:
    """
    Fetch artifacts for a repo so we can inspect exposure categories.
    """
    resp = requests.get(
        f"{base_url}/xray/api/v1/artifacts",
        params={"repo": repo},
        headers=_headers(api_key),
        timeout=60,
    )
    resp.raise_for_status()
    payload = resp.json()
    return payload.get("data", [])


def exposure_categories_for_repo(base_url: str, api_key: str, repo: str) -> List[str]:
    """
    Extract exposure categories enabled for the given repo.
    Expects structure under data[].exposures_issues.categories or
    scans_status.details.exposures.categories.
    """
    artifacts = fetch_repos(base_url, api_key, repo)
    if not artifacts:
        return []

    categories: set[str] = set()
    for artifact in artifacts:
        cat_from_issues = (
            artifact.get("exposures_issues", {})
            .get("categories", {})
        )
        if cat_from_issues:
            categories.update(cat_from_issues.keys())
            continue

        cat_from_status = (
            artifact.get("scans_status", {})
            .get("details", {})
            .get("exposures", {})
            .get("categories", {})
        )
        categories.update(cat_from_status.keys())
    return sorted(categories)

# @ayushaggarwal1 check-1 -> based on req this can be modified
def create_report(
    base_url: str, api_key: str, repo: str, report_type: str, category: Optional[str]
) -> int:
    endpoint_map = {
        "violations": "/xray/api/v1/reports/violations",                        # violations are policy violations
        "vulnerabilities": "/xray/api/v1/reports/vulnerabilities",              
        "exposures": "/xray/api/v1/reports/exposures",                          # exposures can be - iac, applications, secrets etc.
        "licenses": "/xray/api/v1/reports/licenses",                            # this is sbom
        "operationalRisks": "/xray/api/v1/reports/operationalRisks",
    }
    endpoint = endpoint_map[report_type]
    payload = _report_payload(repo, report_type, category)
    resp = requests.post(
        f"{base_url}{endpoint}", headers=_headers(api_key), data=json.dumps(payload), timeout=60
    )
    resp.raise_for_status()
    report_id = resp.json().get("report_id")
    if report_id is None:
        raise RuntimeError(f"No report_id in response: {resp.text}")
    return int(report_id)


def get_report_status(base_url: str, api_key: str, report_id: int) -> Dict:
    resp = requests.get(
        f"{base_url}/xray/api/v1/reports/{report_id}", headers=_headers(api_key), timeout=30
    )
    resp.raise_for_status()
    return resp.json()


def delete_report(base_url: str, api_key: str, report_id: int) -> None:
    resp = requests.delete(
        f"{base_url}/xray/api/v1/reports/{report_id}", headers=_headers(api_key), timeout=30
    )
    if resp.status_code == 404:
        logger.warning("Report %s already deleted or missing during cleanup", report_id)
        return
    resp.raise_for_status()


def wait_for_completion(
    base_url: str,
    api_key: str,
    report_id: int,
    poll_interval: int,
    timeout: int,
) -> Dict:
    deadline = time.time() + timeout
    status = {}
    while time.time() < deadline:
        status = get_report_status(base_url, api_key, report_id)
        state = status.get("status", "").lower()
        logger.info("<----Report %s status: %s---->", report_id, state)
        if state in {"completed", "failed", "cancelled"}:
            return status
        time.sleep(poll_interval)
    raise TimeoutError(f"Timed out waiting for report {report_id} to complete")


def export_report(
    base_url: str,
    api_key: str,
    report_id: int,
    file_name: str,
    export_format: str,
    output_dir: pathlib.Path,
) -> Tuple[pathlib.Path, List[pathlib.Path]]:
    params = {"file_name": file_name, "format": export_format}
    url = f"{base_url}/xray/api/v1/reports/export/{report_id}"
    resp = requests.get(url, headers=_headers(api_key), params=params, timeout=180, stream=True)
    resp.raise_for_status()

    output_dir.mkdir(parents=True, exist_ok=True)
    zip_path = output_dir / f"{file_name}.zip"
    with zip_path.open("wb") as f:
        for chunk in resp.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)

    extracted: List[pathlib.Path] = []
    try:
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(output_dir)
            extracted = [output_dir / name for name in zf.namelist()]
    except zipfile.BadZipFile:
        logger.warning("Export for report %s is not a ZIP; kept raw at %s---->", report_id, zip_path)
    return zip_path, extracted


def main() -> None:
    _configure_logging()
    base_url = _env("JFROG_URL").rstrip("/")
    api_key = _env("JFROG_API_KEY")
    repo = _env("JFROG_REPO")
    output_dir = pathlib.Path("report_output")

    report_types = [
        "violations",               # violations are policy violations it can be custom policies or built-in policies
        "vulnerabilities",          # vulnerabilities
        "exposures",                # exposures can be - iac, applications, secrets etc.
        "licenses",                 # sbom
        "operationalRisks",      
    ]
    exposure_categories = exposure_categories_for_repo(base_url, api_key, repo)
    if not exposure_categories:
        logger.info("No exposure categories found for repo; exposures reports will be skipped.")

    for report_type in report_types:
        categories_to_run = [None]
        if report_type == "exposures":
            if not exposure_categories:
                continue
            categories_to_run = exposure_categories

        for category in categories_to_run:
            try:
                report_id = create_report(base_url, api_key, repo, report_type, category=category)
            except Exception as exc:  # requests.HTTPError or config errors
                cat_suffix = f" ({category})" if category else ""
                logger.error("Failed to create %s%s report: %s", report_type, cat_suffix, exc)
                continue

            cat_suffix = f" ({category})" if category else ""
            logger.info("%s report%s created: id=%s", _display_name(report_type), cat_suffix, report_id)

            try:
                status = wait_for_completion(
                    base_url, api_key, report_id, poll_interval=5, timeout=300
                )
            except TimeoutError as exc:
                logger.error(str(exc))
                continue
            except requests.HTTPError as exc:
                logger.error("Status check failed for report %s: %s", report_id, exc)
                continue

            if status.get("status", "").lower() != "completed":
                logger.warning(
                    "Report %s finished with status %s; not exporting.",
                    report_id,
                    status.get("status"),
                )
                continue

            file_name = f"AccuKnoxReport_{report_type}"
            if category:
                file_name += f"_{category}"
            file_name += f"_{_timestamp()}"

            try:
                zip_path, extracted = export_report(
                    base_url,
                    api_key,
                    report_id,
                    file_name,
                    export_format="json",
                    output_dir=output_dir,
                )
            except requests.HTTPError as exc:
                logger.error("Export failed for report %s: %s", report_id, exc)
                continue

            logger.info("Saved export ZIP to %s", zip_path)
            if extracted:
                logger.info("Extracted files:")
                for path in extracted:
                    logger.info("  %s", path)

            try:
                delete_report(base_url, api_key, report_id)
                logger.info("Deleted report %s from JFrog after export", report_id)
            except requests.HTTPError as exc:
                logger.warning("Failed to delete report %s: %s", report_id, exc)


if __name__ == "__main__":
    try:
        main()
    except ConfigError as err:
        raise SystemExit(f"Config error: {err}")
