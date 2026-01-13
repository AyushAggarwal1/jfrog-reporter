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


def fetch_repos(base_url: str, api_key: str) -> List[Dict]:
    resp = requests.get(f"{base_url}/xray/api/v1/repos", headers=_headers(api_key), timeout=30)
    resp.raise_for_status()
    payload = resp.json()
    return payload.get("data", [])


def exposure_categories_for_repo(base_url: str, api_key: str, repo: str) -> List[str]:
    """
    Extract exposure categories enabled for the given repo.
    Expects structure under configuration.scan.exposures.categories.
    """
    repos = fetch_repos(base_url, api_key)
    repo_entry = next((r for r in repos if r.get("repo") == repo), None)
    if not repo_entry:
        return []
    categories = (
        repo_entry.get("configuration", {})
        .get("scan", {})
        .get("exposures", {})
        .get("categories", {})
    )
    return [name for name, enabled in categories.items() if enabled]


def create_report(
    base_url: str, api_key: str, repo: str, report_type: str, category: Optional[str]
) -> int:
    endpoint_map = {
        "violations": "/xray/api/v1/reports/violations",
        "vulnerabilities": "/xray/api/v1/reports/vulnerabilities",
        "exposures": "/xray/api/v1/reports/exposures",
        "licenses": "/xray/api/v1/reports/licenses",
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
        print(f"Report {report_id} status: {state}")
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
        print(f"Warning: Export for report {report_id} is not a ZIP; kept raw at {zip_path}")
    return zip_path, extracted


def main() -> None:
    base_url = _env("JFROG_URL").rstrip("/")
    api_key = _env("JFROG_API_KEY")
    repo = _env("JFROG_REPO")
    output_dir = pathlib.Path("report_output")

    report_types = [
        "violations",
        "vulnerabilities",
        "exposures",
        "licenses",
        "operationalRisks",
    ]
    exposure_categories = exposure_categories_for_repo(base_url, api_key, repo)
    if not exposure_categories:
        print("No exposure categories found for repo; exposures reports will be skipped.")

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
                print(f"Failed to create {report_type}{cat_suffix} report: {exc}")
                continue

            cat_suffix = f" ({category})" if category else ""
            print(f"{_display_name(report_type)} report{cat_suffix} created: id={report_id}")

            try:
                status = wait_for_completion(
                    base_url, api_key, report_id, poll_interval=5, timeout=300
                )
            except TimeoutError as exc:
                print(str(exc))
                continue
            except requests.HTTPError as exc:
                print(f"Status check failed for report {report_id}: {exc}")
                continue

            if status.get("status", "").lower() != "completed":
                print(f"Report {report_id} finished with status {status.get('status')}; not exporting.")
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
                print(f"Export failed for report {report_id}: {exc}")
                continue

            print(f"Saved export ZIP to {zip_path}")
            if extracted:
                print("Extracted files:")
                for path in extracted:
                    print(f"  {path}")


if __name__ == "__main__":
    try:
        main()
    except ConfigError as err:
        raise SystemExit(f"Config error: {err}")
