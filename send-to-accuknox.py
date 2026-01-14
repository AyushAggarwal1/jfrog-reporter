#!/usr/bin/env python3
"""
Upload all SARIF files under sarif_files/ to the AccuKnox artifact API.

Defaults can be overridden via CLI flags or environment variables:
- ACCUKNOX_TOKEN / ARTIFACT_TOKEN for the bearer token
- CSPM_BASE_URL for the API base (defaults to https://cspm.dev.accuknox.com)
- CSPM_DATA_TYPE for data_type (defaults to MLC)
- LABEL_ID / LABEL for label_id (defaults to cicd)
"""

from __future__ import annotations

import argparse
import logging
import os
import pathlib
from typing import Iterable, Optional

import requests

logger = logging.getLogger(__name__)


def _configure_logging() -> None:
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )



def iter_sarif_files(root: pathlib.Path) -> Iterable[pathlib.Path]:
    """Yield SARIF files under the given directory."""
    yield from sorted(root.rglob("*.sarif.json"))


def upload_file(
    session: requests.Session,
    base_url: str,
    token: str,
    label_id: Optional[str],
    file_path: pathlib.Path,
) -> dict:
    url = f"{base_url.rstrip('/')}/api/v1/artifact/"
    params = {
        "data_type": "DS",
        "save_to_s3": "true",
    }
    if label_id:
        params["label_id"] = label_id

    headers = {"Authorization": f"Bearer {token}"}

    with file_path.open("rb") as handle:
        files = {"file": (file_path.name, handle, "application/json")}
        resp = session.post(
            url,
            headers=headers,
            params=params,
            files=files,
            timeout=180,
        )
    resp.raise_for_status()
    return resp.json()


def main() -> None:
    _configure_logging()
    parser = argparse.ArgumentParser(
        description="Upload SARIF files to AccuKnox artifact API."
    )
    parser.add_argument(
        "--sarif-dir",
        default="sarif_files",
        help="Directory containing *.sarif.json files (default: sarif_files).",
    )
    parser.add_argument(
        "--base-url",
        default=os.getenv("CSPM_BASE_URL", "https://cspm.dev.accuknox.com"),
        help="AccuKnox base URL (default: env CSPM_BASE_URL or https://cspm.dev.accuknox.com).",
    )
    parser.add_argument(
        "--token",
        default=os.getenv("ACCUKNOX_TOKEN") or os.getenv("ARTIFACT_TOKEN"),
        help="Bearer token (default: env ACCUKNOX_TOKEN or ARTIFACT_TOKEN).",
    )
    parser.add_argument(
        "--label-id",
        default=os.getenv("LABEL_ID") or os.getenv("LABEL") or "cicd",
        help="label_id query param (default: env LABEL_ID/LABEL or cicd).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List files that would be uploaded without sending requests.",
    )
    args = parser.parse_args()

    token = args.token
    if not token:
        raise SystemExit("Missing token: provide --token or set ACCUKNOX_TOKEN/ARTIFACT_TOKEN.")

    sarif_dir = pathlib.Path(args.sarif_dir)
    if not sarif_dir.exists() or not sarif_dir.is_dir():
        raise SystemExit(f"SARIF directory not found: {sarif_dir}")

    sarif_files = list(iter_sarif_files(sarif_dir))
    if not sarif_files:
        logger.info("No SARIF files found under %s", sarif_dir)
        return

    session = requests.Session()
    for file_path in sarif_files:
        if args.dry_run:
            logger.info("[dry-run] Would upload %s", file_path)
            continue

        try:
            response = upload_file(
                session=session,
                base_url=args.base_url,
                token=token,
                label_id=args.label_id,
                file_path=file_path,
            )
            logger.info("Uploaded %s -> %s", file_path.name, response)
        except Exception as exc:
            logger.error("Failed to upload %s: %s", file_path, exc)


if __name__ == "__main__":
    main()
