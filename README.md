# JFrog Reporter
- Clicking around JFrog manually was taking minutes and that was unacceptable.
- Helper to export JFrog Xray reports (violations, vulnerabilities, exposures, licenses, operational risks) to json


## Environment variables
- `JFROG_URL` – Base URL, e.g. `https://example.jfrog.io`
- `JFROG_API_KEY` – API key or access token
- `JFROG_REPO` – Repository on Jfrog, e.g. `docker-local`

## Run locally
```bash
pip install -r requirements.txt
export JFROG_URL=... JFROG_API_KEY=... JFROG_REPO=...
python jfrog_report.py
```
Outputs are written to `report_output/` as ZIP plus extracted JSON files.

## Notes
- Exposures run once per enabled exposure category for the repo; if none are enabled they are skipped.
- Failed or non-completed reports are skipped for export but logged to the console.
