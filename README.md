# JFrog Reporter
- Clicking around JFrog manually was taking minutes and that was unacceptable.
- Helper to export JFrog Xray reports (violations, vulnerabilities, exposures, licenses, operational risks) to json


## Environment variables
- `JFROG_URL` – Base URL, e.g. `https://example.jfrog.io`
- `JFROG_API_KEY` – API key or access token
- `JFROG_REPO` – Repository on Jfrog, e.g. `docker-local`
- `CSPM_BASE_URL` - AccuKnox CSPM URL 
- `LABEL` - AccuKnox Label
- `ARTIFACT_TOKEN` - AccuKnox Artifact Token

## Jfrog Endpoint Overview
- "vulnerabilities": 
    - Defination - vulnerabilities/ issues in binaries
    - Endpoint - "/xray/api/v1/reports/vulnerabilities"
- "exposures": 
    - Defination - exposures can be - iac, sast, applications, secrets etc.
    - Endpoint - "/xray/api/v1/reports/exposures",                           
- "violations": 
    - Defination - policy violations/ custom violations
    - Endpoint - "/xray/api/v1/reports/violations",                       
- "licenses": 
    - Defination - sbom - software bill of materials
    - Endpoint - "/xray/api/v1/reports/licenses",                  
- "operationalRisks": 
    - Defination - sca - software component analysis
    - Endpoint - "/xray/api/v1/reports/operationalRisks",   

## Run locally
- By Defult SARIF and SEND-TO-ACCUKNOX is Enabled

```bash
pip install -r requirements.txt
export JFROG_URL=... JFROG_API_KEY=... JFROG_REPO=... CSPM_BASE_URL=... LABEL=... ARTIFACT_TOKEN=...
python jfrog_report.py
```

- Generate Output in SARIF - 
```bash
python3 jfrog_report.py --convert-to-sarif true

python3 jfrog_report.py --convert-to-sarif false
```

- Send Artifact to AccuKnox Control Plane
```bash
python3 jfrog_report.py --convert-to-sarif true --send-to-accuknox true

python3 jfrog_report.py --convert-to-sarif false --send-to-accuknox false
```

Outputs are written to `report_output/` as ZIP plus extracted JSON files.

## Notes
- Exposures run once per enabled exposure category for the repo; if none are enabled they are skipped.
- Failed or non-completed reports are skipped for export but logged to the console.
