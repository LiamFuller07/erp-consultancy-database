#!/usr/bin/env bash
set -euo pipefail

ENDPOINT=${1:-"https://mcp-server-production-fa25.up.railway.app/mcp"}

payload='{
  "tool": "upsert_company",
  "arguments": {
    "region": "australasia",
    "id": "au-000",
    "company_name": "TBD",
    "patch": {
      "rank": 1,
      "priority": "HIGH",
      "company_name": "TBD",
      "country": "Australia",
      "city": "",
      "state": "",
      "employees": "",
      "erp_systems": [],
      "website": "",
      "decision_makers": [],
      "why_target": "",
      "notable_clients": "",
      "awards": ""
    }
  }
}'

echo "Sending upsert to MCP..."
curl -s "$ENDPOINT" -H 'Content-Type: application/json' -d "$payload"

echo "\nDone."
