#!/usr/bin/env bash
set -euo pipefail

ENDPOINT=${1:-"https://mcp-server-production-fa25.up.railway.app/mcp"}

echo "Testing get_instructions..."
curl -s "$ENDPOINT" -H 'Content-Type: application/json' -d '{"tool":"get_instructions","arguments":{}}' | head -c 300

echo
echo "Testing list_regions..."
curl -s "$ENDPOINT" -H 'Content-Type: application/json' -d '{"tool":"list_regions","arguments":{}}'

echo
echo "Testing search_region (NetSuite)..."
curl -s "$ENDPOINT" -H 'Content-Type: application/json' -d '{"tool":"search_region","arguments":{"region":"north_america","query":"NetSuite"}}' | head -c 300

echo
echo "Done."
