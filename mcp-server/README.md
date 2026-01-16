# ERP Consultancy MCP Server

This MCP server exposes tools to read and update the ERP consultancy JSON files in GitHub. It updates the GitHub Pages data by writing to the repo via the GitHub Contents API.

## Setup

```bash
cd mcp-server
npm install
export GITHUB_TOKEN=YOUR_TOKEN
export GITHUB_OWNER=LiamFuller07
export GITHUB_REPO=erp-consultancy-database
export GITHUB_BRANCH=main
npm start
```

## Tools

- `list_regions` -> returns `australasia, north_america, europe`
- `get_region` `{ region }`
- `replace_region` `{ region, data }`
- `upsert_company` `{ region, id?, company_name?, patch }`

## Notes

- All updates write to `data/{region}.json` in the repo.
- Pages will rebuild automatically after updates.
