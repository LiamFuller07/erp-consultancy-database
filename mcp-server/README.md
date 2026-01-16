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
export MCP_PORT=3333
export MCP_API_KEY=your_shared_key
# Railway provides PORT automatically in production.
npm start
```

## Tools

- `list_regions` -> returns `australasia, north_america, europe`
- `get_region` `{ region }`
- `get_region_compact` `{ region }` -> `{ columns, rows }`
- `get_region_text` `{ region }` -> `{ text }`
- `search_region` `{ region, query, fields? }` -> `{ count, results }`
- `get_instructions` `{}` -> `{ description, required_fields, optional_fields, priority_values, stats, files, pages_url }`
- `list_files` `{}` -> `{ files }`
- `get_file` `{ path }` -> JSON (data/* only)
- `replace_region` `{ region, data }`
- `upsert_company` `{ region, id?, company_name?, patch }`
- `get_schema` `{}` -> required/optional fields + valid priority values

## Notes

- All updates write to `data/{region}.json` in the repo.
- Pages will rebuild automatically after updates.
- Validation is enforced: each row must include `id`, `rank`, `priority`, `company_name`, `country`.
- All optional fields are normalized and included in every row (empty string/array if missing).

## Quick Test

```bash
curl -s https://mcp-server-production-fa25.up.railway.app/mcp \\
  -H 'Content-Type: application/json' \\
  -d '{\"tool\":\"get_instructions\",\"arguments\":{}}'
```

## HTTP Bridge

The server also exposes a simple HTTP endpoint so you can call it directly from the UI or other LLMs:

```
POST http://localhost:3333/mcp
{
  \"tool\": \"upsert_company\",
  \"arguments\": {
    \"region\": \"north_america\",
    \"company_name\": \"Example Co\",
    \"patch\": { \"priority\": \"HIGH\" }
  }
}
```

## Auth

If `MCP_API_KEY` is set, clients must send:

```
X-Api-Key: your_shared_key
```
