import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import http from "http";

const OWNER = process.env.GITHUB_OWNER || "LiamFuller07";
const REPO = process.env.GITHUB_REPO || "erp-consultancy-database";
const BRANCH = process.env.GITHUB_BRANCH || "main";
const TOKEN = process.env.GITHUB_TOKEN;
const PORT = Number(process.env.PORT || process.env.MCP_PORT || 3333);

const REGION_SET = new Set(["australasia", "north_america", "europe"]);
const PRIORITY_SET = new Set(["HIGH", "MEDIUM", "LOWER", "LOW", "HIGHEST"]);

if (!TOKEN) {
  process.stderr.write("Missing GITHUB_TOKEN. Export it before running.\n");
  process.exit(1);
}

function apiUrl(path) {
  return `https://api.github.com/repos/${OWNER}/${REPO}/contents/${path}?ref=${BRANCH}`;
}

async function githubFetch(path, options = {}) {
  const res = await fetch(apiUrl(path), {
    ...options,
    headers: {
      "Accept": "application/vnd.github+json",
      "Authorization": `Bearer ${TOKEN}`,
      "X-GitHub-Api-Version": "2022-11-28",
      ...(options.headers || {})
    }
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GitHub API error (${res.status}): ${text}`);
  }
  return res.json();
}

async function getJsonFile(path) {
  const data = await githubFetch(path);
  if (!data.content) {
    throw new Error(`No content for ${path}`);
  }
  const decoded = Buffer.from(data.content, "base64").toString("utf-8");
  return { json: JSON.parse(decoded), sha: data.sha };
}

async function putJsonFile(path, json, message, sha) {
  const content = Buffer.from(JSON.stringify(json, null, 2), "utf-8").toString("base64");
  const body = {
    message,
    content,
    sha
  };

  const res = await fetch(`https://api.github.com/repos/${OWNER}/${REPO}/contents/${path}`, {
    method: "PUT",
    headers: {
      "Accept": "application/vnd.github+json",
      "Authorization": `Bearer ${TOKEN}`,
      "X-GitHub-Api-Version": "2022-11-28"
    },
    body: JSON.stringify(body)
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GitHub PUT error (${res.status}): ${text}`);
  }

  return res.json();
}

const regionSchema = z.enum(["australasia", "north_america", "europe"]);

const replaceRegionSchema = z.object({
  region: regionSchema,
  data: z.any()
});

const getRegionSchema = z.object({
  region: regionSchema
});

const upsertCompanySchema = z.object({
  region: regionSchema,
  id: z.string().optional(),
  company_name: z.string().optional(),
  patch: z.record(z.any())
});

function getRegionPath(region) {
  return `data/${region}.json`;
}

function normalizeText(value) {
  return (value || "").trim().toLowerCase();
}

function findCompanyIndex(rows, id, name) {
  if (id) {
    const idx = rows.findIndex(r => r.id === id);
    if (idx >= 0) return idx;
  }
  if (name) {
    const needle = normalizeText(name);
    return rows.findIndex(r => normalizeText(r.company_name) === needle);
  }
  return -1;
}

function normalizePriority(value) {
  if (!value) return "MEDIUM";
  const norm = String(value).trim().toUpperCase();
  if (!PRIORITY_SET.has(norm)) {
    throw new Error(`Invalid priority: ${value}`);
  }
  return norm;
}

function normalizeDecisionMakers(value) {
  if (!Array.isArray(value)) return [];
  return value.map((entry) => ({
    name: entry?.name ? String(entry.name).trim() : "",
    title: entry?.title ? String(entry.title).trim() : "",
    linkedin_url: entry?.linkedin_url ? String(entry.linkedin_url).trim() : ""
  }));
}

function validateRow(row, region) {
  const errors = [];
  if (!row.company_name) errors.push("company_name");
  if (!row.country) errors.push("country");
  if (row.rank === undefined || row.rank === null || row.rank === "") errors.push("rank");
  if (!row.id) errors.push("id");
  if (errors.length) {
    throw new Error(`Missing required fields (${region}): ${errors.join(", ")}`);
  }
  return {
    ...row,
    priority: normalizePriority(row.priority),
    decision_makers: normalizeDecisionMakers(row.decision_makers || [])
  };
}

function normalizeDataset(region, data) {
  if (!data || !Array.isArray(data.consultancies)) {
    throw new Error("Dataset must include consultancies[]");
  }
  const cleaned = data.consultancies.map((row) => validateRow(row, region));
  return { ...data, region, consultancies: cleaned };
}

async function callTool(name, args) {
  if (name === "list_regions") {
    return Array.from(REGION_SET);
  }

  if (name === "get_region") {
    const { region } = getRegionSchema.parse(args);
    const path = getRegionPath(region);
    const { json } = await getJsonFile(path);
    return json;
  }

  if (name === "replace_region") {
    const { region, data } = replaceRegionSchema.parse(args);
    const path = getRegionPath(region);
    const { sha } = await getJsonFile(path);
    const payload = normalizeDataset(region, {
      ...data,
      last_updated: new Date().toISOString()
    });
    await putJsonFile(path, payload, `Replace ${region} dataset`, sha);
    return { status: "ok", message: `Replaced ${region} dataset.` };
  }

  if (name === "upsert_company") {
    const { region, id, company_name, patch } = upsertCompanySchema.parse(args);
    const path = getRegionPath(region);
    const { json, sha } = await getJsonFile(path);
    const rows = Array.isArray(json.consultancies) ? json.consultancies : [];
    const idx = findCompanyIndex(rows, id, company_name);

    if (idx >= 0) {
      rows[idx] = validateRow({ ...rows[idx], ...patch }, region);
    } else {
      const newId = id || `${region}-new-${Date.now()}`;
      const nextRank = rows.reduce((max, r) => Math.max(max, Number(r.rank) || 0), 0) + 1;
      const newRow = validateRow({
        id: newId,
        rank: patch.rank ?? nextRank,
        priority: patch.priority ?? "MEDIUM",
        company_name: company_name || patch.company_name,
        country: patch.country,
        ...patch
      }, region);
      rows.push(newRow);
    }

    const payload = { ...json, consultancies: rows, last_updated: new Date().toISOString() };
    await putJsonFile(path, payload, `Upsert company in ${region}`, sha);
    return { status: "ok", message: `Upserted company in ${region}.` };
  }

  if (name === "get_schema") {
    return {
      required_fields: ["id", "rank", "priority", "company_name", "country"],
      optional_fields: [
        "city",
        "state",
        "employees",
        "erp_systems",
        "website",
        "decision_makers",
        "why_target",
        "notable_clients",
        "awards"
      ],
      priority_values: Array.from(PRIORITY_SET)
    };
  }

  throw new Error(`Unknown tool: ${name}`);
}

const server = new Server(
  { name: "erp-consultancy-mcp", version: "0.2.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "get_region",
        description: "Fetch a region JSON dataset from GitHub.",
        inputSchema: getRegionSchema
      },
      {
        name: "get_schema",
        description: "Return required/optional fields and valid priority values.",
        inputSchema: z.object({})
      },
      {
        name: "replace_region",
        description: "Replace a region JSON dataset in GitHub (full overwrite).",
        inputSchema: replaceRegionSchema
      },
      {
        name: "upsert_company",
        description: "Update or insert a company record in a region JSON.",
        inputSchema: upsertCompanySchema
      },
      {
        name: "list_regions",
        description: "List available regions.",
        inputSchema: z.object({})
      }
    ]
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const result = await callTool(name, args || {});
  return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
});

const transport = new StdioServerTransport();
await server.connect(transport);

const httpServer = http.createServer(async (req, res) => {
  if (req.method !== "POST" || req.url !== "/mcp") {
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found" }));
    return;
  }

  let body = "";
  req.on("data", chunk => { body += chunk; });
  req.on("end", async () => {
    try {
      const payload = JSON.parse(body || "{}");
      const result = await callTool(payload.tool, payload.arguments || {});
      res.writeHead(200, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
      res.end(JSON.stringify({ ok: true, result }));
    } catch (err) {
      res.writeHead(400, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
      res.end(JSON.stringify({ ok: false, error: err.message }));
    }
  });
});

httpServer.listen(PORT, () => {
  process.stderr.write(`MCP HTTP bridge listening on http://localhost:${PORT}/mcp\n`);
});
