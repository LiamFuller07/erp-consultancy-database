import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import http from "http";
import crypto from "crypto";
import { URL } from "url";

const OWNER = process.env.GITHUB_OWNER || "LiamFuller07";
const REPO = process.env.GITHUB_REPO || "erp-consultancy-database";
const BRANCH = process.env.GITHUB_BRANCH || "main";
const TOKEN = process.env.GITHUB_TOKEN;
const PORT = Number(process.env.PORT || process.env.MCP_PORT || 3333);
const API_KEY = process.env.MCP_API_KEY || "";

// OAuth 2.0 Configuration
const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID || "erp-mcp-client";
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET || "";
const OAUTH_REDIRECT_URIS = (process.env.OAUTH_REDIRECT_URIS || "https://claude.ai/oauth/callback").split(",").map(s => s.trim());

// Allow any claude.ai redirect URI for flexibility
function isValidRedirectUri(uri) {
  if (OAUTH_REDIRECT_URIS.includes(uri)) return true;
  try {
    const parsed = new URL(uri);
    return parsed.hostname === "claude.ai" || parsed.hostname.endsWith(".claude.ai");
  } catch {
    return false;
  }
}
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// In-memory token storage (use Redis/DB in production for multiple instances)
const authCodes = new Map(); // code -> { clientId, redirectUri, expiresAt }
const accessTokens = new Map(); // token -> { clientId, expiresAt }
const registeredClients = new Map(); // clientId -> { clientSecret, redirectUris, ... }

const AUTH_CODE_TTL = 5 * 60 * 1000; // 5 minutes
const ACCESS_TOKEN_TTL = 24 * 60 * 60 * 1000; // 24 hours

function generateToken() {
  return crypto.randomBytes(32).toString("hex");
}

function cleanExpiredTokens() {
  const now = Date.now();
  for (const [code, data] of authCodes) {
    if (data.expiresAt < now) authCodes.delete(code);
  }
  for (const [token, data] of accessTokens) {
    if (data.expiresAt < now) accessTokens.delete(token);
  }
}

// Clean expired tokens every 5 minutes
setInterval(cleanExpiredTokens, 5 * 60 * 1000);

function validateBearerToken(authHeader) {
  if (!authHeader || !authHeader.startsWith("Bearer ")) return false;
  const token = authHeader.slice(7);
  const data = accessTokens.get(token);
  if (!data) return false;
  if (data.expiresAt < Date.now()) {
    accessTokens.delete(token);
    return false;
  }
  return true;
}

// DCR: Validate client (static or dynamic)
function validateClient(clientId, clientSecret, redirectUri) {
  // Check static client first
  if (clientId === OAUTH_CLIENT_ID) {
    if (OAUTH_CLIENT_SECRET && clientSecret !== OAUTH_CLIENT_SECRET) {
      return { valid: false, error: "invalid_client_secret" };
    }
    if (redirectUri && !isValidRedirectUri(redirectUri)) {
      return { valid: false, error: "invalid_redirect_uri" };
    }
    return { valid: true };
  }

  // Check dynamically registered clients
  const client = registeredClients.get(clientId);
  if (!client) {
    return { valid: false, error: "unknown_client" };
  }

  if (clientSecret && client.client_secret !== clientSecret) {
    return { valid: false, error: "invalid_client_secret" };
  }

  if (redirectUri && !client.redirect_uris.includes(redirectUri) && !isValidRedirectUri(redirectUri)) {
    return { valid: false, error: "invalid_redirect_uri" };
  }

  return { valid: true, client };
}

// DCR: Generate client credentials
function generateClientCredentials() {
  return {
    client_id: `dyn-${crypto.randomBytes(16).toString("hex")}`,
    client_secret: crypto.randomBytes(32).toString("base64url")
  };
}

function isAuthorized(req) {
  // Check Bearer token first (OAuth)
  const authHeader = req.headers["authorization"];
  if (authHeader && validateBearerToken(authHeader)) {
    return true;
  }
  // Fall back to API key (legacy)
  if (API_KEY) {
    const provided = req.headers["x-api-key"];
    return provided === API_KEY;
  }
  // If no auth configured, allow (for development)
  return !OAUTH_CLIENT_SECRET && !API_KEY;
}

const REGION_SET = new Set(["australasia", "north_america", "europe"]);
const PRIORITY_SET = new Set(["HIGH", "MEDIUM", "LOWER", "LOW", "HIGHEST"]);
const REQUIRED_FIELDS = ["id", "rank", "priority", "company_name", "country"];
const OPTIONAL_FIELDS = [
  "city",
  "state",
  "employees",
  "erp_systems",
  "website",
  "decision_makers",
  "why_target",
  "notable_clients",
  "awards"
];

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

const getRegionCompactSchema = z.object({
  region: regionSchema
});

const searchRegionSchema = z.object({
  region: regionSchema,
  query: z.string(),
  fields: z.array(z.string()).optional()
});

const getInstructionsSchema = z.object({});
const listFilesSchema = z.object({});
const getFileSchema = z.object({
  path: z.string()
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

function normalizeRow(row, region) {
  const errors = [];
  REQUIRED_FIELDS.forEach((field) => {
    if (row[field] === undefined || row[field] === null || row[field] === "") {
      errors.push(field);
    }
  });
  if (errors.length) {
    throw new Error(`Missing required fields (${region}): ${errors.join(", ")}`);
  }
  return {
    id: row.id,
    rank: row.rank,
    priority: normalizePriority(row.priority),
    company_name: row.company_name,
    country: row.country,
    city: row.city || "",
    state: row.state || "",
    employees: row.employees || "",
    erp_systems: Array.isArray(row.erp_systems) ? row.erp_systems : [],
    website: row.website || "",
    decision_makers: normalizeDecisionMakers(row.decision_makers || []),
    why_target: row.why_target || "",
    notable_clients: row.notable_clients || "",
    awards: row.awards || ""
  };
}

function normalizeDataset(region, data) {
  if (!data || !Array.isArray(data.consultancies)) {
    throw new Error("Dataset must include consultancies[]");
  }
  const cleaned = data.consultancies.map((row) => normalizeRow(row, region));
  return { ...data, region, consultancies: cleaned };
}

function toCompact(json) {
  const columns = [
    "id",
    "rank",
    "priority",
    "company_name",
    "country",
    "city",
    "state",
    "employees",
    "erp_systems",
    "website",
    "decision_makers"
  ];
  const rows = (json.consultancies || []).map((row) => {
    return columns.map((col) => {
      const value = row[col];
      if (Array.isArray(value)) return value.join(", ");
      if (col === "decision_makers") return (value || []).map((d) => `${d.name} (${d.title})`).join("; ");
      return value ?? "";
    });
  });
  return { columns, rows };
}

function toText(json) {
  return (json.consultancies || []).map((row) => {
    const dm = (row.decision_makers || [])
      .map((d) => `${d.name}${d.title ? ` - ${d.title}` : ""}${d.linkedin_url ? ` (${d.linkedin_url})` : ""}`)
      .join("; ");
    return [
      row.rank,
      row.priority,
      row.company_name,
      row.country,
      row.city || "",
      row.state || "",
      row.erp_systems ? row.erp_systems.join(", ") : "",
      row.website || "",
      dm
    ].filter(Boolean).join(" | ");
  }).join("\n");
}

function getStats(json) {
  const rows = json.consultancies || [];
  const ranks = rows.map((r) => Number(r.rank)).filter((r) => !Number.isNaN(r));
  return {
    count: rows.length,
    min_rank: ranks.length ? Math.min(...ranks) : null,
    max_rank: ranks.length ? Math.max(...ranks) : null
  };
}

function rowMatches(row, query, fields) {
  const needle = String(query).toLowerCase();
  const searchFields = fields && fields.length ? fields : Object.keys(row);
  return searchFields.some((field) => {
    const value = row[field];
    if (Array.isArray(value)) {
      return value.join(" ").toLowerCase().includes(needle);
    }
    if (typeof value === "object" && value !== null) {
      return JSON.stringify(value).toLowerCase().includes(needle);
    }
    return String(value ?? "").toLowerCase().includes(needle);
  });
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

  if (name === "get_region_compact") {
    const { region } = getRegionCompactSchema.parse(args);
    const path = getRegionPath(region);
    const { json } = await getJsonFile(path);
    return toCompact(json);
  }

  if (name === "get_region_text") {
    const { region } = getRegionCompactSchema.parse(args);
    const path = getRegionPath(region);
    const { json } = await getJsonFile(path);
    return { text: toText(json) };
  }

  if (name === "search_region") {
    const { region, query, fields } = searchRegionSchema.parse(args);
    const path = getRegionPath(region);
    const { json } = await getJsonFile(path);
    const rows = (json.consultancies || []).filter((row) => rowMatches(row, query, fields));
    return {
      count: rows.length,
      results: rows
    };
  }

  if (name === "get_instructions") {
    const regions = Array.from(REGION_SET);
    const stats = {};
    for (const region of regions) {
      const { json } = await getJsonFile(getRegionPath(region));
      stats[region] = getStats(json);
    }
    return {
      description: "ERP Consultancy MCP. Use tools to query and update regional JSON data that powers the GitHub Pages UI.",
      required_fields: REQUIRED_FIELDS,
      optional_fields: OPTIONAL_FIELDS,
      priority_values: Array.from(PRIORITY_SET),
      stats,
      files: [
        `https://raw.githubusercontent.com/${OWNER}/${REPO}/${BRANCH}/data/australasia.json`,
        `https://raw.githubusercontent.com/${OWNER}/${REPO}/${BRANCH}/data/north_america.json`,
        `https://raw.githubusercontent.com/${OWNER}/${REPO}/${BRANCH}/data/europe.json`
      ],
      pages_url: `https://${OWNER.toLowerCase()}.github.io/${REPO}/`
    };
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
      rows[idx] = normalizeRow({ ...rows[idx], ...patch }, region);
    } else {
      const newId = id || `${region}-new-${Date.now()}`;
      const nextRank = rows.reduce((max, r) => Math.max(max, Number(r.rank) || 0), 0) + 1;
      const newRow = normalizeRow({
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
      required_fields: REQUIRED_FIELDS,
      optional_fields: OPTIONAL_FIELDS,
      priority_values: Array.from(PRIORITY_SET)
    };
  }

  if (name === "list_files") {
    return {
      files: [
        "data/australasia.json",
        "data/north_america.json",
        "data/europe.json"
      ]
    };
  }

  if (name === "get_file") {
    const { path } = getFileSchema.parse(args);
    if (!path.startsWith("data/")) {
      throw new Error("Only data/* files are accessible.");
    }
    const { json } = await getJsonFile(path);
    return json;
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
        name: "get_region_compact",
        description: "Fetch a region dataset as {columns, rows} for LLMs.",
        inputSchema: getRegionCompactSchema
      },
      {
        name: "get_region_text",
        description: "Fetch a region dataset as text lines for LLMs.",
        inputSchema: getRegionCompactSchema
      },
      {
        name: "search_region",
        description: "Search a region dataset by query string.",
        inputSchema: searchRegionSchema
      },
      {
        name: "get_instructions",
        description: "Return MCP usage instructions, schema, and dataset stats.",
        inputSchema: getInstructionsSchema
      },
      {
        name: "list_files",
        description: "List available data files.",
        inputSchema: listFilesSchema
      },
      {
        name: "get_file",
        description: "Fetch a data file (data/* only).",
        inputSchema: getFileSchema
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
      },
      {
        name: "get_schema",
        description: "Return required/optional fields and valid priority values.",
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

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", chunk => { body += chunk; });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

function sendJson(res, status, data, cors = true) {
  const headers = { "Content-Type": "application/json" };
  if (cors) headers["Access-Control-Allow-Origin"] = "*";
  res.writeHead(status, headers);
  res.end(JSON.stringify(data));
}

function sendRedirect(res, url) {
  res.writeHead(302, { "Location": url });
  res.end();
}

const httpServer = http.createServer(async (req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
  const pathname = parsedUrl.pathname;

  // CORS preflight
  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Api-Key"
    });
    res.end();
    return;
  }

  // OAuth: Discovery endpoint
  if (req.method === "GET" && pathname === "/.well-known/oauth-authorization-server") {
    const baseUrl = process.env.BASE_URL || `https://${req.headers.host}`;
    sendJson(res, 200, {
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/oauth/authorize`,
      token_endpoint: `${baseUrl}/oauth/token`,
      registration_endpoint: `${baseUrl}/oauth/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      token_endpoint_auth_methods_supported: ["client_secret_post"],
      code_challenge_methods_supported: ["S256"]
    });
    return;
  }

  // OAuth: Protected Resource Metadata (RFC 8707)
  if (req.method === "GET" && pathname === "/.well-known/oauth-protected-resource") {
    const baseUrl = process.env.BASE_URL || `https://${req.headers.host}`;
    sendJson(res, 200, {
      resource: `${baseUrl}/mcp`,
      authorization_servers: [baseUrl],
      bearer_methods_supported: ["header"],
      scopes_supported: ["mcp:read", "mcp:write"]
    });
    return;
  }

  // OAuth: Dynamic Client Registration (RFC 7591)
  if (req.method === "POST" && pathname === "/oauth/register") {
    try {
      const body = await parseBody(req);
      const registration = JSON.parse(body || "{}");

      // Generate client credentials
      const creds = generateClientCredentials();
      const client_id = creds.client_id;
      const client_secret = creds.client_secret;

      // Extract redirect URIs (required)
      const redirect_uris = registration.redirect_uris || [];
      if (!Array.isArray(redirect_uris) || redirect_uris.length === 0) {
        sendJson(res, 400, { error: "invalid_request", error_description: "redirect_uris required" });
        return;
      }

      // Store registered client
      const clientData = {
        client_id,
        client_secret,
        redirect_uris,
        client_name: registration.client_name || "Dynamic Client",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        token_endpoint_auth_method: "client_secret_post",
        created_at: Date.now()
      };
      registeredClients.set(client_id, clientData);

      // Return registration response
      sendJson(res, 201, {
        client_id,
        client_secret,
        client_secret_expires_at: 0, // Never expires
        redirect_uris,
        client_name: clientData.client_name,
        grant_types: clientData.grant_types,
        response_types: clientData.response_types,
        token_endpoint_auth_method: clientData.token_endpoint_auth_method
      });
      return;
    } catch (err) {
      sendJson(res, 400, { error: "invalid_request", error_description: err.message });
      return;
    }
  }

  // OAuth: Authorization endpoint
  if (req.method === "GET" && pathname === "/oauth/authorize") {
    const clientId = parsedUrl.searchParams.get("client_id");
    const redirectUri = parsedUrl.searchParams.get("redirect_uri");
    const state = parsedUrl.searchParams.get("state");
    const responseType = parsedUrl.searchParams.get("response_type");

    // Validate client (static or dynamic)
    const clientValidation = validateClient(clientId, null, redirectUri);
    if (!clientValidation.valid) {
      if (clientValidation.error === "unknown_client") {
        sendJson(res, 400, { error: "invalid_client", error_description: "Unknown client_id" });
        return;
      }
      if (clientValidation.error === "invalid_redirect_uri") {
        sendJson(res, 400, { error: "invalid_request", error_description: "Invalid redirect_uri" });
        return;
      }
    }

    // Validate redirect_uri exists
    if (!redirectUri) {
      sendJson(res, 400, { error: "invalid_request", error_description: "redirect_uri required" });
      return;
    }

    // Validate response_type
    if (responseType !== "code") {
      sendRedirect(res, `${redirectUri}?error=unsupported_response_type&state=${state || ""}`);
      return;
    }

    // Generate auth code and redirect back
    const code = generateToken();
    authCodes.set(code, {
      clientId,
      redirectUri,
      expiresAt: Date.now() + AUTH_CODE_TTL
    });

    const callbackUrl = new URL(redirectUri);
    callbackUrl.searchParams.set("code", code);
    if (state) callbackUrl.searchParams.set("state", state);
    sendRedirect(res, callbackUrl.toString());
    return;
  }

  // OAuth: Token endpoint
  if (req.method === "POST" && pathname === "/oauth/token") {
    const body = await parseBody(req);
    const params = new URLSearchParams(body);
    const grantType = params.get("grant_type");
    const code = params.get("code");
    const clientId = params.get("client_id");
    const clientSecret = params.get("client_secret");
    const redirectUri = params.get("redirect_uri");

    // Validate grant type
    if (grantType !== "authorization_code") {
      sendJson(res, 400, { error: "unsupported_grant_type" });
      return;
    }

    // Validate client (static or dynamic)
    const clientValidation = validateClient(clientId, clientSecret, null);
    if (!clientValidation.valid) {
      sendJson(res, 400, { error: "invalid_client", error_description: clientValidation.error });
      return;
    }

    // Validate auth code
    const authCode = authCodes.get(code);
    if (!authCode) {
      sendJson(res, 400, { error: "invalid_grant", error_description: "Invalid or expired code" });
      return;
    }

    if (authCode.expiresAt < Date.now()) {
      authCodes.delete(code);
      sendJson(res, 400, { error: "invalid_grant", error_description: "Code expired" });
      return;
    }

    if (authCode.clientId !== clientId || authCode.redirectUri !== redirectUri) {
      sendJson(res, 400, { error: "invalid_grant", error_description: "Code mismatch" });
      return;
    }

    // Consume auth code
    authCodes.delete(code);

    // Generate access token
    const accessToken = generateToken();
    accessTokens.set(accessToken, {
      clientId,
      expiresAt: Date.now() + ACCESS_TOKEN_TTL
    });

    sendJson(res, 200, {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: Math.floor(ACCESS_TOKEN_TTL / 1000)
    });
    return;
  }

  // MCP endpoint - GET for instructions
  if (req.method === "GET" && pathname === "/mcp") {
    if (!isAuthorized(req)) {
      sendJson(res, 401, { ok: false, error: "Unauthorized" });
      return;
    }
    try {
      const result = await callTool("get_instructions", {});
      sendJson(res, 200, { ok: true, result });
    } catch (err) {
      sendJson(res, 500, { ok: false, error: err.message });
    }
    return;
  }

  // MCP endpoint - POST for tool calls
  if (req.method === "POST" && pathname === "/mcp") {
    if (!isAuthorized(req)) {
      sendJson(res, 401, { ok: false, error: "Unauthorized" });
      return;
    }
    try {
      const body = await parseBody(req);
      const payload = JSON.parse(body || "{}");
      const result = await callTool(payload.tool, payload.arguments || {});
      sendJson(res, 200, { ok: true, result });
    } catch (err) {
      sendJson(res, 400, { ok: false, error: err.message });
    }
    return;
  }

  // Not found
  sendJson(res, 404, { error: "Not found" });
});

httpServer.listen(PORT, () => {
  process.stderr.write(`MCP HTTP bridge listening on http://localhost:${PORT}/mcp\n`);
  process.stderr.write(`OAuth endpoints: /oauth/authorize, /oauth/token\n`);
  process.stderr.write(`Discovery: /.well-known/oauth-authorization-server\n`);
});
