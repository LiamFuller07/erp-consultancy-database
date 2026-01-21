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
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// MCP Protocol Version
const MCP_PROTOCOL_VERSION = "2025-03-26";

// Session management
const sessions = new Map(); // sessionId -> { clientInfo, initialized }
const authCodes = new Map();
const accessTokens = new Map();
const registeredClients = new Map();

const AUTH_CODE_TTL = 5 * 60 * 1000;
const ACCESS_TOKEN_TTL = 24 * 60 * 60 * 1000;

// ============ Utility Functions ============

function generateToken() {
  return crypto.randomBytes(32).toString("hex");
}

function generateSessionId() {
  return crypto.randomUUID();
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

setInterval(cleanExpiredTokens, 5 * 60 * 1000);

// ============ OAuth Functions ============

function isValidRedirectUri(uri) {
  if (OAUTH_REDIRECT_URIS.includes(uri)) return true;
  try {
    const parsed = new URL(uri);
    return parsed.hostname === "claude.ai" || parsed.hostname.endsWith(".claude.ai");
  } catch {
    return false;
  }
}

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

function validateClient(clientId, clientSecret, redirectUri, requireSecret = false) {
  if (clientId === OAUTH_CLIENT_ID) {
    // Only check secret if explicitly required (token endpoint)
    if (requireSecret && OAUTH_CLIENT_SECRET && clientSecret !== OAUTH_CLIENT_SECRET) {
      return { valid: false, error: "invalid_client_secret" };
    }
    if (redirectUri && !isValidRedirectUri(redirectUri)) {
      return { valid: false, error: "invalid_redirect_uri" };
    }
    return { valid: true };
  }
  const client = registeredClients.get(clientId);
  if (!client) return { valid: false, error: "unknown_client" };
  // Only check secret if explicitly required (token endpoint)
  if (requireSecret && clientSecret !== client.client_secret) {
    return { valid: false, error: "invalid_client_secret" };
  }
  if (redirectUri && !client.redirect_uris.includes(redirectUri) && !isValidRedirectUri(redirectUri)) {
    return { valid: false, error: "invalid_redirect_uri" };
  }
  return { valid: true, client };
}

function generateClientCredentials() {
  return {
    client_id: `dyn-${crypto.randomBytes(16).toString("hex")}`,
    client_secret: crypto.randomBytes(32).toString("base64url")
  };
}

function isAuthorized(req) {
  const authHeader = req.headers["authorization"];
  if (authHeader && validateBearerToken(authHeader)) return true;
  if (API_KEY) return req.headers["x-api-key"] === API_KEY;
  return !OAUTH_CLIENT_SECRET && !API_KEY;
}

// ============ GitHub API Functions ============

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
  if (!data.content) throw new Error(`No content for ${path}`);
  const decoded = Buffer.from(data.content, "base64").toString("utf-8");
  return { json: JSON.parse(decoded), sha: data.sha };
}

async function putJsonFile(path, json, message, sha) {
  const content = Buffer.from(JSON.stringify(json, null, 2), "utf-8").toString("base64");
  const res = await fetch(`https://api.github.com/repos/${OWNER}/${REPO}/contents/${path}`, {
    method: "PUT",
    headers: {
      "Accept": "application/vnd.github+json",
      "Authorization": `Bearer ${TOKEN}`,
      "X-GitHub-Api-Version": "2022-11-28"
    },
    body: JSON.stringify({ message, content, sha })
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GitHub PUT error (${res.status}): ${text}`);
  }
  return res.json();
}

// ============ Data Processing Functions ============

const REGION_SET = new Set(["australasia", "north_america", "europe"]);
const PRIORITY_SET = new Set(["HIGH", "MEDIUM", "LOWER", "LOW", "HIGHEST"]);
const REQUIRED_FIELDS = ["id", "rank", "priority", "company_name", "country"];
const OPTIONAL_FIELDS = ["city", "state", "employees", "erp_systems", "website", "decision_makers", "why_target", "notable_clients", "awards", "checked"];

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
  if (!PRIORITY_SET.has(norm)) throw new Error(`Invalid priority: ${value}`);
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
    if (row[field] === undefined || row[field] === null || row[field] === "") errors.push(field);
  });
  if (errors.length) throw new Error(`Missing required fields (${region}): ${errors.join(", ")}`);
  return {
    id: row.id, rank: row.rank, priority: normalizePriority(row.priority),
    company_name: row.company_name, country: row.country,
    city: row.city || "", state: row.state || "", employees: row.employees || "",
    erp_systems: Array.isArray(row.erp_systems) ? row.erp_systems : [],
    website: row.website || "",
    decision_makers: normalizeDecisionMakers(row.decision_makers || []),
    why_target: row.why_target || "", notable_clients: row.notable_clients || "", awards: row.awards || "",
    checked: Boolean(row.checked)
  };
}

function normalizeDataset(region, data) {
  if (!data || !Array.isArray(data.consultancies)) throw new Error("Dataset must include consultancies[]");
  const cleaned = data.consultancies.map((row) => normalizeRow(row, region));
  return { ...data, region, consultancies: cleaned };
}

function toCompact(json) {
  const columns = ["id", "rank", "priority", "company_name", "country", "city", "state", "employees", "erp_systems", "website", "decision_makers"];
  const rows = (json.consultancies || []).map((row) => columns.map((col) => {
    const value = row[col];
    if (Array.isArray(value)) return value.join(", ");
    if (col === "decision_makers") return (value || []).map((d) => `${d.name} (${d.title})`).join("; ");
    return value ?? "";
  }));
  return { columns, rows };
}

function getStats(json) {
  const rows = json.consultancies || [];
  const ranks = rows.map((r) => Number(r.rank)).filter((r) => !Number.isNaN(r));
  return { count: rows.length, min_rank: ranks.length ? Math.min(...ranks) : null, max_rank: ranks.length ? Math.max(...ranks) : null };
}

function rowMatches(row, query, fields) {
  const needle = String(query).toLowerCase();
  const searchFields = fields && fields.length ? fields : Object.keys(row);
  return searchFields.some((field) => {
    const value = row[field];
    if (Array.isArray(value)) return value.join(" ").toLowerCase().includes(needle);
    if (typeof value === "object" && value !== null) return JSON.stringify(value).toLowerCase().includes(needle);
    return String(value ?? "").toLowerCase().includes(needle);
  });
}

// ============ MCP Tool Definitions ============

const TOOLS = [
  { name: "get_region", description: "Fetch a region JSON dataset from GitHub.", inputSchema: { type: "object", properties: { region: { type: "string", enum: ["australasia", "north_america", "europe"] } }, required: ["region"] } },
  { name: "get_region_compact", description: "Fetch a region dataset as {columns, rows} for LLMs.", inputSchema: { type: "object", properties: { region: { type: "string", enum: ["australasia", "north_america", "europe"] } }, required: ["region"] } },
  { name: "search_region", description: "Search a region dataset by query string.", inputSchema: { type: "object", properties: { region: { type: "string" }, query: { type: "string" }, fields: { type: "array", items: { type: "string" } } }, required: ["region", "query"] } },
  { name: "get_instructions", description: "Return MCP usage instructions, schema, and dataset stats.", inputSchema: { type: "object", properties: {} } },
  { name: "list_files", description: "List available data files.", inputSchema: { type: "object", properties: {} } },
  { name: "get_file", description: "Fetch a data file (data/* only).", inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"] } },
  { name: "replace_region", description: "Replace a region JSON dataset in GitHub (full overwrite).", inputSchema: { type: "object", properties: { region: { type: "string" }, data: { type: "object" } }, required: ["region", "data"] } },
  { name: "upsert_company", description: "Update or insert a company record in a region JSON.", inputSchema: { type: "object", properties: { region: { type: "string" }, id: { type: "string" }, company_name: { type: "string" }, patch: { type: "object" } }, required: ["region", "patch"] } },
  { name: "list_regions", description: "List available regions.", inputSchema: { type: "object", properties: {} } },
  { name: "get_schema", description: "Return required/optional fields and valid priority values.", inputSchema: { type: "object", properties: {} } }
];

async function callTool(name, args) {
  if (name === "list_regions") return Array.from(REGION_SET);
  if (name === "get_region") {
    const { json } = await getJsonFile(getRegionPath(args.region));
    return json;
  }
  if (name === "get_region_compact") {
    const { json } = await getJsonFile(getRegionPath(args.region));
    return toCompact(json);
  }
  if (name === "search_region") {
    const { json } = await getJsonFile(getRegionPath(args.region));
    const rows = (json.consultancies || []).filter((row) => rowMatches(row, args.query, args.fields));
    return { count: rows.length, results: rows };
  }
  if (name === "get_instructions") {
    const stats = {};
    for (const region of REGION_SET) {
      const { json } = await getJsonFile(getRegionPath(region));
      stats[region] = getStats(json);
    }
    return { description: "ERP Consultancy MCP. Use tools to query and update regional JSON data.", required_fields: REQUIRED_FIELDS, optional_fields: OPTIONAL_FIELDS, priority_values: Array.from(PRIORITY_SET), stats };
  }
  if (name === "replace_region") {
    const { sha } = await getJsonFile(getRegionPath(args.region));
    const payload = normalizeDataset(args.region, { ...args.data, last_updated: new Date().toISOString() });
    await putJsonFile(getRegionPath(args.region), payload, `Replace ${args.region} dataset`, sha);
    return { status: "ok", message: `Replaced ${args.region} dataset.` };
  }
  if (name === "upsert_company") {
    const path = getRegionPath(args.region);
    const { json, sha } = await getJsonFile(path);
    const rows = Array.isArray(json.consultancies) ? json.consultancies : [];
    const idx = findCompanyIndex(rows, args.id, args.company_name);
    if (idx >= 0) {
      rows[idx] = normalizeRow({ ...rows[idx], ...args.patch }, args.region);
    } else {
      const newId = args.id || `${args.region}-new-${Date.now()}`;
      const nextRank = rows.reduce((max, r) => Math.max(max, Number(r.rank) || 0), 0) + 1;
      rows.push(normalizeRow({ id: newId, rank: args.patch.rank ?? nextRank, priority: args.patch.priority ?? "MEDIUM", company_name: args.company_name || args.patch.company_name, country: args.patch.country, ...args.patch }, args.region));
    }
    await putJsonFile(path, { ...json, consultancies: rows, last_updated: new Date().toISOString() }, `Upsert company in ${args.region}`, sha);
    return { status: "ok", message: `Upserted company in ${args.region}.` };
  }
  if (name === "get_schema") return { required_fields: REQUIRED_FIELDS, optional_fields: OPTIONAL_FIELDS, priority_values: Array.from(PRIORITY_SET) };
  if (name === "list_files") return { files: ["data/australasia.json", "data/north_america.json", "data/europe.json"] };
  if (name === "get_file") {
    if (!args.path.startsWith("data/")) throw new Error("Only data/* files are accessible.");
    const { json } = await getJsonFile(args.path);
    return json;
  }
  throw new Error(`Unknown tool: ${name}`);
}

// ============ MCP JSON-RPC Handler ============

async function handleJsonRpcRequest(message, sessionId) {
  const { jsonrpc, id, method, params } = message;

  if (jsonrpc !== "2.0") {
    return { jsonrpc: "2.0", id, error: { code: -32600, message: "Invalid Request" } };
  }

  try {
    switch (method) {
      case "initialize": {
        const newSessionId = sessionId || generateSessionId();
        sessions.set(newSessionId, { clientInfo: params?.clientInfo, initialized: true });
        return {
          jsonrpc: "2.0", id,
          result: {
            protocolVersion: MCP_PROTOCOL_VERSION,
            serverInfo: { name: "erp-consultancy-mcp", version: "1.0.0" },
            capabilities: { tools: { listChanged: false } }
          },
          _sessionId: newSessionId
        };
      }

      case "initialized":
        return null; // Notification, no response

      case "tools/list":
        return { jsonrpc: "2.0", id, result: { tools: TOOLS } };

      case "tools/call": {
        const { name, arguments: args } = params;
        const result = await callTool(name, args || {});
        return {
          jsonrpc: "2.0", id,
          result: { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] }
        };
      }

      case "ping":
        return { jsonrpc: "2.0", id, result: {} };

      default:
        return { jsonrpc: "2.0", id, error: { code: -32601, message: `Method not found: ${method}` } };
    }
  } catch (err) {
    return { jsonrpc: "2.0", id, error: { code: -32000, message: err.message } };
  }
}

// ============ HTTP Server ============

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", chunk => { body += chunk; });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

function sendJson(res, status, data, headers = {}) {
  res.writeHead(status, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", ...headers });
  res.end(JSON.stringify(data));
}

function sendSSE(res, data, eventId) {
  if (eventId) res.write(`id: ${eventId}\n`);
  res.write(`data: ${JSON.stringify(data)}\n\n`);
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
      "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Api-Key, Accept, Mcp-Session-Id, MCP-Protocol-Version"
    });
    res.end();
    return;
  }

  // ============ OAuth Endpoints ============

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

  if (req.method === "POST" && pathname === "/oauth/register") {
    try {
      const body = await parseBody(req);
      const registration = JSON.parse(body || "{}");
      const creds = generateClientCredentials();
      const redirect_uris = registration.redirect_uris || [];
      if (!Array.isArray(redirect_uris) || redirect_uris.length === 0) {
        sendJson(res, 400, { error: "invalid_request", error_description: "redirect_uris required" });
        return;
      }
      const clientData = {
        client_id: creds.client_id, client_secret: creds.client_secret, redirect_uris,
        client_name: registration.client_name || "Dynamic Client",
        grant_types: ["authorization_code"], response_types: ["code"],
        token_endpoint_auth_method: "client_secret_post", created_at: Date.now()
      };
      registeredClients.set(creds.client_id, clientData);
      sendJson(res, 201, { ...clientData, client_secret_expires_at: 0 });
    } catch (err) {
      sendJson(res, 400, { error: "invalid_request", error_description: err.message });
    }
    return;
  }

  if (req.method === "GET" && pathname === "/oauth/authorize") {
    const clientId = parsedUrl.searchParams.get("client_id");
    const redirectUri = parsedUrl.searchParams.get("redirect_uri");
    const state = parsedUrl.searchParams.get("state");
    const responseType = parsedUrl.searchParams.get("response_type");

    const clientValidation = validateClient(clientId, null, redirectUri);
    if (!clientValidation.valid) {
      sendJson(res, 400, { error: "invalid_client", error_description: clientValidation.error });
      return;
    }
    if (!redirectUri) {
      sendJson(res, 400, { error: "invalid_request", error_description: "redirect_uri required" });
      return;
    }
    if (responseType !== "code") {
      sendRedirect(res, `${redirectUri}?error=unsupported_response_type&state=${state || ""}`);
      return;
    }

    const code = generateToken();
    authCodes.set(code, { clientId, redirectUri, expiresAt: Date.now() + AUTH_CODE_TTL });
    const callbackUrl = new URL(redirectUri);
    callbackUrl.searchParams.set("code", code);
    if (state) callbackUrl.searchParams.set("state", state);
    sendRedirect(res, callbackUrl.toString());
    return;
  }

  if (req.method === "POST" && pathname === "/oauth/token") {
    const body = await parseBody(req);
    const params = new URLSearchParams(body);
    const grantType = params.get("grant_type");
    const code = params.get("code");
    const clientId = params.get("client_id");
    const clientSecret = params.get("client_secret");
    const redirectUri = params.get("redirect_uri");

    if (grantType !== "authorization_code") {
      sendJson(res, 400, { error: "unsupported_grant_type" });
      return;
    }
    const clientValidation = validateClient(clientId, clientSecret, null, true);  // requireSecret=true for token endpoint
    if (!clientValidation.valid) {
      sendJson(res, 400, { error: "invalid_client", error_description: clientValidation.error });
      return;
    }
    const authCode = authCodes.get(code);
    if (!authCode || authCode.expiresAt < Date.now()) {
      authCodes.delete(code);
      sendJson(res, 400, { error: "invalid_grant", error_description: "Invalid or expired code" });
      return;
    }
    if (authCode.clientId !== clientId || authCode.redirectUri !== redirectUri) {
      sendJson(res, 400, { error: "invalid_grant", error_description: "Code mismatch" });
      return;
    }
    authCodes.delete(code);
    const accessToken = generateToken();
    accessTokens.set(accessToken, { clientId, expiresAt: Date.now() + ACCESS_TOKEN_TTL });
    sendJson(res, 200, { access_token: accessToken, token_type: "Bearer", expires_in: Math.floor(ACCESS_TOKEN_TTL / 1000) });
    return;
  }

  // ============ MCP Streamable HTTP Endpoint ============

  if (pathname === "/mcp") {
    // Check authorization
    if (!isAuthorized(req)) {
      sendJson(res, 401, { jsonrpc: "2.0", error: { code: -32000, message: "Unauthorized" } });
      return;
    }

    const sessionId = req.headers["mcp-session-id"];
    const acceptHeader = req.headers["accept"] || "";

    // DELETE - Session termination
    if (req.method === "DELETE") {
      if (sessionId && sessions.has(sessionId)) {
        sessions.delete(sessionId);
        res.writeHead(204);
        res.end();
      } else {
        sendJson(res, 404, { error: "Session not found" });
      }
      return;
    }

    // GET - SSE stream for server-to-client messages
    if (req.method === "GET") {
      if (!acceptHeader.includes("text/event-stream")) {
        sendJson(res, 400, { error: "Accept header must include text/event-stream" });
        return;
      }

      res.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Access-Control-Allow-Origin": "*"
      });

      // Send initial ping
      sendSSE(res, { jsonrpc: "2.0", method: "ping" }, generateToken());

      // Keep connection alive with periodic pings
      const pingInterval = setInterval(() => {
        if (!res.writableEnded) {
          sendSSE(res, { jsonrpc: "2.0", method: "ping" }, generateToken());
        }
      }, 30000);

      req.on("close", () => {
        clearInterval(pingInterval);
      });
      return;
    }

    // POST - JSON-RPC messages
    if (req.method === "POST") {
      try {
        const body = await parseBody(req);
        const message = JSON.parse(body);

        const response = await handleJsonRpcRequest(message, sessionId);

        if (!response) {
          // Notification - no response needed
          res.writeHead(202, { "Access-Control-Allow-Origin": "*" });
          res.end();
          return;
        }

        // Check if client accepts SSE
        if (acceptHeader.includes("text/event-stream")) {
          res.writeHead(200, {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Access-Control-Allow-Origin": "*",
            ...(response._sessionId ? { "Mcp-Session-Id": response._sessionId } : {})
          });

          // Remove internal session ID before sending
          const { _sessionId, ...cleanResponse } = response;
          sendSSE(res, cleanResponse, generateToken());
          res.end();
        } else {
          // JSON response
          const { _sessionId, ...cleanResponse } = response;
          sendJson(res, 200, cleanResponse, response._sessionId ? { "Mcp-Session-Id": response._sessionId } : {});
        }
      } catch (err) {
        sendJson(res, 400, { jsonrpc: "2.0", error: { code: -32700, message: "Parse error" } });
      }
      return;
    }

    sendJson(res, 405, { error: "Method not allowed" });
    return;
  }

  // ============ Legacy /sse endpoint for backwards compatibility ============

  if (pathname === "/sse") {
    // Redirect to /mcp
    res.writeHead(301, { "Location": "/mcp" });
    res.end();
    return;
  }

  // Not found
  sendJson(res, 404, { error: "Not found" });
});

httpServer.listen(PORT, () => {
  process.stderr.write(`MCP Streamable HTTP server listening on http://localhost:${PORT}/mcp\n`);
  process.stderr.write(`OAuth endpoints: /oauth/authorize, /oauth/token, /oauth/register\n`);
  process.stderr.write(`Discovery: /.well-known/oauth-authorization-server\n`);
});
