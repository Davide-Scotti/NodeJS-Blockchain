import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { Blockchain } from "./core/blockchain.js";
import { INTEGRITY_CONFIG } from "./config.js";
import { runFileIntegrityCheck } from "./agents/fileIntegrityAgent.js";
import { runNetworkCheck } from "./agents/networkAgent.js";
import { runAccountCheck } from "./agents/accountAgent.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());

// Singleton blockchain instance for the Security Event Ledger
const chain = new Blockchain();

// In-memory queue of pending security events to be mined into the next block
let pendingEvents = [];

function emitEvent(evt) {
  pendingEvents.push(evt);
}

// opzionale: mina automaticamente se ci sono eventi in coda
function minePendingEventsIfAny() {
  if (pendingEvents.length === 0) {
    return;
  }

  const block = chain.addBlock(pendingEvents);
  pendingEvents = [];
  // log sul server
  console.log("Auto-mined block from integrity checks:", {
    index: block.index,
    hash: block.hash,
    timestamp: block.timestamp,
  });
}

// Helper: basic validation for incoming security events
function validateEvent(body) {
  if (typeof body !== "object" || body === null) {
    return "Request body must be a JSON object";
  }

  if (typeof body.type !== "string" || body.type.trim() === "") {
    return 'Field "type" is required and must be a non-empty string';
  }

  if (typeof body.source !== "string" || body.source.trim() === "") {
    return 'Field "source" is required and must be a non-empty string';
  }

  if (body.severity != null && typeof body.severity !== "string") {
    return 'Field "severity", if provided, must be a string';
  }

  if (body.message != null && typeof body.message !== "string") {
    return 'Field "message", if provided, must be a string';
  }

  if (body.details != null && (typeof body.details !== "object" || Array.isArray(body.details))) {
    return 'Field "details", if provided, must be an object';
  }

  return null;
}

// POST /events - queue a new security event
app.post("/events", (req, res) => {
  const error = validateEvent(req.body);

  if (error) {
    return res.status(400).json({ error });
  }

  const now = new Date().toISOString();

  const event = {
    type: req.body.type,
    source: req.body.source,
    severity: req.body.severity ?? "info",
    message: req.body.message ?? "",
    timestamp: now,
    details: req.body.details ?? {},
  };

  pendingEvents.push(event);

  return res.status(202).json({ status: "queued", event });
});

// GET /pending - list pending events not yet mined into a block
app.get("/pending", (req, res) => {
  return res.json({ count: pendingEvents.length, events: pendingEvents });
});

// POST /mine - mine all pending events into a new block
app.post("/mine", (req, res) => {
  if (pendingEvents.length === 0) {
    return res.status(400).json({ error: "No pending events to mine" });
  }

  const block = chain.addBlock(pendingEvents);
  pendingEvents = [];

  return res.status(201).json(block);
});

// GET /chain - return the whole blockchain (security event ledger)
app.get("/chain", (req, res) => {
  return res.json({ length: chain.chain.length, chain: chain.chain });
});

// GET /verify - verify the integrity of the blockchain
app.get("/verify", (req, res) => {
  const valid = chain.isValid();

  return res.json({ valid, length: chain.chain.length });
});

// Optional: basic health endpoint
app.get("/health", (req, res) => {
  const valid = chain.isValid();

  return res.json({ status: "ok", valid, length: chain.chain.length });
});

// Simple HTML UI to interact with the Security Event Ledger
app.get("/ui", (req, res) => {
  res.sendFile(path.join(__dirname, "ui", "index.html"));
});

// Redirect root to the UI for convenience
app.get("/", (req, res) => {
  res.redirect("/ui");
});

// Manual scan endpoints
app.post("/scan/full", (req, res) => {
  if (INTEGRITY_CONFIG?.roots?.length) {
    runFileIntegrityCheck(emitEvent);
  }
  runNetworkCheck(emitEvent);
  runAccountCheck(emitEvent);
  res.status(202).json({ status: "queued" });
});

app.post("/scan/files", (req, res) => {
  if (INTEGRITY_CONFIG?.roots?.length) {
    runFileIntegrityCheck(emitEvent);
  }
  res.status(202).json({ status: "queued" });
});

app.post("/scan/network", (req, res) => {
  runNetworkCheck(emitEvent);
  res.status(202).json({ status: "queued" });
});

app.post("/scan/accounts", (req, res) => {
  runAccountCheck(emitEvent);
  res.status(202).json({ status: "queued" });
});

// Config endpoints
app.get("/config", (req, res) => {
  res.json({
    intervalMs: INTEGRITY_CONFIG.intervalMs,
    roots: INTEGRITY_CONFIG.roots ?? [],
    excludeDirs: INTEGRITY_CONFIG.excludeDirs ?? [],
  });
});

// Update only the roots list at runtime (UI-driven)
app.post("/config/roots", (req, res) => {
  const { roots } = req.body || {};

  if (!Array.isArray(roots)) {
    return res.status(400).json({ error: "'roots' must be an array of strings" });
  }

  const cleaned = roots
    .map((r) => (typeof r === "string" ? r.trim() : ""))
    .filter((r) => r.length > 0);

  if (cleaned.length === 0) {
    return res.status(400).json({ error: "At least one non-empty root path is required" });
  }

  INTEGRITY_CONFIG.roots = cleaned;

  return res.json({
    intervalMs: INTEGRITY_CONFIG.intervalMs,
    roots: INTEGRITY_CONFIG.roots,
    excludeDirs: INTEGRITY_CONFIG.excludeDirs ?? [],
  });
});

// Update excluded directories list at runtime (UI-driven)
app.post("/config/excludes", (req, res) => {
  const { excludeDirs } = req.body || {};

  if (!Array.isArray(excludeDirs)) {
    return res.status(400).json({ error: "'excludeDirs' must be an array of strings" });
  }

  const cleaned = excludeDirs
    .map((d) => (typeof d === "string" ? d.trim() : ""))
    .filter((d) => d.length > 0);

  INTEGRITY_CONFIG.excludeDirs = cleaned;

  return res.json({
    intervalMs: INTEGRITY_CONFIG.intervalMs,
    roots: INTEGRITY_CONFIG.roots ?? [],
    excludeDirs: INTEGRITY_CONFIG.excludeDirs,
  });
});

// Fallback for unknown routes
app.use((req, res) => {
  res.status(404).json({ error: "Not found" });
});

// Avvia gli agent automatici
if (INTEGRITY_CONFIG?.roots?.length) {
  setInterval(() => runFileIntegrityCheck(emitEvent), INTEGRITY_CONFIG.intervalMs);
}

setInterval(() => runNetworkCheck(emitEvent), INTEGRITY_CONFIG.intervalMs);
setInterval(() => runAccountCheck(emitEvent), INTEGRITY_CONFIG.intervalMs);

setInterval(minePendingEventsIfAny, INTEGRITY_CONFIG.intervalMs + 5_000);

const port = process.env.PORT ?? 3000;

app.listen(port, () => {
  console.log(`Security Event Ledger API listening on http://localhost:${port}`);
});
