import express from "express";
import { Blockchain } from "./core/blockchain.js";
    
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { execSync } from "child_process";
import { INTEGRITY_CONFIG } from "./config.js";

const app = express();
app.use(express.json());

// Singleton blockchain instance for the Security Event Ledger
const chain = new Blockchain();

// In-memory queue of pending security events to be mined into the next block
let pendingEvents = [];

// Mappa in memoria degli ultimi hash visti per ogni file
// chiave: percorso del file, valore: hash SHA-256
const lastFileHashes = new Map();

// Stato precedente della rete (porte in ascolto)
// chiave: proto:ip:porta, valore: { proto, localAddress, port, pid }
const lastListeningPorts = new Map();

// Stato precedente degli account locali
const lastAccounts = {
  users: new Set(),
  admins: new Set(),
};

function computeFileHash(filePath) {
  try {
    const data = fs.readFileSync(filePath);
    return crypto.createHash("sha256").update(data).digest("hex");
  } catch (err) {
    // Se il file non è leggibile, restituiamo null e registreremo un evento di errore
    return null;
  }
}

function collectFilesUnderRoot(rootPath, excludeDirs) {
  const results = [];

  function walk(currentPath) {
    let stat;
    try {
      stat = fs.statSync(currentPath);
    } catch {
      return;
    }

    if (stat.isFile()) {
      results.push(currentPath);
      return;
    }

    if (!stat.isDirectory()) {
      return;
    }

    const baseName = path.basename(currentPath);
    if (excludeDirs.includes(baseName)) {
      return;
    }

    let entries;
    try {
      entries = fs.readdirSync(currentPath, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentPath, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile()) {
        results.push(fullPath);
      }
    }
  }

  walk(rootPath);
  return results;
}

function runFileIntegrityCheck() {
  const now = new Date().toISOString();
  const roots = INTEGRITY_CONFIG.roots ?? [];
  const excludeDirs = INTEGRITY_CONFIG.excludeDirs ?? [];

  for (const root of roots) {
    const files = collectFilesUnderRoot(root, excludeDirs);

    for (const filePath of files) {
      const hash = computeFileHash(filePath);

      if (hash === null) {
        // evento di errore/alert per file non leggibili
        pendingEvents.push({
          type: "file_integrity_error",
          source: "file-agent",
          severity: "high",
          message: `Unable to read file: ${filePath}`,
          timestamp: now,
          details: { path: filePath },
        });
        continue;
      }

      const previousHash = lastFileHashes.get(filePath);

      // Nessun cambiamento: salta
      if (previousHash === hash) {
        continue;
      }

      // Primo avvistamento del file: evento di baseline
      if (previousHash === undefined) {
        pendingEvents.push({
          type: "file_integrity_baseline",
          source: "file-agent",
          severity: "info",
          message: `Baseline hash recorded for ${filePath}`,
          timestamp: now,
          details: { path: filePath, hash },
        });
      } else {
        // Hash cambiato rispetto all'ultimo snapshot: vero evento di change
        pendingEvents.push({
          type: "file_integrity_change",
          source: "file-agent",
          severity: "high",
          message: `File content changed: ${filePath}`,
          timestamp: now,
          details: { path: filePath, oldHash: previousHash, newHash: hash },
        });
      }

      // Aggiorna lo stato noto
      lastFileHashes.set(filePath, hash);
    }
  }
}

// --- Network state / listening ports agent (Windows) ---

function getCurrentListeningPorts() {
  try {
    const output = execSync("netstat -ano", { encoding: "utf8" });
    const lines = output.split(/\r?\n/);
    const ports = new Map();

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed.startsWith("TCP") && !trimmed.startsWith("UDP")) continue;

      const parts = trimmed.split(/\s+/);
      if (parts.length < 4) continue;

      const proto = parts[0];
      const local = parts[1];
      const state = proto === "TCP" ? parts[3] : null;
      const pid = proto === "TCP" ? parts[4] : parts[3];

      if (proto === "TCP" && state !== "LISTENING") continue;

      const [localAddress, portStr] = local.split(":");
      if (!localAddress || !portStr) continue;

      const key = `${proto}:${localAddress}:${portStr}`;
      ports.set(key, { proto, localAddress, port: portStr, pid });
    }

    return ports;
  } catch {
    return null;
  }
}

function runNetworkCheck() {
  const now = new Date().toISOString();
  const current = getCurrentListeningPorts();

  if (!current) {
    pendingEvents.push({
      type: "network_check_error",
      source: "net-agent",
      severity: "high",
      message: "Failed to read current listening ports",
      timestamp: now,
      details: {},
    });
    return;
  }

  if (lastListeningPorts.size === 0) {
    // baseline iniziale
    pendingEvents.push({
      type: "network_baseline",
      source: "net-agent",
      severity: "info",
      message: "Initial listening ports baseline recorded",
      timestamp: now,
      details: { listening: Array.from(current.values()) },
    });
    for (const [key, value] of current.entries()) {
      lastListeningPorts.set(key, value);
    }
    return;
  }

  const newListening = [];
  const closed = [];

  for (const [key, value] of current.entries()) {
    if (!lastListeningPorts.has(key)) {
      newListening.push(value);
    }
  }

  for (const [key, value] of lastListeningPorts.entries()) {
    if (!current.has(key)) {
      closed.push(value);
    }
  }

  if (newListening.length === 0 && closed.length === 0) {
    return;
  }

  pendingEvents.push({
    type: "network_port_change",
    source: "net-agent",
    severity: "medium",
    message: "Changes in listening network ports detected",
    timestamp: now,
    details: { newListening, closed },
  });

  lastListeningPorts.clear();
  for (const [key, value] of current.entries()) {
    lastListeningPorts.set(key, value);
  }
}

// --- Local users / privileges agent (Windows) ---

function getLocalUsers() {
  try {
    const output = execSync("net user", { encoding: "utf8" });
    const lines = output.split(/\r?\n/);
    const users = new Set();

    let inList = false;
    for (const line of lines) {
      if (line.includes("-")) {
        inList = true;
        continue;
      }
      if (!inList) continue;
      const trimmed = line.trim();
      if (!trimmed) continue;
      if (trimmed.startsWith("The command")) break;
      const parts = trimmed.split(/\s+/);
      for (const p of parts) {
        if (p) users.add(p);
      }
    }

    return users;
  } catch {
    return null;
  }
}

function getLocalAdmins() {
  try {
    const output = execSync("net localgroup administrators", { encoding: "utf8" });
    const lines = output.split(/\r?\n/);
    const admins = new Set();

    let inList = false;
    for (const line of lines) {
      if (line.includes("-")) {
        inList = true;
        continue;
      }
      if (!inList) continue;
      const trimmed = line.trim();
      if (!trimmed) continue;
      if (trimmed.startsWith("The command")) break;
      admins.add(trimmed);
    }

    return admins;
  } catch {
    return null;
  }
}

function runAccountCheck() {
  const now = new Date().toISOString();
  const users = getLocalUsers();
  const admins = getLocalAdmins();

  if (!users || !admins) {
    pendingEvents.push({
      type: "account_check_error",
      source: "identity-agent",
      severity: "high",
      message: "Failed to read local users or administrators",
      timestamp: now,
      details: {},
    });
    return;
  }

  if (lastAccounts.users.size === 0 && lastAccounts.admins.size === 0) {
    // baseline iniziale
    pendingEvents.push({
      type: "account_baseline",
      source: "identity-agent",
      severity: "info",
      message: "Initial local accounts baseline recorded",
      timestamp: now,
      details: {
        users: Array.from(users),
        admins: Array.from(admins),
      },
    });

    lastAccounts.users = new Set(users);
    lastAccounts.admins = new Set(admins);
    return;
  }

  const newUsers = [];
  const removedUsers = [];
  const newAdmins = [];
  const removedAdmins = [];

  for (const u of users) {
    if (!lastAccounts.users.has(u)) newUsers.push(u);
  }
  for (const u of lastAccounts.users) {
    if (!users.has(u)) removedUsers.push(u);
  }

  for (const a of admins) {
    if (!lastAccounts.admins.has(a)) newAdmins.push(a);
  }
  for (const a of lastAccounts.admins) {
    if (!admins.has(a)) removedAdmins.push(a);
  }

  if (
    newUsers.length === 0 &&
    removedUsers.length === 0 &&
    newAdmins.length === 0 &&
    removedAdmins.length === 0
  ) {
    return;
  }

  pendingEvents.push({
    type: "account_membership_change",
    source: "identity-agent",
    severity: "high",
    message: "Changes in local users or administrators detected",
    timestamp: now,
    details: { newUsers, removedUsers, newAdmins, removedAdmins },
  });

  lastAccounts.users = new Set(users);
  lastAccounts.admins = new Set(admins);
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
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>Security Event Ledger</title>
    <style>
      body { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 1.5rem; background: #0f172a; color: #e5e7eb; }
      h1, h2 { color: #fbbf24; }
      label { display: block; margin-top: 0.5rem; }
      input, textarea, select { width: 100%; padding: 0.4rem; margin-top: 0.25rem; border-radius: 4px; border: 1px solid #4b5563; background: #020617; color: #e5e7eb; }
      button { margin-top: 0.75rem; padding: 0.5rem 1rem; border-radius: 4px; border: none; background: #22c55e; color: #022c22; font-weight: 600; cursor: pointer; }
      button.secondary { background: #38bdf8; color: #082f49; }
      button:disabled { opacity: 0.6; cursor: default; }
      .row { display: flex; flex-wrap: wrap; gap: 1.5rem; }
      .card { background: #020617; border-radius: 8px; padding: 1rem; border: 1px solid #1f2937; flex: 1; min-width: 260px; }
      pre { background: #020617; padding: 0.75rem; border-radius: 6px; overflow: auto; border: 1px solid #111827; font-size: 0.85rem; }
      .status-ok { color: #4ade80; }
      .status-bad { color: #f97373; }
      small { color: #9ca3af; }
      .chain-tree { max-height: 520px; overflow: auto; border-radius: 6px; border: 1px solid #111827; padding: 0.5rem 0.75rem; background: #020617; }
      .block-node { border-left: 2px solid #1f2937; margin-left: 0.5rem; padding-left: 0.75rem; margin-bottom: 0.75rem; }
      .block-header { display: flex; justify-content: space-between; align-items: center; font-size: 0.85rem; }
      .block-index { font-weight: 600; color: #fbbf24; }
      .block-hash { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; font-size: 0.7rem; color: #9ca3af; }
      .event-list { margin-top: 0.5rem; margin-left: 0.25rem; border-left: 1px dashed #374151; padding-left: 0.5rem; }
      .event-item { margin-bottom: 0.35rem; font-size: 0.8rem; }
      .event-type { display: inline-block; padding: 0.05rem 0.4rem; border-radius: 999px; font-weight: 600; margin-right: 0.35rem; }
      .event-type.info { background: #1d4ed8; color: #dbeafe; }
      .event-type.high { background: #b91c1c; color: #fee2e2; }
      .event-type.medium { background: #c2410c; color: #ffedd5; }
      .event-source { color: #a5b4fc; }
      .event-timestamp { color: #6b7280; margin-left: 0.35rem; }
    </style>
  </head>
  <body>
    <h1>Security Event Ledger</h1>
    <p><small>Blockchain-based, tamper-evident log of security events — powered by your Node.js blockchain.</small></p>

    <div class="row">
      <div class="card" style="max-width: 420px;">
        <h2>New Security Event</h2>
        <form id="event-form">
          <label>
            Type*
            <input id="type" name="type" placeholder="login_failed, config_change..." required />
          </label>
          <label>
            Source*
            <input id="source" name="source" placeholder="auth-service, api-gateway..." required />
          </label>
          <label>
            Severity
            <select id="severity" name="severity">
              <option value="info" selected>info</option>
              <option value="low">low</option>
              <option value="medium">medium</option>
              <option value="high">high</option>
            </select>
          </label>
          <label>
            Message
            <input id="message" name="message" placeholder="Short human-readable description" />
          </label>
          <label>
            Details (JSON object)
            <textarea id="details" name="details" rows="4" placeholder="{ \"username\": \"alice\", \"ip\": \"10.0.0.5\" }"></textarea>
          </label>
          <button type="submit" id="send-btn">Send event</button>
          <button type="button" id="mine-btn" class="secondary">Mine block from pending events</button>
          <p id="form-status"></p>
        </form>
      </div>

      <div class="card">
        <h2>Ledger status</h2>
        <p>Health: <span id="health-text">loading...</span></p>
        <p>Pending events: <span id="pending-count">0</span></p>
        <button type="button" id="refresh-btn" class="secondary">Refresh chain and status</button>
        <h2 style="margin-top: 1.25rem;">Chain</h2>
        <div id="chain-tree" class="chain-tree">Loading...</div>
      </div>
    </div>

    <script>
      async function fetchJSON(url, options) {
        const res = await fetch(url, options);
        const text = await res.text();
        try {
          const data = text ? JSON.parse(text) : null;
          if (!res.ok) {
            const err = new Error(data && data.error ? data.error : res.statusText);
            err.status = res.status;
            throw err;
          }
          return data;
        } catch (e) {
          if (!res.ok) throw e;
          return null;
        }
      }

      function renderChainTree(chainPayload) {
        const container = document.getElementById("chain-tree");
        if (!container) return;
        container.innerHTML = "";

        if (!chainPayload || !Array.isArray(chainPayload.chain)) {
          container.textContent = "No chain data";
          return;
        }

        for (const block of chainPayload.chain) {
          const blockNode = document.createElement("div");
          blockNode.className = "block-node";

          const header = document.createElement("div");
          header.className = "block-header";

          const left = document.createElement("div");
          const indexSpan = document.createElement("span");
          indexSpan.className = "block-index";
          indexSpan.textContent = "Block #" + block.index;
          left.appendChild(indexSpan);

          const tsSpan = document.createElement("span");
          tsSpan.className = "event-timestamp";
          tsSpan.textContent = block.timestamp ?? "";
          left.appendChild(document.createTextNode(" "));
          left.appendChild(tsSpan);

          const hashSpan = document.createElement("span");
          hashSpan.className = "block-hash";
          const shortHash = (block.hash || "").slice(0, 12);
          hashSpan.textContent = shortHash ? "# " + shortHash + "…" : "# genesis";

          header.appendChild(left);
          header.appendChild(hashSpan);
          blockNode.appendChild(header);

          const eventsContainer = document.createElement("div");
          eventsContainer.className = "event-list";

          const events = Array.isArray(block.data) ? block.data : [block.data];
          for (const ev of events) {
            if (!ev) continue;
            const item = document.createElement("div");
            item.className = "event-item";

            const typeSpan = document.createElement("span");
            typeSpan.className = "event-type info";
            const sev = (ev.severity || "info").toLowerCase();
            typeSpan.classList.add(sev);
            typeSpan.textContent = ev.type || "event";

          const srcSpan = document.createElement("span");
          srcSpan.className = "event-source";
          srcSpan.textContent = ev.source ? "@ " + ev.source : "";

            const tsEvSpan = document.createElement("span");
            tsEvSpan.className = "event-timestamp";
            tsEvSpan.textContent = ev.timestamp || "";

            item.appendChild(typeSpan);
            if (ev.message) {
              item.appendChild(document.createTextNode(" " + ev.message));
            }
            if (ev.source) {
              item.appendChild(document.createTextNode(" "));
              item.appendChild(srcSpan);
            }
            if (ev.timestamp) {
              item.appendChild(tsEvSpan);
            }

            eventsContainer.appendChild(item);
          }

          blockNode.appendChild(eventsContainer);
          container.appendChild(blockNode);
        }
      }

      async function refreshStatus() {
        const healthEl = document.getElementById("health-text");
        const pendingCountEl = document.getElementById("pending-count");

        try {
          const [health, pending, chain] = await Promise.all([
            fetchJSON("/health"),
            fetchJSON("/pending"),
            fetchJSON("/chain"),
          ]);

          if (health) {
            healthEl.textContent = health.valid ? "VALID" : "INVALID";
            healthEl.className = health.valid ? "status-ok" : "status-bad";
          }

          if (pending) {
            pendingCountEl.textContent = pending.count ?? 0;
          }

          if (chain) {
            renderChainTree(chain);
          }
        } catch (err) {
          healthEl.textContent = "Error: " + err.message;
          healthEl.className = "status-bad";
        }
      }

      async function handleSubmit(event) {
        event.preventDefault();
        const formStatus = document.getElementById("form-status");
        const sendBtn = document.getElementById("send-btn");

        formStatus.textContent = "";
        sendBtn.disabled = true;

        const type = document.getElementById("type").value.trim();
        const source = document.getElementById("source").value.trim();
        const severity = document.getElementById("severity").value;
        const message = document.getElementById("message").value.trim();
        const detailsRaw = document.getElementById("details").value.trim();

        let details = {};
        if (detailsRaw) {
          try {
            details = JSON.parse(detailsRaw);
          } catch (err) {
            formStatus.textContent = "Invalid JSON in details: " + err.message;
            formStatus.className = "status-bad";
            sendBtn.disabled = false;
            return;
          }
        }

        const payload = { type, source, severity, message, details };

        try {
          await fetchJSON("/events", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
          });
          formStatus.textContent = "Event queued successfully";
          formStatus.className = "status-ok";
          document.getElementById("details").value = "";
          await refreshStatus();
        } catch (err) {
          formStatus.textContent = "Error: " + err.message;
          formStatus.className = "status-bad";
        } finally {
          sendBtn.disabled = false;
        }
      }

      async function handleMine() {
        const formStatus = document.getElementById("form-status");
        const mineBtn = document.getElementById("mine-btn");
        mineBtn.disabled = true;
        formStatus.textContent = "";

        try {
          await fetchJSON("/mine", { method: "POST" });
          formStatus.textContent = "Block mined successfully";
          formStatus.className = "status-ok";
          await refreshStatus();
        } catch (err) {
          formStatus.textContent = "Error: " + err.message;
          formStatus.className = "status-bad";
        } finally {
          mineBtn.disabled = false;
        }
      }

      document.addEventListener("DOMContentLoaded", () => {
        document.getElementById("event-form").addEventListener("submit", handleSubmit);
        document.getElementById("mine-btn").addEventListener("click", handleMine);
        document.getElementById("refresh-btn").addEventListener("click", refreshStatus);
        refreshStatus();
      });
    </script>
  </body>
</html>`);
});

// Redirect root to the UI for convenience
app.get("/", (req, res) => {
  res.redirect("/ui");
});

// Fallback for unknown routes
app.use((req, res) => {
  res.status(404).json({ error: "Not found" });
});

// Avvia gli agent automatici
if (INTEGRITY_CONFIG?.roots?.length) {
  setInterval(runFileIntegrityCheck, INTEGRITY_CONFIG.intervalMs);
}

// Network e account check girano con lo stesso intervallo
setInterval(runNetworkCheck, INTEGRITY_CONFIG.intervalMs);
setInterval(runAccountCheck, INTEGRITY_CONFIG.intervalMs);

// Ogni intervallo (con un piccolo offset) miniamo gli eventi raccolti
setInterval(minePendingEventsIfAny, INTEGRITY_CONFIG.intervalMs + 5_000);

const port = process.env.PORT ?? 3000;

app.listen(port, () => {
  console.log(`Security Event Ledger API listening on http://localhost:${port}`);
});
