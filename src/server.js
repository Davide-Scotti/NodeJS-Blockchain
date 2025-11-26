import express from "express";
import { Blockchain } from "./core/blockchain.js";

const app = express();
app.use(express.json());

// Singleton blockchain instance for the Security Event Ledger
const chain = new Blockchain();

// In-memory queue of pending security events to be mined into the next block
let pendingEvents = [];

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
        <pre id="chain-view">Loading...</pre>
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

      async function refreshStatus() {
        const healthEl = document.getElementById("health-text");
        const pendingCountEl = document.getElementById("pending-count");
        const chainViewEl = document.getElementById("chain-view");

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
            chainViewEl.textContent = JSON.stringify(chain, null, 2);
          }
        } catch (err) {
          healthEl.textContent = `Error: ${err.message}`;
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

const port = process.env.PORT ?? 3000;

app.listen(port, () => {
  console.log(`Security Event Ledger API listening on http://localhost:${port}`);
});
