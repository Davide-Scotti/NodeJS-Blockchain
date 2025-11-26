import { execSync } from "child_process";

// Stato precedente della rete (porte in ascolto)
// chiave: proto:ip:porta, valore: { proto, localAddress, port, pid }
const lastListeningPorts = new Map();

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

export function runNetworkCheck(emitEvent) {
  const now = new Date().toISOString();
  const current = getCurrentListeningPorts();

  if (!current) {
    emitEvent({
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
    emitEvent({
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

  emitEvent({
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
