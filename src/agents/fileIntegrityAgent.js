import fs from "fs";
import path from "path";
import crypto from "crypto";
import { INTEGRITY_CONFIG } from "../config.js";

// Mappa in memoria degli ultimi hash visti per ogni file
// chiave: percorso del file, valore: hash SHA-256
const lastFileHashes = new Map();

function computeFileHash(filePath) {
  try {
    const data = fs.readFileSync(filePath);
    return crypto.createHash("sha256").update(data).digest("hex");
  } catch (err) {
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

export function runFileIntegrityCheck(emitEvent) {
  const now = new Date().toISOString();
  const roots = INTEGRITY_CONFIG.roots ?? [];
  const excludeDirs = INTEGRITY_CONFIG.excludeDirs ?? [];

  for (const root of roots) {
    const files = collectFilesUnderRoot(root, excludeDirs);

    for (const filePath of files) {
      const hash = computeFileHash(filePath);

      if (hash === null) {
        emitEvent({
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

      if (previousHash === hash) {
        continue;
      }

      if (previousHash === undefined) {
        emitEvent({
          type: "file_integrity_baseline",
          source: "file-agent",
          severity: "info",
          message: `Baseline hash recorded for ${filePath}`,
          timestamp: now,
          details: { path: filePath, hash },
        });
      } else {
        emitEvent({
          type: "file_integrity_change",
          source: "file-agent",
          severity: "high",
          message: `File content changed: ${filePath}`,
          timestamp: now,
          details: { path: filePath, oldHash: previousHash, newHash: hash },
        });
      }

      lastFileHashes.set(filePath, hash);
    }
  }
}
