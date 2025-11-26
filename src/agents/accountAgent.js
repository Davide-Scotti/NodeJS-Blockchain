import { execSync } from "child_process";

const lastAccounts = {
  users: new Set(),
  admins: new Set(),
};

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

export function runAccountCheck(emitEvent) {
  const now = new Date().toISOString();
  const users = getLocalUsers();
  const admins = getLocalAdmins();

  if (!users || !admins) {
    emitEvent({
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
    emitEvent({
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

  emitEvent({
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
