export const BLOCKCHAIN_CONFIG = {
  difficulty: 2,
  miningReward: 50,
};

// Configurazione dell'agente di integrità dei file
// roots: cartelle di partenza da scansionare ricorsivamente
// excludeDirs: nomi di directory da saltare (node_modules, .git, ...)
export const INTEGRITY_CONFIG = {
  intervalMs: 60_000,
  roots: [
    "C:\\",
  ],
  excludeDirs: ["node_modules", ".git", ".vscode", "dist", "build", ".vs"],
};
