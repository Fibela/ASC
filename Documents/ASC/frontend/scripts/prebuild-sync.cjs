/**
 * prebuild-sync.cjs — shim de Vercel para el sync canónico.
 *
 * Vive DENTRO de frontend/ para existir siempre en el build de Vercel
 * (root del proyecto asc-mono). Si el monorepo completo es visible
 * (archivos fuera del root incluidos), refresca frontend/asc_api desde
 * backend/asc_api; si no, no-op: la copia commiteada ya pasó el gate
 * de integridad (backend/tests/test_asc_api_sync.py).
 *
 * La herramienta canónica es scripts/sync-asc-api.mjs (root del proyecto).
 */
const { existsSync } = require("node:fs");
const { execFileSync } = require("node:child_process");
const path = require("node:path");

const canonical = path.resolve(__dirname, "..", "..", "scripts", "sync-asc-api.mjs");

if (existsSync(canonical)) {
  execFileSync(process.execPath, [canonical], { stdio: "inherit" });
} else {
  console.log("[prebuild-sync] monorepo no visible — se usa frontend/asc_api commiteado (no-op).");
}
