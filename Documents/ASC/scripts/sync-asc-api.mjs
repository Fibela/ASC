#!/usr/bin/env node
/**
 * sync-asc-api.mjs — Fuente única del backend: backend/asc_api.
 *
 * frontend/asc_api es un ESPEJO GENERADO. Nunca se edita a mano.
 * Historia: la copia manual divergió (S99 fix CORS y S100 cron.py se
 * aplicaron solo a backend/asc_api) y produjo bugs tipo incidente I-2.
 *
 * Modos:
 *   node scripts/sync-asc-api.mjs           → sincroniza (copia/borra en frontend/asc_api)
 *   node scripts/sync-asc-api.mjs --check   → solo verifica; exit 1 si hay divergencia
 *
 * Sin dependencias externas (Node stdlib). Corre en dev, CI y Vercel.
 */
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(SCRIPT_DIR, "..");
const SRC = path.join(REPO, "backend", "asc_api");
const DST = path.join(REPO, "frontend", "asc_api");
const EXCLUDE = new Set(["__pycache__", ".pytest_cache", ".mypy_cache"]);
const CHECK = process.argv.includes("--check");

function sha256(file) {
  return createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

/** Mapa ruta-relativa (posix) → hash, ignorando EXCLUDE. */
function walk(dir, base = dir, out = new Map()) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (EXCLUDE.has(e.name)) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, base, out);
    else out.set(path.relative(base, p).split(path.sep).join("/"), sha256(p));
  }
  return out;
}

if (!fs.existsSync(SRC)) {
  // Escenario Vercel con root=frontend/ y sin archivos fuera del root:
  // no hay fuente que copiar; la copia commiteada ya pasó el gate de integridad.
  console.log("[sync-asc-api] backend/asc_api no visible — se usa la copia commiteada (no-op).");
  process.exit(0);
}

const src = walk(SRC);
const dst = fs.existsSync(DST) ? walk(DST) : new Map();

const missing = [...src.keys()].filter((k) => !dst.has(k));
const extra = [...dst.keys()].filter((k) => !src.has(k));
const changed = [...src.keys()].filter((k) => dst.has(k) && dst.get(k) !== src.get(k));

if (missing.length === 0 && extra.length === 0 && changed.length === 0) {
  console.log(`[sync-asc-api] OK — espejo íntegro (${src.size} archivos).`);
  process.exit(0);
}

const report = { missing_in_frontend: missing, extra_in_frontend: extra, changed };
if (CHECK) {
  console.error("[sync-asc-api] DIVERGENCIA DETECTADA:");
  console.error(JSON.stringify(report, null, 2));
  console.error("Corre: node scripts/sync-asc-api.mjs");
  process.exit(1);
}

for (const rel of [...missing, ...changed]) {
  const to = path.join(DST, ...rel.split("/"));
  fs.mkdirSync(path.dirname(to), { recursive: true });
  fs.copyFileSync(path.join(SRC, ...rel.split("/")), to);
  console.log(`  copiado  ${rel}`);
}
for (const rel of extra) {
  fs.rmSync(path.join(DST, ...rel.split("/")));
  console.log(`  borrado  ${rel}`);
}
// Limpia directorios vacíos que dejó el borrado.
(function prune(dir) {
  if (!fs.existsSync(dir)) return;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) prune(path.join(dir, e.name));
  }
  if (fs.readdirSync(dir).length === 0) fs.rmdirSync(dir);
})(DST);

console.log(
  `[sync-asc-api] Sincronizado: +${missing.length} copiados, ~${changed.length} actualizados, -${extra.length} borrados.`
);
