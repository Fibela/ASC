// asc-watchdog — Supabase Edge Function (Deno)
// Watchdog EXTERNO: corre en infraestructura de Supabase (AWS), independiente de
// Vercel. Rompe el límite "Vercel no se monitorea a sí mismo".
//
// Cada 2 min (programado vía pg_cron, ver supabase/watchdog_setup.sql):
//   1. pinguea /health/readiness (NO liveness: readiness sí chequea DB+esquema).
//   2. escribe el latido 'watchdog-supabase' en platform_heartbeats.
//   3. si NO está 'ready', alerta por Resend.
//
// Secrets requeridos (supabase secrets set ...):
//   SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, RESEND_API_KEY,
//   WATCHDOG_ALERT_EMAIL, (opcional) WATCHDOG_ALERT_FROM
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const READINESS_URL = "https://asc.premoscorp.com/api/v1/health/readiness";
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const RESEND_API_KEY = Deno.env.get("RESEND_API_KEY") ?? "";
const ALERT_TO = Deno.env.get("WATCHDOG_ALERT_EMAIL") ?? "";
const ALERT_FROM = Deno.env.get("WATCHDOG_ALERT_FROM") ?? "watchdog@premoscorp.com";

Deno.serve(async () => {
  let status = "ok";
  let detail: string | null = null;

  // 1) Ping a readiness (timeout 8s)
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 8000);
    const resp = await fetch(READINESS_URL, { signal: ctrl.signal });
    clearTimeout(timer);
    if (!resp.ok) {
      status = "unreachable";
      detail = `HTTP ${resp.status}`;
    } else {
      const body = await resp.json().catch(() => ({}));
      if (body?.status !== "ready") {
        status = "error";
        detail = `readiness=${body?.status ?? "?"}`;
      }
    }
  } catch (e) {
    status = "unreachable";
    detail = String((e as Error)?.message ?? e);
  }

  // 2) Escribir latido (misma tabla que los crons de Vercel)
  try {
    const supabase = createClient(SUPABASE_URL, SERVICE_ROLE);
    await supabase.from("platform_heartbeats").upsert({
      id: "watchdog-supabase",
      last_seen_at: new Date().toISOString(),
      last_status: status,
      detail,
    });
  } catch (e) {
    detail = `${detail ?? ""} | heartbeat_write_failed: ${String((e as Error)?.message ?? e)}`;
  }

  // 3) Alerta si NO está OK
  if (status !== "ok" && RESEND_API_KEY && ALERT_TO) {
    try {
      await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${RESEND_API_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          from: ALERT_FROM,
          to: [ALERT_TO],
          subject: `ASC watchdog: produccion ${status.toUpperCase()}`,
          text:
            `El watchdog externo (Supabase/AWS) detecto que ASC no esta 'ready'.\n\n` +
            `Estado: ${status}\nDetalle: ${detail}\nURL: ${READINESS_URL}\n` +
            `Hora (UTC): ${new Date().toISOString()}\n\n` +
            `Revisa Vercel (rollback al ultimo READY) y Supabase. Ver docs/OPERACIONES.md.`,
        }),
      });
    } catch (_e) {
      // la alerta es best-effort; el latido en DB ya deja el rastro
    }
  }

  return new Response(JSON.stringify({ status, detail }), {
    headers: { "Content-Type": "application/json" },
  });
});
