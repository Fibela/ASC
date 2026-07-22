// asc-watchdog — Supabase Edge Function (Deno)
// Watchdog EXTERNO: corre en infraestructura de Supabase (AWS), independiente de
// Vercel. Rompe el límite "Vercel no se monitorea a sí mismo".
//
// Cada 2 min (programado vía pg_cron, ver supabase/watchdog_setup.sql):
//   1. pinguea /health/readiness (NO liveness: readiness sí chequea DB+esquema).
//   2. escribe el latido 'watchdog-supabase' en platform_heartbeats.
//   3. si NO está 'ready', alerta por Resend.
//
// PRUEBA DE ALARMA: invocar con ?test=1 envía un correo de alerta de PRUEBA sin tocar
//   el estado real ni pinguear ASC — sirve para verificar que el canal Resend funciona.
//
// Secrets: RESEND_API_KEY, WATCHDOG_ALERT_EMAIL, (opcional) WATCHDOG_ALERT_FROM.
// SUPABASE_URL y SUPABASE_SERVICE_ROLE_KEY se inyectan automáticamente.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const READINESS_URL = "https://asc.premoscorp.com/api/v1/health/readiness";
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const RESEND_API_KEY = Deno.env.get("RESEND_API_KEY") ?? "";
const ALERT_TO = Deno.env.get("WATCHDOG_ALERT_EMAIL") ?? "";
const ALERT_FROM = Deno.env.get("WATCHDOG_ALERT_FROM") ?? "watchdog@premoscorp.com";

async function sendAlert(status: string, detail: string | null): Promise<boolean> {
  if (!RESEND_API_KEY || !ALERT_TO) return false;
  try {
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: ALERT_FROM,
        to: [ALERT_TO],
        subject: `ASC watchdog: ${status.toUpperCase()}`,
        text:
          `Watchdog externo (Supabase/AWS).\n\nEstado: ${status}\nDetalle: ${detail}\n` +
          `URL: ${READINESS_URL}\nHora (UTC): ${new Date().toISOString()}\n\n` +
          `Si es real: revisa Vercel (rollback al ultimo READY) y Supabase. Ver docs/OPERACIONES.md.`,
      }),
    });
    return r.ok;
  } catch (_e) {
    return false;
  }
}

Deno.serve(async (req) => {
  // Modo prueba: ?test=1 → verifica el canal de alerta sin tocar el estado real.
  const url = new URL(req.url);
  if (url.searchParams.get("test") === "1") {
    const sent = await sendAlert(
      "prueba",
      "PRUEBA MANUAL de la alarma — ASC NO esta caido. Confirma que el correo llega.",
    );
    return new Response(JSON.stringify({ test: true, alert_sent: sent }), {
      headers: { "Content-Type": "application/json" },
    });
  }

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
  if (status !== "ok") {
    await sendAlert(status, detail);
  }

  return new Response(JSON.stringify({ status, detail }), {
    headers: { "Content-Type": "application/json" },
  });
});
