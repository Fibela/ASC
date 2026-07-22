-- Programación del watchdog externo cada 2 min (pg_cron + pg_net).
-- Correr UNA VEZ en el SQL Editor de Supabase, tras desplegar la Edge Function.
-- Requiere las extensiones pg_cron y pg_net (habilitarlas en Database > Extensions).
--
-- Reemplaza <PROJECT_REF> y <SERVICE_ROLE_KEY> por los tuyos.

-- (idempotente) quitar un schedule previo con el mismo nombre
select cron.unschedule('asc-watchdog-2min')
where exists (select 1 from cron.job where jobname = 'asc-watchdog-2min');

select cron.schedule(
  'asc-watchdog-2min',
  '*/2 * * * *',
  $$
    select net.http_post(
      url     := 'https://<PROJECT_REF>.supabase.co/functions/v1/asc-watchdog',
      headers := jsonb_build_object(
        'Authorization', 'Bearer <SERVICE_ROLE_KEY>',
        'Content-Type',  'application/json'
      )
    );
  $$
);
