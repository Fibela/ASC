# ASC PremosCorp — Diagramas de Flujo
> Versión 2.0 | Actualizado: 2026-06-12
> Módulos activos: P01–P27 (Correlation Engine)
> Los diagramas usan sintaxis Mermaid (renderizable en GitHub, GitLab, Notion, VS Code)

---

## 1. Flujo Principal: Evento → Alerta → Neutralización

```mermaid
flowchart TD
    A([Evento de Seguridad]) --> B[Ingesta via /api/v1/events]
    B --> C[Normalización ECS\ncorrelator.normalize_event]
    C --> D{Evaluación de\nReglas SIEM}

    D -->|Sin coincidencia| E[(PostgreSQL\nEvento archivado)]
    D -->|Regla disparada| F[Alerta Creada\nstatus: open]

    F --> G[Enriquecimiento\nIoC + Threat Intel]
    G --> H{PCDI Risk Score\nAdaptive Scoring}

    H -->|score >= 0.85\nCRITICAL| I[Cola de Aprobación\nHuman-in-the-Loop]
    H -->|score >= 0.65\nHIGH| I
    H -->|score >= 0.40\nMEDIUM| J[Acción Automática\nbloqueo IP/dominio]
    H -->|score < 0.40\nLOW| K[Log & Monitor\nsin acción activa]

    I --> L{Analista SOC\n⏱ CRITICAL: 15min\n⏱ HIGH: 30min}

    L -->|APROBAR| M[Ejecutar Neutralización\nvia Adapter]
    L -->|RECHAZAR| N[Marcar False Positive\nCerrar alerta]
    L -->|TIMEOUT| O[ESCALACIÓN\nSOC Lead / Tier 2]

    O --> P{Supervisor\nDecide}
    P -->|Aprobar| M
    P -->|Rechazar| N

    M --> Q{Proveedor}
    Q -->|EDR| R[PremosCorp Specter\nIsolate / Kill / Quarantine]
    Q -->|Firewall| S[Palo Alto / Fortinet\nBlock IP / Domain]
    Q -->|Identity| T[Active Directory\nDisable Account → PIDS Token]

    R --> U[Resultado Registrado]
    S --> U
    T --> U

    U --> V[Audit Trail Inmutable\nForensic Ledger]
    U --> W[Actualizar Alert Status\ncontained / resolved]
    U --> X[Notificación WebSocket\nDashboard actualizado]
    U --> Y[Correlation Engine\nNueva señal cross-domain]

    J --> U
    K --> E
```

---

## 2. Flujo de Aprobación Human-in-the-Loop (PANL — Detalle)

```mermaid
sequenceDiagram
    participant SIEM as SIEM / Correlator
    participant API as FastAPI Backend
    participant DB as PostgreSQL
    participant QUEUE as Celery + Redis
    participant WS as WebSocket
    participant ANALYST as Analista SOC
    participant ADAPTER as Neutralization Adapter
    participant AUDIT as Forensic Ledger

    SIEM->>API: Alerta CRITICAL detectada
    API->>DB: Crear NeutralizationRequest (PENDING_APPROVAL)
    API->>AUDIT: Log: request.created (PANL)
    API->>QUEUE: Celery task con timeout=15min
    API->>WS: Broadcast: nueva solicitud pendiente
    WS->>ANALYST: Notificación en dashboard

    alt Analista aprueba dentro del timeout
        ANALYST->>API: POST /neutralize/approve/{id} + reason
        API->>DB: Update status → APPROVED
        API->>AUDIT: Log: request.approved (actor, reason, timestamp)
        API->>ADAPTER: execute_action(action_type, params)
        ADAPTER->>API: ActionResult (success/fail + raw_response)
        API->>DB: Update status → COMPLETED / FAILED
        API->>AUDIT: Log: action.executed (result, provider_response)
        API->>WS: Broadcast: acción completada
        WS->>ANALYST: Dashboard actualizado

    else Analista rechaza
        ANALYST->>API: POST /neutralize/reject/{id} + reason
        API->>DB: Update status → REJECTED
        API->>AUDIT: Log: request.rejected (actor, reason, timestamp)
        API->>DB: Update Alert: false_positive=True

    else TIMEOUT (15 minutos)
        QUEUE->>API: Celery timeout triggered
        API->>DB: Update status → ESCALATED
        API->>AUDIT: Log: request.escalated (timeout)
        API->>WS: Broadcast: escalación requerida
        API-->>ANALYST: Notificación: ESCALACIÓN SOC Lead
    end
```

---

## 3. Flujo: Análisis de Artefacto → Respuesta Automática

```mermaid
flowchart LR
    A([Analista sube\nartefacto]) --> B[POST /api/v1/analyze/artifact]
    B --> C[Compute Hashes\nMD5 SHA1 SHA256]
    C --> D[Magic Byte Detection\nPE ELF PDF ZIP...]
    D --> E[Signature Scan\nMimikatz CobaltStrike etc.]
    E --> F[PCDI Risk Score\nAdaptive + Context]

    F --> G{Veredicto}
    G -->|clean\nscore < 0.40| H[✅ Resultado al analista\nSin acción]
    G -->|suspicious\n0.40 - 0.85| I[⚠️ Resultado + IoC creado\nMonitoreo activo]
    G -->|malicious\nscore >= 0.85| J[🚨 Resultado + Alerta CRITICAL\n+ Queue Aprobación HitL]

    J --> K[Analista aprueba]
    K --> L[Quarantine File\nvia Specter RTR]
    K --> M[Block Hash\nen IoC + Threat Intel DB]
    K --> N[Alerta con TTPs MITRE\n+ Correlation Signal]
```

---

## 4. Flujo: SPECTER Agent — Pipeline de Comando

```mermaid
sequenceDiagram
    participant ANALYST as Analista SOC
    participant API as FastAPI /agents
    participant DB as PostgreSQL
    participant AGENT as Specter Agent\n(Endpoint)
    participant AUDIT as Forensic Ledger
    participant CORR as Correlation Engine

    ANALYST->>API: POST /agents/{id}/command\n{type: isolate, params: {reason}}
    API->>DB: Crear AgentCommand (status: pending)
    API->>AUDIT: Log: command.issued

    AGENT->>API: GET /agents/poll (heartbeat)
    API-->>AGENT: Comando pendiente (JWT firmado)

    AGENT->>AGENT: Ejecutar acción\n(isolate / process_kill / file_delete / etc.)

    AGENT->>API: POST /agents/result\n{command_id, success, output}
    API->>DB: Update AgentCommand → completed/failed
    API->>AUDIT: Log: command.executed (result, latency_ms)
    API->>CORR: Emitir señal cross-domain\n(panl_action: isolate_endpoint)

    Note over AGENT,API: Heartbeat cada poll_interval segundos\nDetección de agentes offline automática
```

---

## 5. Flujo: Bloqueo IP — Palo Alto (Detalle Técnico)

```mermaid
sequenceDiagram
    participant NS as Neutralizer Service
    participant PA as PAN-OS REST API
    participant DB as PostgreSQL Audit

    NS->>PA: POST /restapi/v10.1/Objects/Addresses
    Note over NS,PA: Crear Address Object "ASC-block-1.2.3.4"
    PA-->>NS: 200 OK

    NS->>PA: PUT /restapi/v10.1/Objects/AddressGroups/ASC-Blocked-IPs
    Note over NS,PA: Agregar nuevo address al grupo dinámico
    PA-->>NS: 200 OK

    NS->>PA: POST /restapi/v10.1/Device/Operational
    Note over NS,PA: Commit cambios en candidate config
    PA-->>NS: job_id: 1234

    loop Poll hasta commit completado
        NS->>PA: GET /restapi/v10.1/Operational/JobStatus?id=1234
        PA-->>NS: status: "ACT" | "FIN"
    end

    PA-->>NS: status: "FIN" (commit OK)
    NS->>DB: INSERT audit_log (all details)
```

---

## 6. Flujo: SOAR + PIDS — Identity Response (P25/P26)

```mermaid
flowchart TD
    A([Evento de identidad\nEj: login fallido masivo]) --> B[SOAR evaluate_triggers_for_context]
    B --> C{Condition match?\nidentity_group / iam_event}

    C -->|No match| D[No action]
    C -->|Match — priority DESC| E[_is_dedup_active?\ndedup_window_minutes check]

    E -->|Duplicado activo| F[Skip — awaiting_approval\naún en vuelo]
    E -->|Sin duplicado| G[_fire_trigger\nPlaybookContext + affected_user]

    G --> H[PB-005 — PIDS Identity Response\nrequires_approval = True]

    H --> I[Pasos secuenciales]
    I --> I1[LOG]
    I1 --> I2[CREATE_ALERT]
    I2 --> I3[NOTIFY]
    I3 --> I4[AWAIT_APPROVAL ⏱ HitL]

    I4 -->|Aprobado| I5[DISABLE_ACCOUNT\nvía Active Directory]
    I5 --> I6[FORCE_PASSWORD_RESET]
    I6 --> I7[QUARANTINE_ACCOUNT\nmove → AD_QUARANTINE_OU]
    I7 --> I8[NOTIFY — acción completada]

    I5 --> J[PIDS Token Forense\nSHA3-512 + Ed25519\npor cada paso]
    I6 --> J
    I7 --> J

    J --> K[IdentityAction record\nen PostgreSQL]
    K --> L[Correlation Engine\nseñal identity_action]
    K --> M[ScheduledReport\nforensic timeline]

    I4 -->|Rechazado| N[Playbook abortado\nAudit log]
```

---

## 7. Flujo: Correlation Engine — Sweep Cross-Domain (P27)

```mermaid
flowchart TD
    BEAT([Celery Beat\ncada 15min]) --> SWEEP[run_correlation_sweep]
    MANUAL([POST /correlation/sweep\nAdmin manual]) --> SWEEP

    SWEEP --> RULES[Cargar CorrelationRules\nenabled = True]

    RULES --> R1[R001: host_pivot\n≥3 señales / 60min]
    RULES --> R2[R002: identity_pivot\n≥2 señales / 120min]
    RULES --> R3[R003: ip_pivot\n≥2 señales / 60min HIGH+]
    RULES --> R4[R004: domain_pivot\n≥2 señales / 60min]

    R1 --> GATHER[_gather_X_signals\nwindow_start = now - time_window]

    subgraph GATHER_HOST[host_pivot sources]
        G1[Event.host]
        G2[Alert.affected_hosts JSON list]
        G3[HuntFinding.affected_host]
        G4[PANL isolate_endpoint.target]
    end

    subgraph GATHER_IDENTITY[identity_pivot sources]
        GI1[IdentityAction.username@domain]
        GI2[HuntFinding.affected_user]
    end

    subgraph GATHER_IP[ip_pivot sources]
        GIP1[Event.normalized src_ip/dst_ip]
        GIP2[ThreatIntelIndicator type=ip]
        GIP3[PANL block_ip.target]
    end

    GATHER --> FILTER[Filtrar por severity_threshold]
    FILTER --> GROUP[Agrupar por pivot_value]
    GROUP --> CHECK{signal_count\n>= min_signals?}

    CHECK -->|No| SKIP[Skip — señal insuficiente]
    CHECK -->|Sí| UPSERT[_upsert_cluster]

    UPSERT --> DEDUP[Deduplicar señales\npor signal_type + signal_id]
    DEDUP --> AGGR[Recompute:\n• severity = max\n• distinct_signal_domains\n• is_campaign ≥3 tipos\n• confidence_score\n• forensic_hash SHA3-512]

    AGGR --> CAMPAIGN{distinct_signal_domains\n≥ 3?}
    CAMPAIGN -->|Sí| CAMP[is_campaign = True\ncampaign_name auto-generado]
    CAMPAIGN -->|No| STORE[CorrelationCluster updated]
    CAMP --> STORE

    STORE --> GRAPH[GET /correlation/clusters/{id}/graph\nNodes + Edges por signal_type]
    STORE --> ANALYST[Dashboard /correlation\nKPIs + tabla + expand graph]
```

---

## 8. Flujo: Threat Hunting — Hypothesis to Finding (P22)

```mermaid
flowchart LR
    A([Analista crea Hunt\nHypothesis + MITRE]) --> B[POST /threat-hunting/sessions]
    B --> C[status: draft → active]

    C --> D[Ejecutar HuntQuery\nELK / Wazuh / Specter]
    D --> E[Resultados raw\nRead-only — no mutations]

    E --> F{Analista evalúa}
    F -->|Normal| G[Marcar is_false_positive]
    F -->|Sospechoso| H[Crear HuntFinding\nindicator_value + affected_host/user]

    H --> I[PCDI Escalation\n_check_critical_findings Celery]
    I --> J{adaptive_score\n>= 0.85?}
    J -->|Sí| K[SOAR evaluate_triggers\nhunt_priority / finding_severity]
    J -->|No| L[Finding archivado]

    K --> M[Auto-trigger playbook\nsi condition match]
    H --> N[Correlation Engine\nseñal: finding\nhost/user/domain pivot]

    C --> O[status: completed]
    O --> P[Conclusión + tags MITRE\nfindings_count + true_positive_count]
```

---

## 9. Flujo: Threat Intelligence — Ingesta y Enriquecimiento (P21)

```mermaid
flowchart TD
    subgraph INGESTA[Fuentes de Ingesta]
        I1[Analista manual\nPOST /threat-intel]
        I2[Bulk import CSV/MISP\nPOST /threat-intel/bulk]
        I3[TAXII / OpenCTI feed]
    end

    INGESTA --> TI[(ThreatIntelIndicator\nPostgreSQL)]

    TI --> ENR[POST /threat-intel/enrich\nvalue lookup]
    ENR --> MATCH{Encontrado?}
    MATCH -->|Sí| ENRICHED[Retornar indicator\n+ threat_actor, campaign, TTPs]
    MATCH -->|No| MISS[No match — no datos]

    TI --> HIT[hit_count++ / last_hit_at\ncuando alert o evento coincide]
    TI --> EXPIRE[expires_at check\nactive = False si expirado]

    TI --> CORR[Correlation Engine\nTI signal → ip_pivot / domain_pivot]
    TI --> PIDS[PIDS ScheduledReport\nTI correlación en forensic timeline]
```

---

## 10. Flujo: Forensic Ledger — Cadena de Custodia (P19)

```mermaid
sequenceDiagram
    participant ACTION as Acción de Sistema\n(PANL / PIDS / SOAR)
    participant LEDGER as ForensicEntry\n(PostgreSQL)
    participant SIGN as Ed25519 + SHA3-512\nSigning Module
    participant VERIFY as Endpoint /forensic/verify

    ACTION->>SIGN: canonical_dict\n(determinístico, sort_keys)
    SIGN->>SIGN: SHA3-512(canonical) → hash_hex
    SIGN->>SIGN: Ed25519.sign(hash_hex) → signature
    SIGN-->>ACTION: hash + signature

    ACTION->>LEDGER: INSERT ForensicEntry\n{hash_sha3_512, signature_ed25519,\nsigned_at, signed_by_email}

    Note over LEDGER: Inmutable — sin UPDATE/DELETE\nAudit trail completo

    VERIFY->>LEDGER: GET ForensicEntry by id
    LEDGER-->>VERIFY: stored hash + signature
    VERIFY->>SIGN: recompute hash desde canonical
    VERIFY->>SIGN: Ed25519.verify(stored_signature, computed_hash)
    SIGN-->>VERIFY: match / mismatch / no_key
    VERIFY-->>ACTION: {verified, hash_match, signature_ok}
```

---

## 11. Arquitectura Completa ASC — Vista de Sistema (v2.0)

```mermaid
flowchart TD
    subgraph INGESTION["Ingesta de Señales"]
        EV[Eventos SIEM\n/api/v1/events]
        AG[Specter Agents\npoll + result]
        HP[Honeypot\n/honeypot/events]
        TI2[Threat Intel\n/threat-intel]
    end

    subgraph ANALYSIS["Motor de Análisis"]
        NORM[Correlator / Normalizer]
        PCDI2[PCDI — Adaptive Scoring\nrisk_score + escalation]
        HUNT[Threat Hunting\nHypothesis + Queries]
        CORR2[Correlation Engine\nCross-domain Clusters]
    end

    subgraph RESPONSE["Motor de Respuesta"]
        SOAR2[SOAR — Auto-triggers\nCondition evaluation]
        PIDS2[PIDS — Identity SOAR\nEd25519 forensic tokens]
        PANL[PANL — Neutralización\nHuman-in-the-Loop]
    end

    subgraph ADAPTERS2["Adaptadores de Ejecución"]
        SPE[PremosCorp Specter\nEDR / Agent RTR]
        FW[Palo Alto / Fortinet\nFirewall Rules]
        AD2[Active Directory\nIdentity Actions]
    end

    subgraph STORAGE["Persistencia"]
        PG2[(PostgreSQL\nAll models)]
        RD2[(Redis\nCelery broker + JWT blacklist)]
    end

    subgraph OBSERVABILITY["Observabilidad"]
        FL[Forensic Ledger\nImmutable audit chain]
        OPS[Ops Dashboard\n/ops/cross-domain]
        REP[Scheduled Reports\nForensic + PIDS timeline]
    end

    subgraph FRONTEND["Frontend Next.js"]
        UI1[Dashboard / Alertas]
        UI2[SOAR / PIDS / Correlation]
        UI3[Threat Hunting / TI]
        UI4[Ops / Reports / Forensic]
    end

    INGESTION --> ANALYSIS
    ANALYSIS --> RESPONSE
    RESPONSE --> ADAPTERS2
    ADAPTERS2 --> STORAGE
    ANALYSIS --> STORAGE
    RESPONSE --> FL
    STORAGE --> OBSERVABILITY
    OBSERVABILITY --> FRONTEND
    INGESTION --> CORR2
    RESPONSE --> CORR2
    CORR2 --> STORAGE
```

---

## 12. Pipeline CI/CD con Security Gates

```mermaid
flowchart LR
    A([git push / PR]) --> B[GitHub Actions]

    B --> C[Secrets Scan\ngitleaks / detect-secrets]
    B --> D[Dependency Audit\nsafety / pip-audit]
    B --> E[Static Analysis\nbandit / semgrep]

    C -->|FAIL| BLOCK([❌ PR Bloqueado])
    D -->|FAIL| BLOCK
    E -->|FAIL| BLOCK

    C -->|PASS| F[Unit Tests\npytest + coverage]
    D -->|PASS| F
    E -->|PASS| F

    F -->|coverage < 85%| BLOCK
    F -->|PASS| G[Integration Tests\nvs sandbox APIs]

    G -->|FAIL| BLOCK
    G -->|PASS| H[Container Build\ndocker build]

    H --> I[Trivy Scan\nContainer vulnerabilities]
    I -->|CRITICAL vuln| BLOCK
    I -->|PASS| J[Deploy Staging]

    J --> K[Smoke Tests\nE2E básico]
    K -->|FAIL| L([🔄 Rollback Staging])
    K -->|PASS| M([✅ Listo para\nProducción])

    M --> N{Manual Approval\nTech Lead}
    N -->|Approve| O([🚀 Deploy Producción])
    N -->|Reject| BLOCK
```

---

## Índice de Módulos — Estado Actual (P27)

| Módulo | Descripción | Estado |
|--------|-------------|--------|
| P01–P15 | Core platform, auth, RBAC, events, alerts, neutralización base | ✅ Completado |
| P16 | PANL — Human-in-the-Loop + multi-firma + rollback | ✅ Completado |
| P17 | SPECTER Agents — fleet command + heartbeat | ✅ Completado |
| P18 | Honeypot — traps passivos, detection, evidencia | ✅ Completado |
| P19 | Forensic Ledger — cadena de custodia Ed25519 + SHA3-512 | ✅ Completado |
| P20 | Ops Dashboard — fleet health, cross-domain metrics | ✅ Completado |
| P21 | Threat Intelligence — indicadores, enriquecimiento, bulk import | ✅ Completado |
| P22 | Threat Hunting — sessions, findings, queries read-only | ✅ Completado |
| P24 | PCDI — Adaptive scoring, Celery escalation, MITRE context | ✅ Completado |
| P25 | SOAR — Auto-triggers, playbooks, condition engine | ✅ Completado |
| P26 | PIDS — Identity SOAR, forensic tokens, scheduled reports | ✅ Completado |
| P27 | Correlation Engine — cross-domain clusters, campaigns, graph | ✅ Completado |
| **P28** | **Próximo módulo — por definir** | 🔲 Planificación |
