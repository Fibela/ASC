# Arquitectura del Servicio de Neutralización — Producción
> Versión 1.0 | Fecha: 2026-06-04

---

## Estado Actual vs. Estado Objetivo

### Estado Actual (Simulación)
```python
# backend/app/services/neutralizer.py — ESTADO ACTUAL
async def isolate_endpoint(host: str, reason: str = "") -> NeutralizationResult:
    await asyncio.sleep(0.1)  # ← placeholder, no hace nada real
    return NeutralizationResult(success=True, message=f"Endpoint {host} isolated")
```

### Estado Objetivo (Producción)
```python
# backend/app/services/neutralizer.py — ESTADO OBJETIVO
async def isolate_endpoint(host: str, reason: str = "") -> NeutralizationResult:
    adapter = get_edr_adapter()                           # Factory pattern
    await approval_queue.request(                         # Human-in-the-loop
        action="isolate_endpoint",
        params={"host": host, "reason": reason},
        severity="critical",
        timeout_minutes=15
    )
    result = await adapter.isolate_host(host, reason)     # CrowdStrike real API
    await audit_log.record(action="isolate_endpoint", result=result)  # Auditoría
    return result
```

---

## Diagrama de Componentes

```
┌────────────────────────────────────────────────────────────────┐
│                     ASC Backend (FastAPI)                      │
│                                                                │
│  ┌──────────────┐    ┌──────────────────┐   ┌──────────────┐  │
│  │  API Layer   │    │  Neutralizer     │   │  Audit Log   │  │
│  │  /neutralize │───▶│  Orchestrator   │──▶│  Service     │  │
│  └──────────────┘    └────────┬─────────┘   └──────────────┘  │
│                               │                                │
│                    ┌──────────┴──────────┐                    │
│                    ▼                     ▼                     │
│           ┌─────────────────┐   ┌─────────────────┐           │
│           │  Approval Queue │   │  Adapter Factory│           │
│           │  (Celery + Redis│   └────────┬────────┘           │
│           └────────┬────────┘            │                    │
│                    │             ┌───────┼────────┐           │
│                    ▼             ▼       ▼        ▼           │
│           ┌────────────────┐  ┌────┐ ┌──────┐ ┌────┐        │
│           │WebSocket       │  │EDR │ │ FW   │ │ ID │        │
│           │Notifications   │  │Adp │ │ Adp  │ │ Adp│        │
│           └────────────────┘  └──┬─┘ └──┬───┘ └──┬─┘        │
└────────────────────────────────  │       │        │  ─────────┘
                                   ▼       ▼        ▼
                             ┌──────────────────────────┐
                             │  Integraciones Externas  │
                             │                          │
                             │  CrowdStrike Falcon API  │
                             │  Palo Alto PAN-OS API    │
                             │  Fortinet FortiGate API  │
                             │  Active Directory / LDAP │
                             └──────────────────────────┘
```

---

## Diseño de Adaptadores (Adapter Pattern)

### Interfaces Abstractas (`backend/app/adapters/base.py`)

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass

@dataclass
class ActionResult:
    success: bool
    message: str
    details: dict
    action_id: str       # ID único para tracking
    executed_at: str     # ISO timestamp
    provider: str        # "crowdstrike", "paloalto", etc.
    raw_response: dict   # Respuesta completa del proveedor para auditoría

class BaseEDRAdapter(ABC):
    @abstractmethod
    async def isolate_host(self, host_id: str, reason: str) -> ActionResult: ...
    @abstractmethod
    async def lift_isolation(self, host_id: str, reason: str) -> ActionResult: ...
    @abstractmethod
    async def kill_process(self, host_id: str, process_name: str, pid: int | None) -> ActionResult: ...
    @abstractmethod
    async def quarantine_file(self, host_id: str, file_path: str) -> ActionResult: ...
    @abstractmethod
    async def health_check(self) -> bool: ...

class BaseFirewallAdapter(ABC):
    @abstractmethod
    async def block_ip(self, ip: str, direction: str, reason: str) -> ActionResult: ...
    @abstractmethod
    async def unblock_ip(self, ip: str) -> ActionResult: ...
    @abstractmethod
    async def block_domain(self, domain: str, reason: str) -> ActionResult: ...
    @abstractmethod
    async def unblock_domain(self, domain: str) -> ActionResult: ...
    @abstractmethod
    async def health_check(self) -> bool: ...

class BaseIdentityAdapter(ABC):
    @abstractmethod
    async def disable_account(self, username: str, domain: str, reason: str) -> ActionResult: ...
    @abstractmethod
    async def enable_account(self, username: str, domain: str) -> ActionResult: ...
    @abstractmethod
    async def force_password_reset(self, username: str, domain: str) -> ActionResult: ...
    @abstractmethod
    async def health_check(self) -> bool: ...
```

---

## Integración 1: CrowdStrike Falcon

### Autenticación
```python
# backend/app/adapters/edr/crowdstrike.py

class CrowdStrikeFalconAdapter(BaseEDRAdapter):
    """
    Usa la API OAuth2 de CrowdStrike Falcon.
    Docs: https://falcon.crowdstrike.com/documentation/
    Base URL: https://api.crowdstrike.com
    """
    
    def __init__(self, client_id: str, client_secret: str, base_url: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url
        self._token: str | None = None
        self._token_expires_at: float = 0
    
    async def _get_token(self) -> str:
        """OAuth2 client credentials, con refresh automático."""
        import time
        if self._token and time.time() < self._token_expires_at - 60:
            return self._token
        
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.base_url}/oauth2/token",
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
            self._token = data["access_token"]
            self._token_expires_at = time.time() + data["expires_in"]
            return self._token
```

### Endpoints de API utilizados

| Acción | Método | Endpoint CrowdStrike |
|--------|--------|----------------------|
| Aislar host | POST | `/devices/entities/devices-actions/v2?action_name=contain` |
| Levantar aislamiento | POST | `/devices/entities/devices-actions/v2?action_name=lift_containment` |
| Buscar host por hostname | GET | `/devices/queries/devices/v1?filter=hostname:'...'` |
| Iniciar RTR session | POST | `/real-time-response/entities/sessions/v1` |
| Ejecutar comando RTR | POST | `/real-time-response/entities/active-sessions/v1` |
| Kill process (RTR) | POST | RTR `kill` command |
| Quarantine file (RTR) | POST | RTR `put` + `run` commands |

### Retry Logic y Circuit Breaker
```python
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type(httpx.HTTPStatusError),
    reraise=True
)
async def _api_call(self, method: str, endpoint: str, **kwargs) -> dict:
    token = await self._get_token()
    async with httpx.AsyncClient() as client:
        resp = await client.request(
            method,
            f"{self.base_url}{endpoint}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
            **kwargs
        )
        resp.raise_for_status()
        return resp.json()
```

---

## Integración 2: Palo Alto Networks / Fortinet

### Palo Alto PAN-OS REST API

**Enfoque:** Dynamic Address Groups + Custom URL Categories

```python
# backend/app/adapters/firewall/paloalto.py

class PaloAltoAdapter(BaseFirewallAdapter):
    """
    Usa PAN-OS REST API.
    Requiere API Key generada en: Device > Administrators > API Key
    Base URL: https://<panorama-ip>/restapi/v10.1
    """

    async def block_ip(self, ip: str, direction: str, reason: str) -> ActionResult:
        # 1. Crear Address Object
        # POST /restapi/v10.1/Objects/Addresses
        # 2. Agregar a Dynamic Address Group "ASC-Blocked-IPs"
        # 3. Commit (o usar candidate config + commit)
        ...

    async def block_domain(self, domain: str, reason: str) -> ActionResult:
        # 1. Agregar a Custom URL Category "ASC-Blocked-Domains"
        # PUT /restapi/v10.1/Objects/CustomURLCategories
        # 2. Commit
        ...
```

### Fortinet FortiGate REST API

```python
# backend/app/adapters/firewall/fortinet.py

class FortinetAdapter(BaseFirewallAdapter):
    """
    Usa FortiGate REST API.
    Token via: System > API Users
    Base URL: https://<fortigate-ip>/api/v2
    """

    async def block_ip(self, ip: str, direction: str, reason: str) -> ActionResult:
        # 1. POST /api/v2/cmdb/firewall/address — crear Address Object
        # 2. POST /api/v2/cmdb/firewall/addrgrp — agregar a grupo "ASC_Blocked"
        # 3. Verificar que la policy que usa el grupo está activa
        ...
```

### Estrategia de Commit (Palo Alto)
Las operaciones en PAN-OS requieren un **commit explícito**. La estrategia es:
- Acumular cambios en candidate config durante la ventana de aprobación
- Ejecutar un único commit al aprobar la acción
- Verificar el estado del commit antes de marcar como completado
- En caso de fallo del commit: rollback y notificar al analista

---

## Integración 3: Active Directory / LDAP

### Configuración de Conexión
```python
# backend/app/adapters/identity/active_directory.py
import ldap3

class ActiveDirectoryAdapter(BaseIdentityAdapter):
    """
    Usa ldap3 con LDAPS (TLS requerido en producción).
    Credenciales: cuenta de servicio con permisos mínimos necesarios.
    Permisos requeridos: 
      - Modify userAccountControl (deshabilitar/habilitar)
      - Reset password (force password change)
      - Move objects between OUs (quarantine OU)
    """
    
    def __init__(self, server_url: str, bind_dn: str, bind_password: str, base_dn: str):
        # LDAPS obligatorio en producción (puerto 636)
        tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLSv1_2)
        self.server = ldap3.Server(server_url, use_ssl=True, tls=tls, get_info=ldap3.ALL)
        self.bind_dn = bind_dn
        self.bind_password = bind_password  # Debe venir de Vault, nunca hardcodeado
        self.base_dn = base_dn

    async def disable_account(self, username: str, domain: str, reason: str) -> ActionResult:
        """
        Deshabilita cuenta via userAccountControl flag.
        UF_ACCOUNTDISABLE = 0x0002
        Para deshabilitar: OR con 0x0002
        Para habilitar: AND NOT con 0x0002
        """
        ...
```

### Principio de Mínimo Privilegio
La cuenta de servicio de AD debe tener **únicamente** los permisos necesarios:
- Delegación en OUs específicas (no Domain Admin)
- Derecho de "Reset Password" en usuarios objetivo
- Derecho de "Write Account Restrictions" para `userAccountControl`
- Derecho de "Move objects" solo hacia la OU de cuarentena

---

## Workflow Human-in-the-Loop

### Modelo de Aprobación (`backend/app/models/neutralization.py`)
```python
class NeutralizationRequest(Base):
    __tablename__ = "neutralization_requests"
    
    id:           str      # UUID
    alert_id:     str      # FK a Alert
    action_type:  str      # "isolate_endpoint", "block_ip", etc.
    params:       dict     # Parámetros de la acción
    severity:     str      # Determina timeout
    status:       str      # PENDING_APPROVAL | APPROVED | REJECTED |
                           # EXECUTING | COMPLETED | FAILED | ESCALATED
    requested_by: str      # user_id que inició la solicitud (sistema o analista)
    approved_by:  str      # user_id del analista que aprobó
    rejected_by:  str      # user_id del analista que rechazó
    reason:       str      # Justificación de aprobación/rechazo
    created_at:   datetime
    expires_at:   datetime  # created_at + timeout según severidad
    executed_at:  datetime
    result:       dict     # Respuesta completa del adapter
    audit_trail:  list     # Lista de eventos con timestamp
```

### Timeouts por Severidad
| Severidad | Timeout | Escalación |
|-----------|---------|------------|
| CRITICAL | 15 minutos | Tier 2 SOC Lead |
| HIGH | 30 minutos | Senior Analyst |
| MEDIUM | Automático (sin aprobación) | N/A |
| LOW | Automático (sin aprobación) | N/A |

---

## Auditoría (Audit Trail)

**Principio:** Toda acción de neutralización debe ser 100% rastreable. El audit trail es **inmutable** — no se permite UPDATE ni DELETE en la tabla de auditoría.

### Eventos auditados
1. Solicitud de neutralización creada
2. Notificación enviada al analista
3. Analista abrió la solicitud (viewed_at)
4. Analista aprobó/rechazó con justificación
5. Ejecución iniciada
6. Respuesta del proveedor recibida (completa)
7. Estado final registrado
8. Escalación (si timeout)

### Estructura del log de auditoría
```json
{
  "event_id": "uuid",
  "timestamp": "2026-06-04T14:32:01Z",
  "event_type": "neutralization.approved",
  "actor": {
    "user_id": "analyst-123",
    "username": "j.garcia",
    "ip": "10.0.1.50"
  },
  "resource": {
    "request_id": "uuid",
    "action_type": "isolate_endpoint",
    "target": "WORKSTATION-042"
  },
  "outcome": "success",
  "reason": "Confirmed C2 beacon activity",
  "provider_response": { /* respuesta completa de CrowdStrike */ }
}
```

---

## Gestión de Secretos

### Nunca en código ni en `.env` en producción

| Secreto | Almacenamiento Dev | Almacenamiento Prod |
|---------|-------------------|---------------------|
| CrowdStrike Client Secret | `.env` local | HashiCorp Vault |
| PAN-OS API Key | `.env` local | HashiCorp Vault |
| Fortinet API Token | `.env` local | HashiCorp Vault |
| AD Service Account Password | `.env` local | HashiCorp Vault |
| PostgreSQL password | `.env` local | AWS Secrets Manager |
| SECRET_KEY FastAPI | `.env` local | HashiCorp Vault |

### Validación de secrets antes de deploy
```bash
# Escaneo obligatorio antes de cualquier push/deploy
gitleaks detect --source . --verbose
detect-secrets scan . | jq '.results | length'  # Debe ser 0
grep -rn "CHANGEME\|changeme\|your-secret\|replace-me" . --include="*.py" --include="*.yml" --include="*.env*"
```

---

## Configuración (`backend/app/core/config.py` — Extensiones para Fase 1)

```python
class Settings(BaseSettings):
    # ... settings existentes ...
    
    # CrowdStrike
    CROWDSTRIKE_CLIENT_ID: str = ""
    CROWDSTRIKE_CLIENT_SECRET: str = ""  # Desde Vault en producción
    CROWDSTRIKE_BASE_URL: str = "https://api.crowdstrike.com"
    
    # Palo Alto
    PALOALTO_HOST: str = ""
    PALOALTO_API_KEY: str = ""           # Desde Vault
    PALOALTO_VSYS: str = "vsys1"
    PALOALTO_BLOCKED_ADDRESS_GROUP: str = "ASC-Blocked-IPs"
    
    # Fortinet
    FORTINET_HOST: str = ""
    FORTINET_API_TOKEN: str = ""         # Desde Vault
    FORTINET_VDOM: str = "root"
    
    # Active Directory
    AD_SERVER_URL: str = ""              # ldaps://dc.premoscorp.local:636
    AD_BIND_DN: str = ""
    AD_BIND_PASSWORD: str = ""           # Desde Vault
    AD_BASE_DN: str = ""
    AD_QUARANTINE_OU: str = ""
    
    # Approval Workflow
    APPROVAL_TIMEOUT_CRITICAL_MINUTES: int = 15
    APPROVAL_TIMEOUT_HIGH_MINUTES: int = 30
    ESCALATION_EMAIL: str = ""
```
