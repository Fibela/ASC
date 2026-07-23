"""
seed_correlation — canonical definition of global (tenant_id=NULL) correlation rules.

These 4 rules are seeded by migration j9d14g2b5c37 and are read-only for all
tenants (protected by correlation_service.update_rule / delete_rule with a
PermissionError guard).  They are exposed here as a constant so tests and
tooling can validate them without importing the migration module.

P-16 note: all entries MUST have tenant_id absent (None) to be treated as
global system rules visible to every tenant.
"""

from __future__ import annotations

SEED_RULES: list[dict] = [
    {
        "name": "R001 — Host Lateral Movement",
        "description": ("Clusters signals sharing a host pivot to detect lateral movement campaigns."),
        "pivot_type": "host_pivot",
        "min_signals": 3,
        "time_window_minutes": 60,
        "severity_threshold": "medium",
        "enabled": True,
        "tenant_id": None,
    },
    {
        "name": "R002 — Identity Compromise",
        "description": ("Groups identity-related signals to detect account takeover or credential abuse."),
        "pivot_type": "identity_pivot",
        "min_signals": 2,
        "time_window_minutes": 120,
        "severity_threshold": "medium",
        "enabled": True,
        "tenant_id": None,
    },
    {
        "name": "R003 — C2 IP Activity",
        "description": ("Detects repeated contact with a suspicious IP across events, TI hits, and neutralizations."),
        "pivot_type": "ip_pivot",
        "min_signals": 2,
        "time_window_minutes": 60,
        "severity_threshold": "high",
        "enabled": True,
        "tenant_id": None,
    },
    {
        "name": "R004 — Malicious Domain Cluster",
        "description": ("Groups domain-related signals to identify phishing or malware distribution infrastructure."),
        "pivot_type": "domain_pivot",
        "min_signals": 2,
        "time_window_minutes": 60,
        "severity_threshold": "medium",
        "enabled": True,
        "tenant_id": None,
    },
]
