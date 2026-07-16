"""
Gate de integridad: frontend/asc_api debe ser espejo byte-exacto de backend/asc_api.

Por qué existe: la copia manual divergió dos veces con impacto real —
S99 (fix CORS aplicado solo a backend/asc_api, nunca llegó al deploy) y
S100 (cron.py registrado solo en backend/asc_api → 5 crons de vercel.json
apuntando a rutas 404). Patrón incidente I-2.

Si este test falla: NO edites frontend/asc_api a mano.
Corre `node scripts/sync-asc-api.mjs` desde el root del proyecto.
"""
import hashlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "backend" / "asc_api"
DST = REPO / "frontend" / "asc_api"
EXCLUDE = {"__pycache__", ".pytest_cache", ".mypy_cache"}


def _tree(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in root.rglob("*"):
        if p.is_dir() or any(part in EXCLUDE for part in p.parts):
            continue
        out[p.relative_to(root).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def test_source_tree_exists():
    assert SRC.is_dir(), f"No existe {SRC} — la fuente única debe ser backend/asc_api"
    assert DST.is_dir(), f"No existe {DST} — el espejo desplegado por Vercel (asc-mono)"


def test_frontend_asc_api_is_exact_mirror_of_backend():
    src, dst = _tree(SRC), _tree(DST)
    missing = sorted(set(src) - set(dst))
    extra = sorted(set(dst) - set(src))
    changed = sorted(k for k in set(src) & set(dst) if src[k] != dst[k])
    assert not (missing or extra or changed), (
        "frontend/asc_api divergió de backend/asc_api — "
        "corre `node scripts/sync-asc-api.mjs`.\n"
        f"  faltan_en_frontend={missing[:10]}\n"
        f"  sobran_en_frontend={extra[:10]}\n"
        f"  contenido_distinto={changed[:10]}"
    )
