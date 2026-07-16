"""
S103.3 — Invalidación de sesión por epoch (tokens_valid_after).

Gap cerrado: cambiar la contraseña (o forzar logout-all) invalida TODAS las
sesiones previas — access Y refresh, de cualquier dispositivo. Antes, un token
robado seguía sirviendo después del cambio de contraseña.
"""
from __future__ import annotations

import uuid
import jwt as pyjwt
import pytest
from datetime import datetime, timezone, timedelta

from asc_api.core import security
from asc_api.core.config import get_settings
from asc_api.core.security import ALGORITHM, create_access_token, decode_token_payload, get_password_hash
from asc_api.models.user import User


def _token(sub: str, ttype: str, iat_dt: datetime) -> str:
    return pyjwt.encode(
        {"sub": sub, "type": ttype, "jti": str(uuid.uuid4()),
         "iat": int(iat_dt.timestamp()),
         "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
        get_settings().SECRET_KEY, algorithm=ALGORITHM,
    )


class TestEpochHelper:
    def test_none_epoch_nunca_invalida(self):
        assert security.is_token_before_epoch({"iat": 1}, None) is False

    def test_token_sin_iat_invalido_si_hay_epoch(self):
        epoch = datetime.now(timezone.utc)
        assert security.is_token_before_epoch({}, epoch) is True

    def test_iat_anterior_al_epoch_invalido(self):
        now = datetime.now(timezone.utc)
        old = {"iat": int((now - timedelta(minutes=5)).timestamp())}
        assert security.is_token_before_epoch(old, now) is True

    def test_iat_posterior_al_epoch_valido(self):
        now = datetime.now(timezone.utc)
        fresh = {"iat": int((now + timedelta(minutes=5)).timestamp())}
        assert security.is_token_before_epoch(fresh, now) is False


class TestTokensLlevanIat:
    def test_access_token_incluye_iat(self):
        p = decode_token_payload(create_access_token("u1"))
        assert "iat" in p and isinstance(p["iat"], int)


async def _mk_user(db, epoch=None, pwd="Xx@12345!"):
    u = User(
        id=str(uuid.uuid4()), email=f"u-{uuid.uuid4().hex[:8]}@x.com", full_name="U",
        hashed_password=get_password_hash(pwd), role="analyst", is_active=True,
        tokens_valid_after=epoch,
    )
    db.add(u); await db.commit(); return u


class TestEnforcement:
    @pytest.mark.asyncio
    async def test_token_previo_al_epoch_rechazado(self, client, db):
        now = datetime.now(timezone.utc)
        user = await _mk_user(db, epoch=now)
        old = _token(user.id, "access", now - timedelta(minutes=10))
        r = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {old}"})
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_refresh_previo_al_epoch_rechazado(self, client, db):
        now = datetime.now(timezone.utc)
        user = await _mk_user(db, epoch=now)
        old_refresh = _token(user.id, "refresh", now - timedelta(minutes=10))
        r = await client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_sin_epoch_el_token_funciona(self, client, db):
        now = datetime.now(timezone.utc)
        user = await _mk_user(db, epoch=None)
        tok = _token(user.id, "access", now - timedelta(minutes=10))
        r = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200


class TestChangePasswordCortaSesiones:
    @pytest.mark.asyncio
    async def test_change_password_invalida_tokens_previos(self, client, db):
        """End-to-end: un token emitido ANTES del cambio de contraseña queda
        invalidado DESPUÉS — el hueco de seguridad cerrado."""
        now = datetime.now(timezone.utc)
        user = await _mk_user(db, pwd="OldSecret@12345!")   # epoch=None
        old_tok = _token(user.id, "access", now - timedelta(minutes=5))

        # Antes: el token sirve para cambiar la contraseña (epoch aún None).
        r1 = await client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {old_tok}"},
            json={"current_password": "OldSecret@12345!", "new_password": "NewSecret@98765!"},
        )
        assert r1.status_code == 200

        # Después: el MISMO token (previo al epoch) queda rechazado.
        r2 = await client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {old_tok}"}
        )
        assert r2.status_code == 401
