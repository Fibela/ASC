"""
Shared pytest fixtures for ASC test suite.

Uses an in-memory SQLite DB (via aiosqlite) so tests run without
a live PostgreSQL instance. httpx.AsyncClient is used to call the
FastAPI app without a real server.
"""
import uuid as _uuid
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from datetime import datetime, timezone, timedelta

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.user import User
from app.core.security import get_password_hash, create_access_token, create_refresh_token


@pytest_asyncio.fixture
async def db():
    """
    Fresh SQLite in-memory DB per test — guaranteed clean state.

    Each test gets its own named in-memory database (via URI) so commits in one
    test never bleed into the next.  The engine is disposed after the test.
    """
    db_name = _uuid.uuid4().hex
    url = f"sqlite+aiosqlite:///file:{db_name}?mode=memory&cache=shared&uri=true"
    eng = create_async_engine(url, echo=False)
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async_session = async_sessionmaker(eng, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        yield session
    await eng.dispose()


@pytest_asyncio.fixture
async def client(db):
    """AsyncClient with the DB dependency overridden to use the test session."""
    async def _override_get_db():
        yield db

    app.dependency_overrides[get_db] = _override_get_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


# ─── User factory fixtures ────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def admin_user(db: AsyncSession) -> User:
    user = User(
        email="admin@premoscorp.com",
        full_name="Admin Test",
        hashed_password=get_password_hash("Admin@1234!"),
        role="admin",
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@pytest_asyncio.fixture
async def analyst_user(db: AsyncSession) -> User:
    user = User(
        email="analyst@premoscorp.com",
        full_name="Analyst Test",
        hashed_password=get_password_hash("Analyst@1234!"),
        role="analyst",
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@pytest_asyncio.fixture
async def viewer_user(db: AsyncSession) -> User:
    user = User(
        email="viewer@premoscorp.com",
        full_name="Viewer Test",
        hashed_password=get_password_hash("Viewer@1234!"),
        role="viewer",
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


# ─── Token factory fixtures ───────────────────────────────────────────────────

@pytest.fixture
def admin_token(admin_user: User) -> str:
    return create_access_token(admin_user.id)


@pytest.fixture
def analyst_token(analyst_user: User) -> str:
    return create_access_token(analyst_user.id)


@pytest.fixture
def viewer_token(viewer_user: User) -> str:
    return create_access_token(viewer_user.id)


@pytest.fixture
def admin_headers(admin_token: str) -> dict:
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture
def analyst_headers(analyst_token: str) -> dict:
    return {"Authorization": f"Bearer {analyst_token}"}


@pytest.fixture
def viewer_headers(viewer_token: str) -> dict:
    return {"Authorization": f"Bearer {viewer_token}"}


# ─── Helpers ─────────────────────────────────────────────────────────────────

@pytest.fixture
def now_utc() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def past_3h(now_utc) -> datetime:
    return now_utc - timedelta(hours=3)


@pytest.fixture
def past_25h(now_utc) -> datetime:
    return now_utc - timedelta(hours=25)
