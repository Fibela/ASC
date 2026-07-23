import os

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import AsyncAdaptedQueuePool, NullPool

from asc_api.core.config import get_settings

settings = get_settings()

# Ensure asyncpg driver is always used regardless of URL prefix in env var
_db_url = settings.DATABASE_URL.strip()
if _db_url.startswith("postgresql://"):
    _db_url = _db_url.replace("postgresql://", "postgresql+asyncpg://", 1)

# Serverless environments (Vercel Lambda) must not maintain connection pools —
# each function invocation is independent and shared pools cause connection leaks.
# NullPool creates a fresh connection per request; Supabase's transaction pooler
# (port 6543) handles efficient connection reuse at the infrastructure level.
_IS_SERVERLESS = bool(os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))

engine = create_async_engine(
    _db_url,
    poolclass=NullPool if _IS_SERVERLESS else AsyncAdaptedQueuePool,
    **(
        {}
        if _IS_SERVERLESS
        else {
            "pool_pre_ping": True,
            "pool_size": 10,
            "max_overflow": 20,
        }
    ),
    echo=settings.DEBUG,
    connect_args={"statement_cache_size": 0},  # required for Supabase Transaction pooler (port 6543)
)

AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session
