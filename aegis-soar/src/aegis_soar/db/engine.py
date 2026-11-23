from __future__ import annotations

import os

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

DEFAULT_APP_DATABASE_URL = "postgresql+asyncpg://aegis_app:aegis_app_dev@localhost:5433/aegis_soar"


def get_app_database_url() -> str:
    """Return the asyncpg DSN for the least-privilege aegis_app role."""
    return os.environ.get("AEGIS_APP_DATABASE_URL", DEFAULT_APP_DATABASE_URL)


def create_app_engine(database_url: str | None = None) -> AsyncEngine:
    """Create the SQLAlchemy 2.0 async engine for aegis_app.

    Pool sizing satisfies Gate G3 concurrency requirements (pool_size >= 10).
    """
    url = database_url or get_app_database_url()
    return create_async_engine(
        url,
        pool_size=12,
        max_overflow=8,
        pool_pre_ping=True,
        future=True,
    )


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create an async session factory with expire_on_commit disabled."""
    return async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        autoflush=False,
        expire_on_commit=False,
    )
