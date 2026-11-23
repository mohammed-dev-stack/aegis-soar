from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

_SET_TENANT_SQL = text("SELECT set_config('app.current_tenant_id', :tid, true)")


@asynccontextmanager
async def tenant_transaction(
    session_factory: async_sessionmaker[AsyncSession],
    tenant_id: UUID,
) -> AsyncIterator[AsyncSession]:
    """Open a transaction-scoped session bound to a single tenant via set_config.

    Because is_local=true, PostgreSQL automatically clears app.current_tenant_id
    on COMMIT or ROLLBACK, preventing connection-pool cross-talk.
    """
    async with session_factory() as session, session.begin():
        await session.execute(_SET_TENANT_SQL, {"tid": str(tenant_id)})
        yield session


@asynccontextmanager
async def pre_auth_session(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    """Open a transaction with NO tenant context bound.

    Used strictly for pre-login calls to auth_lookup_identity(p_email).
    All tenant-scoped tables fail closed (0 rows) under this session.
    """
    async with session_factory() as session, session.begin():
        yield session
