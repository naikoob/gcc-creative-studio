# Copyright 2026 Google LLC
# IM8-Compliant Bootstrap Overlay for Cloud SQL Private IP & IAM Auth

import asyncio
import logging
import os

from bootstrap.bootstrap import main as upstream_bootstrap_main
from src.config.config_service import config_service

logger = logging.getLogger(__name__)


async def ensure_schema_permissions():
    """Ensure the IAM runtime user has full permissions on schema public.

    In PostgreSQL 15+, CREATE on schema public was revoked from PUBLIC.
    If ADMIN_DB_PASS is set, connect as postgres to grant ownership/privileges.
    """
    admin_pass = os.getenv("ADMIN_DB_PASS")
    if not admin_pass:
        return

    logger.info(
        "ADMIN_DB_PASS detected: Ensuring schema public permissions for %s...",
        config_service.DB_USER,
    )
    from google.cloud.sql.connector import Connector, IPTypes

    loop = asyncio.get_running_loop()
    connector = Connector(loop=loop)
    ip_type = (
        IPTypes.PRIVATE
        if config_service.DB_IP_TYPE.upper() == "PRIVATE"
        else IPTypes.PUBLIC
    )
    conn = await connector.connect_async(
        config_service.INSTANCE_CONNECTION_NAME,
        "asyncpg",
        user="postgres",
        password=admin_pass,
        db=config_service.DB_NAME,
        ip_type=ip_type,
    )
    try:
        user_to_grant = config_service.DB_USER
        logger.info(
            "Configuring schema public permissions for %s...", user_to_grant
        )
        try:
            version_check = await conn.fetchval(
                "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'alembic_version');"
            )
            if not version_check:
                logger.info("Initial run detected: resetting schema public...")
                await conn.execute("DROP SCHEMA IF EXISTS public CASCADE;")
                await conn.execute("CREATE SCHEMA public;")
            await conn.execute(
                f'GRANT ALL ON SCHEMA public TO "{user_to_grant}";'
            )
            await conn.execute("GRANT ALL ON SCHEMA public TO postgres;")
            await conn.execute(
                f'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO "{user_to_grant}";'
            )
            await conn.execute(
                f'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO "{user_to_grant}";'
            )
            logger.info("Schema public permissions configured successfully.")
        except Exception as e:
            logger.warning("Error configuring schema public: %s", e)
    finally:
        await conn.close()
        await connector.close_async()


async def main():
    await ensure_schema_permissions()
    await upstream_bootstrap_main()


if __name__ == "__main__":
    asyncio.run(main())
