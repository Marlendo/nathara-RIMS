import asyncio
import logging

from flask import current_app
from sqlalchemy import text

from ops_api.ops.auth.supabase_sso_provider import get_supabase_jwks


async def check_auth_services() -> dict:
    """MIGRATION (PM RIMS 0001): cek provider OAuth lama DIMATIKAN.

    Diganti health-check read-only ke JWKS Supabase prod (publik).
    M-01 (PM RIMS 0002): pakai get_supabase_jwks() yang sudah cache TTL
    10 menit + fallback cache basi — TIDAK fetch langsung tiap poll.
    Returns:
        dict: with alarm_level>0 if there is a problem
    """

    resp = {"status_code": None, "alarm_level": 0}
    if not current_app.config.get("HEALTH_CHECK_AUTH_SERVICES", True):
        return resp
    try:
        jwks = get_supabase_jwks()
        keys = jwks.get("keys", [])
        resp["status_code"] = 200 if keys else 503
        # JWKS kosong (IdP belum terbit key) = fail-closed, alarm agar terpantau.
        if not keys:
            resp["alarm_level"] = 1
    except Exception as e:
        logging.error("SSO JWKS check failed: " + str(e), exc_info=True)
        resp["alarm_level"] = 2
    return resp


async def check_db_conn() -> dict:
    """check the DB by executing a test query
    Returns:
        dict: alarm_level>0 if there is a problem
    """
    resp = {"db_conn_is_ok": True, "alarm_level": 0}
    try:
        current_app.db_session.execute(
            text("SELECT 'OK';"),
            execution_options={"timeout": 5},  # just pool wait timeout ?
        )
    except Exception as e:
        logging.error("Database test query failed: " + str(e), exc_info=True)
        resp["db_conn_is_ok"] = False
        resp["alarm_level"] = 2
    try:
        pool = current_app.engine.pool
        pool_status = {
            "size": pool.size(),
            "checked_in": pool.checkedin(),
            "overflow": pool.overflow(),
            "checked_out": pool.checkedout(),
        }
        resp["pool_status"] = pool_status
    except Exception as e:
        logging.error("Connection pool status failed: " + str(e), exc_info=True)
    return resp


async def check_all() -> dict:
    """run all checks (DB and Auth services)
    Returns:
        dict: a map of the responses from each check
    """
    auth, db_conn = await asyncio.gather(check_auth_services(), check_db_conn())
    checks = {"auth_services": auth, "database_connection": db_conn}
    return checks
