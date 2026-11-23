from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from flask import current_app, request
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
)
from loguru import logger
from sqlalchemy import select, text
from sqlalchemy.exc import DatabaseError, OperationalError
from sqlalchemy.orm import Session, selectinload

from models import OpsEventType, User, UserSession
from ops_api.ops.auth.auth_types import UserInfoDict
from ops_api.ops.auth.exceptions import PrivateKeyError


def create_oauth_jwt(
    provider: str,
    config,
    key: Optional[str] = None,
    header: Optional[str] = None,
    payload: Optional[dict[str, Any]] = None,
) -> str:
    """MIGRATION (PM RIMS 0001): penandatanganan JWT keypair lama DIMATIKAN.

    Keypair lama (private key) HARAM dipakai. Verifikasi diganti JWKS prod
    publik, lihat supabase_sso_provider.verify_supabase_jwt.
    """
    raise PrivateKeyError("Penandatanganan JWT lama dimatikan (PM RIMS 0001).")


def get_jwks(provider_metadata_url: str) -> str:
    """MIGRATION (PM RIMS 0001): fetch JWKS tanpa cache DIMATIKAN.

    Diganti supabase_sso_provider.get_supabase_jwks (JWKS prod + cache
    TTL 10 menit). Argumen URL lama diabaikan; config SSO yang dipakai.
    """
    import json

    from ops_api.ops.auth.supabase_sso_provider import get_supabase_jwks

    return json.dumps(get_supabase_jwks())


def get_user_from_userinfo(user_info: UserInfoDict, session: Session) -> Optional[User]:
    """
    Get a user from the database using the user information
    :param user_info: REQUIRED - The user information to search for
    :param session: REQUIRED - The database session
    :return: User
    """
    # Eager load only roles to avoid lazy loading other relationships during login
    sub = user_info.get("supabase_sub") or user_info.get("sub")
    user = None
    if sub:
        stmt = select(User).options(selectinload(User.roles)).where(User.supabase_sub == sub)
        user = session.scalars(stmt).one_or_none()
    if user:
        return user
    stmt = select(User).options(selectinload(User.roles)).where(User.oidc_id == user_info.get("sub"))
    user = session.scalars(stmt).one_or_none()
    if user:
        return user
    stmt = select(User).options(selectinload(User.roles)).where(User.email.ilike(user_info.get("email")))  # type: ignore
    user = session.scalars(stmt).one_or_none()
    return user


def update_user_from_userinfo(user: User, user_info: UserInfoDict, session: Session) -> None:
    """
    Update a user in the database using the user information
    :param user: REQUIRED - The user to update
    :param user_info: REQUIRED - The user information to update
    """
    user.first_name = user_info.get("given_name")
    user.last_name = user_info.get("family_name")
    user.hhs_id = user_info.get("hhsid")
    user.email = user_info.get("email")
    supabase_sub = user_info.get("supabase_sub") or user_info.get("sub")
    if supabase_sub and not getattr(user, "supabase_sub", None):
        user.supabase_sub = str(supabase_sub)
    # oidc_id legacy (UUID): hanya ditulis bila sub berformat UUID agar tidak
    # merusak baris untuk subjek SSO non-UUID.
    try:
        candidate = UUID(str(user_info.get("sub"))) if user_info.get("sub") else None
    except (ValueError, AttributeError, TypeError):
        candidate = None
    if candidate is not None:
        user.oidc_id = candidate

    # Avoid expensive user.to_dict() call during login - just log basic info
    logger.debug(f"Updating User: id={user.id}, email={user.email}, supabase_sub={user.supabase_sub}")

    session.add(user)
    session.commit()


def get_user(user_info: UserInfoDict, session: Session) -> User | None:
    """
    Get a user from the database by user data
    :param user_data: REQUIRED - The user data to search for
    :param session: REQUIRED - The database session
    :return: User.
    """
    user = get_user_from_userinfo(user_info, session)
    if user:
        update_user_from_userinfo(user, user_info, session)
        return user


def _get_token_and_user_data_from_internal_auth(
    user_data: UserInfoDict, config, session: Session, extra_claims: dict | None = None
) -> tuple[str, str, User]:
    """
    Generate internal backend-JWT.
    """

    user = get_user(user_data, session)

    # The next two tokens are specific to our backend API, these are used for our API
    # authZ, given a valid login from the prior authN steps above.

    additional_claims = dict(extra_claims or {})
    if user.roles:
        additional_claims["roles"] = [role.name for role in user.roles]
    access_token = create_access_token(
        identity=user,
        expires_delta=config.get("JWT_ACCESS_TOKEN_EXPIRES"),
        additional_claims=additional_claims,
        fresh=True,
    )
    refresh_token = create_refresh_token(
        identity=user,
        expires_delta=config.get("JWT_REFRESH_TOKEN_EXPIRES"),
        additional_claims=additional_claims,
    )
    return access_token, refresh_token, user


def _is_token_expired_unverified(token: str) -> bool:
    """M-05/L-03 (PM RIMS 0002): cek kedaluwarsa TANPA verifikasi tanda tangan.

    PRIVAT — pemanggil WAJIB sudah memvalidasi tanda tangan terlebih dulu
    (mis. endpoint sudah ``jwt_required`` + token berasal dari sesi milik
    server di DB). Memeriksa ``exp`` DAN ``iat`` (tolak iat jauh di masa
    depan, skew +/-60 detik). Token tak-terparse/di luar masa berlaku
    dianggap kedaluwarsa (fail-closed).
    """
    import time

    from authlib.jose import jwt as jose_jwt_decode

    try:
        data = jose_jwt_decode.decode(token, key="")
    except Exception:
        try:
            import base64
            import json as _json

            parts = token.split(".")
            padded = parts[1] + "=" * (-len(parts[1]) % 4)
            data = _json.loads(base64.urlsafe_b64decode(padded))
        except Exception:
            return True
    exp = data.get("exp")
    if exp is None:
        return True
    now = time.time()
    logger.debug(f"Token Expiration: {exp} Current Time: {now}")
    if float(exp) < now:
        return True
    # L-03: tolak token pra-diterbitkan (iat jauh di masa depan).
    iat = data.get("iat")
    if iat is not None and float(iat) - 60 > now:
        return True
    return False


def is_token_expired(token: str, secret_key: str | None = None) -> bool:
    """MIGRATION (PM RIMS 0001): validasi expiry TANPA secret key lama.

    Argumen secret_key lama diabaikan (keypair dimatikan). Wrapper kompatibel
    untuk call-site lama + test; logika реального ada di
    ``_is_token_expired_unverified``. Expiry dibaca dari klaim JWT tanpa
    verifikasi tanda tangan — pemanggil WAJIB sudah memvalidasi tanda tangan
    via supabase_sso_provider.verify_supabase_jwt sebelum memakai ini untuk
    keputusan auth.
    """
    _ = secret_key  # diabaikan by-design (keypair lama dimatikan)
    return _is_token_expired_unverified(token)


def get_latest_user_session(user_id: int, session: Session) -> UserSession | None:
    try:
        # Save current lock_timeout setting to restore it later
        session.execute(text("SELECT current_setting('lock_timeout')")).scalar()

        # Set temporary lock timeout for this operation
        session.execute(text("SET lock_timeout = '5000';"))

        stmt = (
            select(UserSession)
            .where(UserSession.user_id == user_id)
            .order_by(UserSession.created_on.desc())
            .limit(1)
            .with_for_update(nowait=False, skip_locked=False, of=UserSession)
        )
        result = session.execute(stmt).scalar_one_or_none()

        # Reset lock_timeout to default value
        session.execute(text("SET lock_timeout = DEFAULT;"))

        return result
    except OperationalError as e:
        logger.error(f"Database lock error while fetching user session: {e}")
        return None
    except DatabaseError as e:
        logger.error(f"Database error occurred: {e}")
        return None


def get_bearer_token() -> str:
    """
    Get the bearer token from the request headers.
    """
    return request.headers.get("Authorization")


def get_all_active_user_sessions(user_id: int, session: Session) -> list[UserSession]:
    stmt = (
        select(UserSession)
        .where(UserSession.user_id == user_id, UserSession.is_active == True)  # noqa: E712
        .order_by(UserSession.created_on.desc())
    )
    return session.execute(stmt).scalars().all()


def deactivate_all_user_sessions(user_sessions):
    active_sessions = [session for session in user_sessions if session.is_active]
    for session in active_sessions:
        session.is_active = False
        session.last_active_at = datetime.now()
        current_app.db_session.add(session)
    current_app.db_session.commit()


def get_request_ip_address() -> str:
    """
    Get the IP address from the request headers.
    """
    return (
        request.headers.get("X-Forwarded-For").split(",")[0]
        if request.headers.get("X-Forwarded-For")
        else request.remote_addr
    )


def idle_logout(user: User, user_sessions: list[UserSession]) -> dict[str, str]:
    """
    Records an OpsEvent related to the user being logged out due to an idle session and deactivates
    all sessions including the current one.
    Returns a dict of two strings containing a statement about what action was taken
    """
    from ops_api.ops.utils.events import OpsEventHandler

    with OpsEventHandler(OpsEventType.IDLE_LOGOUT) as la:
        identity = get_jwt_identity()
        la.metadata.update({"oidc_id": identity})

    deactivate_all_user_sessions(user_sessions)

    return {"message": f"User: {user.id} logged out for their session not being active within the configured threshold"}
