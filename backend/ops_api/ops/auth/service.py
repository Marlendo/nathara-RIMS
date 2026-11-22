from datetime import datetime
from typing import Any, Optional

from flask import current_app
from flask_jwt_extended import create_access_token, current_user, get_jwt_identity
from sqlalchemy import select
from sqlalchemy.orm import Session

from models import Role, User, UserSession
from models.events import OpsEventType
from models.users import UserStatus
from ops_api.ops.auth.auth_types import UserInfoDict
from ops_api.ops.auth.exceptions import AuthenticationError, InvalidUserSessionError
from ops_api.ops.auth.supabase_sso_provider import (
    extract_sso_identity,
    is_rims_admin,
    verify_supabase_jwt,
)
from ops_api.ops.auth.utils import (
    _get_token_and_user_data_from_internal_auth,
    deactivate_all_user_sessions,
    get_all_active_user_sessions,
    get_latest_user_session,
    get_request_ip_address,
    is_token_expired,
)
from ops_api.ops.utils.events import OpsEventHandler


def _provision_sso_user(identity: dict, session: Session) -> User:
    """Auto-provision ops_user dari identitas SSO.

    Cari supabase_sub -> link email (ilike) -> buat baru default
    status=INACTIVE (aktivasi manual oleh admin, kecuali seed admin awal
    dari human). Default deny admin otomatis.
    """
    from sqlalchemy.orm import selectinload

    sub = identity.get("sub")
    email = identity.get("email")
    user = None
    if sub:
        stmt = (
            select(User)
            .options(selectinload(User.roles))
            .where(User.supabase_sub == str(sub))
        )
        user = session.scalars(stmt).one_or_none()
    if user is None and email:
        stmt = (
            select(User)
            .options(selectinload(User.roles))
            .where(User.email.ilike(email))
        )
        user = session.scalars(stmt).one_or_none()
        if user is not None:
            user.supabase_sub = str(sub) if sub else user.supabase_sub
    if user is None:
        user = User(
            supabase_sub=str(sub) if sub else None,
            email=email,
            first_name=identity.get("given_name"),
            last_name=identity.get("family_name"),
            status=UserStatus.INACTIVE,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        return user
    user.first_name = identity.get("given_name") or user.first_name
    user.last_name = identity.get("family_name") or user.last_name
    if email:
        user.email = email
    session.add(user)
    session.commit()
    return user


def login_sso(supabase_jwt: str) -> dict[str, Any]:
    """Tukar JWT Supabase prod -> sesi aplikasi internal.

    Validasi RS256 via JWKS -> mapping role/scope -> auto-provision ->
    sesi app baru. Audit tiap login via OpsEventHandler.
    """
    claims = verify_supabase_jwt(supabase_jwt)
    identity = extract_sso_identity(claims)

    with OpsEventHandler(OpsEventType.LOGIN_ATTEMPT) as la:
        if not is_rims_admin(identity):
            la.metadata.update(
                {
                    "sso_sub": identity.get("sub"),
                    "sso_email": identity.get("email"),
                    "sso_role": identity.get("role"),
                    "sso_scope": identity.get("scope"),
                    "result": "DENIED_403",
                }
            )
            raise AuthenticationError(
                "Akses ditolak: akun SSO tidak memiliki role admin + scope RIMS. Hubungi admin."
            )

        user = _provision_sso_user(identity, current_app.db_session)
        if user.status == UserStatus.LOCKED:
            la.metadata.update({"user_id": user.id, "result": "LOCKED"})
            raise AuthenticationError("Akun dikunci. Hubungi admin.")
        if user.status == UserStatus.INACTIVE:
            la.metadata.update({"user_id": user.id, "result": "INACTIVE"})
            raise AuthenticationError("Akun belum diaktifkan. Hubungi admin RIMS.")

        user_data: UserInfoDict = {
            "sub": str(identity.get("sub")),
            "email": identity.get("email"),
            "supabase_sub": str(identity.get("sub")),
            "given_name": identity.get("given_name"),
            "family_name": identity.get("family_name"),
        }
        (
            access_token,
            refresh_token,
            user,
        ) = _get_token_and_user_data_from_internal_auth(
            user_data,
            current_app.config,
            current_app.db_session,
            extra_claims={"sso_role": identity.get("role"), "sso_scope": identity.get("scope")},
        )

        user_session = _get_or_create_user_session(user, access_token, refresh_token, get_request_ip_address())

        la.metadata.update(
            {
                "user": {
                    "id": user.id,
                    "supabase_sub": user.supabase_sub,
                    "email": user.email,
                    "full_name": user.full_name,
                },
                "access_token": user_session.access_token,
                "session_id": user_session.id,
                "result": "OK",
            }
        )

    return {
        "access_token": user_session.access_token,
        "refresh_token": user_session.refresh_token,
        "user": user,
    }


def sso_session_info() -> dict[str, Any]:
    """Info sesi aplikasi berjalan untuk GET /auth/sso/session."""
    return {
        "user_id": current_user.id,
        "email": current_user.email,
        "status": current_user.status.name if current_user.status else None,
        "supabase_sub": getattr(current_user, "supabase_sub", None),
        "roles": [r.name for r in current_user.roles] if current_user.roles else [],
    }


def login(code: str, provider: str) -> dict[str, Any]:
    """MIGRATION (PM RIMS 0001): endpoint login lama DIMATIKAN (410)."""
    raise AuthenticationError(
        "Login lama dimatikan (PM RIMS 0001). Gunakan POST /auth/sso/callback dengan JWT SSO Nathara."
    )


def logout() -> dict[str, str]:
    with OpsEventHandler(OpsEventType.LOGOUT) as la:
        identity = get_jwt_identity()
        la.metadata.update({"oidc_id": identity})
        # Sesi IdP (refresh/revoke) = login ulang di FE; backend nonaktifkan sesi app.

        user_sessions = get_all_active_user_sessions(current_user.id, current_app.db_session)
        deactivate_all_user_sessions(user_sessions)

        return {"message": f"User: {current_user.email} Logged out"}


def refresh() -> dict[str, str]:
    # Get the latest user session first
    latest_user_session = get_latest_user_session(current_user.id, current_app.db_session)

    if not latest_user_session or not latest_user_session.is_active:
        raise InvalidUserSessionError("User session is not active.")

    # Check if the current access token is valid before creating a new one
    if not is_token_expired(latest_user_session.access_token):
        return {"access_token": latest_user_session.access_token}

    # Only create a new token if the existing one is expired
    additional_claims = {"roles": []}
    if current_user.roles:
        additional_claims["roles"] = [role.name for role in current_user.roles]

    access_token = create_access_token(
        identity=current_user,
        expires_delta=current_app.config.get("JWT_ACCESS_TOKEN_EXPIRES"),
        additional_claims=additional_claims,
        fresh=False,
    )

    # Update session with new token
    latest_user_session.access_token = access_token
    latest_user_session.last_active_at = datetime.now()
    current_app.db_session.add(latest_user_session)
    current_app.db_session.commit()

    return {"access_token": access_token}


def _get_or_create_user_session(
    user: User,
    access_token: Optional[str] = None,
    refresh_token: Optional[str] = None,
    ip_address: Optional[str] = "127.0.0.1",
) -> UserSession:
    stmt = (
        select(UserSession)
        .where(UserSession.user_id == user.id)
        .where(UserSession.is_active == True)  # noqa: E712
        .order_by(UserSession.created_on.desc())
    )
    user_sessions = current_app.db_session.execute(stmt).scalars().all()

    # set all other sessions to inactive before creating a new one
    deactivate_all_user_sessions(user_sessions)

    user_session = UserSession(
        user_id=user.id,
        is_active=True,
        ip_address=ip_address,
        access_token=access_token,
        refresh_token=refresh_token,
        last_active_at=datetime.now(),
        created_by=user.id,
        updated_by=user.id,
    )
    current_app.db_session.add(user_session)
    current_app.db_session.commit()

    return user_session


def get_roles(session: Session, **kwargs) -> list[Role]:
    """
    Get all roles that match the given criteria.

    :param session: The database session.
    :param **kwargs: The criteria to filter the roles by.
    :return: The roles that match the criteria.

    """
    stmt = select(Role)

    for key, value in kwargs.items():
        stmt = stmt.where(getattr(Role, key) == value)

    stmt = stmt.order_by(Role.id)

    roles = session.execute(stmt).scalars().all()

    return list(roles)
