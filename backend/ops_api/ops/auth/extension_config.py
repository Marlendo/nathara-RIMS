from typing import Optional
from uuid import UUID

from flask import current_app
from flask_jwt_extended import JWTManager
from sqlalchemy import or_, select

from models import User

jwtMgr = JWTManager()


@jwtMgr.user_identity_loader
def user_identity_lookup(user: User) -> str:
    # MIGRATION (PM RIMS 0001): identitas sesi = supabase_sub bila ada,
    # fallback oidc_id lama untuk sesi yang sudah berjalan.
    identity = user.supabase_sub or user.oidc_id
    return str(identity) if identity is not None else None


def _is_uuid(value: str) -> bool:
    try:
        UUID(str(value))
        return True
    except (ValueError, AttributeError, TypeError):
        return False


@jwtMgr.user_lookup_loader
def user_lookup_callback(_jwt_header: dict, jwt_data: dict) -> Optional[User]:
    identity = jwt_data["sub"]
    # supabase_sub (TEXT) selalu aman dicocokkan; oidc_id (UUID) hanya
    # bila identity berformat UUID (hindari error cast postgres + hasil
    # ganda dari baris-baris legacy yang supabase_sub-nya NULL).
    if _is_uuid(identity):
        stmt = select(User).where(
            or_(User.supabase_sub == identity, User.oidc_id == identity)
        )
    else:
        stmt = select(User).where(User.supabase_sub == identity)
    return current_app.db_session.scalars(stmt).one_or_none()
