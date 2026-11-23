from types import TracebackType
from typing import Any, Optional, Type

from flask import current_app, request
from flask_jwt_extended import current_user
from loguru import logger
from sqlalchemy.orm import Session
from werkzeug.exceptions import UnsupportedMediaType

from models.events import OpsEvent, OpsEventStatus, OpsEventType
from ops_api.ops.auth.utils import get_request_ip_address

# H-03 (PM RIMS 0002): kunci yang TIDAK BOLEH masuk DB event/log — nilai
# diganti placeholder sebelum persist/cetak.
REDACTED_KEYS = frozenset(
    {
        "authorization",
        "cookie",
        "supabase_jwt",
        "access_token",
        "refresh_token",
        "code",
        "password",
    }
)
REDACTED_VALUE = "***REDACTED***"


def redact_event_metadata(value: Any, _depth: int = 0) -> Any:
    """Samarkan material token/kredensial dari struktur metadata event.

    Menangani dict (case-insensitive untuk header), list/tuple, dan string.
    Kedalaman dibatasi agar aman untuk struktur request yang besar.
    """
    if _depth > 6:
        return REDACTED_VALUE if isinstance(value, str) else value
    if isinstance(value, dict):
        return {
            k: (REDACTED_VALUE if str(k).lower() in REDACTED_KEYS else redact_event_metadata(v, _depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_event_metadata(v, _depth + 1) for v in value]
    return value


def token_fingerprint(token: Optional[str]) -> Optional[str]:
    """Fingerprint non-reversibel (8 char sha256) untuk audit tanpa token mentah."""
    import hashlib

    if not token:
        return None
    return hashlib.sha256(str(token).encode()).hexdigest()[:8]


class OpsEventHandler:
    def __init__(self, event_type: OpsEventType):
        self.metadata = {}
        self.event_type = event_type

    def __enter__(self):
        # H-03: redact token/kredensial SEBELUM masuk metadata (DB + log).
        raw_values = request.values.to_dict(flat=False) if hasattr(request.values, "to_dict") else dict(request.values)
        self.metadata.update(
            {
                "request.values": redact_event_metadata(raw_values),
                "request.headers": redact_event_metadata({k: v for k, v in request.headers}),
                "request.remote_addr": get_request_ip_address(),
                "request.remote_user": request.remote_user,
            }
        )

        try:
            self.metadata["request.json"] = redact_event_metadata(request.json)
        except UnsupportedMediaType:
            if request.data:
                self.metadata["request.data"] = redact_event_metadata(request.data.decode("utf-8", "replace")[:2000])

        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        if exc_val or not current_app.db_session.is_active:
            event_status = OpsEventStatus.FAILED
            self.metadata.update({"error_message": f"{exc_val}", "error_type": f"{exc_type}"})
        else:
            event_status = OpsEventStatus.SUCCESS

        current_user_id = None
        try:
            current_user_id = current_user.id if current_user else None
        except Exception as e:
            print(e)

        event = OpsEvent(
            event_type=self.event_type,
            event_status=event_status,
            event_details=self.metadata,
            created_by=current_user_id,
        )

        with Session(current_app.engine) as session:
            session.add(event)
            session.commit()
            logger.info(f"EVENT: {event.to_dict()}")

        if isinstance(exc_val, Exception):
            logger.error(f"EVENT ({exc_type}): {exc_val}")

        if not current_app.db_session.is_active:
            logger.error("Session is not active. It has likely been rolled back.")

        if hasattr(request, "message_bus"):
            logger.info(f"Publishing event {self.event_type.name}")
            request.message_bus.publish(self.event_type, event)
