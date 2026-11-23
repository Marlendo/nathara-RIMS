"""M-02 (PM RIMS 0002): guard kanonis require_rims_access — matriks allow/deny.

Model resource didokumentasikan di decorators.require_rims_access: jalur
resource umum tetap memakai model role-permission lama; guard ini untuk
endpoint sensitif SSO-gated. Test ini mengunci perilaku guard-nya.
"""

from flask_jwt_extended import create_access_token, verify_jwt_in_request

from ops_api.ops.auth.decorators import require_rims_access


def _call_gate(app, token):
    @require_rims_access
    def _gate():
        return {"ok": True}, 200

    with app.test_request_context(
        "/__test_rims_gate__",
        headers={"Authorization": f"Bearer {token}"},
    ):
        verify_jwt_in_request()
        return _gate()


def test_require_rims_access_allows_admin_rims(app, test_user):
    with app.app_context():
        token = create_access_token(
            identity=test_user,
            additional_claims={"sso_role": "admin", "sso_scope": "RIMS"},
        )
    body, status = _call_gate(app, token)
    assert status == 200
    assert body == {"ok": True}


def test_require_rims_access_denies_matrix(app, test_user):
    cases = [
        {"sso_role": "user", "sso_scope": "RIMS"},  # non-admin + RIMS
        {"sso_role": "admin", "sso_scope": "OTHER"},  # admin + scope lain
        {"sso_role": "admin"},  # tanpa scope
        {"sso_scope": "RIMS"},  # tanpa role
        {},  # tanpa klaim SSO sama sekali
    ]
    for extra in cases:
        with app.app_context():
            token = create_access_token(identity=test_user, additional_claims=extra)
        resp = _call_gate(app, token)
        # guard mengembalikan Response 403 via make_response_with_headers
        assert resp.status_code == 403, extra
