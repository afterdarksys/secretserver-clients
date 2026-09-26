"""Live contract test; run through scripts/live-integration.sh."""

import os
from datetime import datetime, timedelta, timezone

from secretserver import AuthError, SecretServerClient

URL, KEY, CONTAINER = os.environ["SS_LIVE_URL"], os.environ["SS_LIVE_KEY"], os.environ["SS_LIVE_CONTAINER"]
c = SecretServerClient(KEY, URL)
cleanup = []

# Flows deliberately not exercised live; their request shapes are pinned by
# tests/test_contract.py instead. Printed so the harness marks the run honestly.
for flow, reason in (
    ("gpg", "server build returns HTTP 500 'failed to store key metadata' on generate/import"),
    ("totp", "server build returns HTTP 500 'failed to store secret key' on create"),
    ("jks", "server build returns HTTP 500 'failed to store keystore' on create"),
    ("yubikey", "needs a real YubiKey and the external Yubico validation service"),
    ("certificate download", "enroll/download needs an ACME issuer, unavailable locally"),
    ("share", "needs a second user or group UUID the harness does not provision"),
    ("webhook create", "needs a reachable external webhook receiver"),
):
    print(f"SKIP {flow}: {reason}")

try:
    # Secrets, path access and read-merge-write update.
    c.create_secret("python-live", "first", description="live description", container_id=CONTAINER)
    cleanup.append(lambda: c.delete_secret("python-live"))
    assert any(s["name"] == "python-live" for s in c.list_secrets())
    assert c.secret("prod/python-live") == "first"
    c.update_secret("python-live", "second")
    assert c.secret("python-live") == "second"
    assert c.secret("prod/python-live") == "second", "container lost on update"
    assert c.secret("prod/python-live/2") == "first"
    record = c.get_secret("python-live")
    assert record["container_id"] == CONTAINER and record["description"] == "live description"

    # The server records history rows only for some write paths; the contract
    # checked here is that the endpoint answers with a bare array.
    history = c.get_history("secret", record["id"])
    assert isinstance(history, list), history

    grant = c.create_temp_access("secret", record["id"], 60)
    assert grant.get("token")

    # Wrong key fails closed without echoing the key.
    wrong = "sk_wrong_python_live_key"
    try:
        SecretServerClient(wrong, URL).list_secrets()
        raise AssertionError("wrong API key was accepted")
    except AuthError as exc:
        assert exc.status_code == 401 and wrong not in str(exc) and KEY not in str(exc)

    # Variables.
    c.assign_variable("PYTHON_LIVE", "secret", record["id"], "value")
    cleanup.append(lambda: c.delete_variable("PYTHON_LIVE"))
    assert c.render("x=%%PYTHON_LIVE%%") == "x=second"
    assert c.resolve_document({"password": "%%PYTHON_LIVE%%", "count": 2}) == {"password": "second", "count": 2}
    assert c.get_variable("PYTHON_LIVE")["secret_id"] == record["id"]
    assert any(v["name"] == "PYTHON_LIVE" for v in c.list_variables())

    # Passwords.
    created = c.create_password("python-live-pw", "svc", "Correct-Horse-9")
    cleanup.append(lambda: c._delete(f"/passwords/{created['id']}"))
    generated = c.generate_password("python-live-gen", length=24, use_symbols=False)
    cleanup.append(lambda: c._delete(f"/passwords/{generated['id']}"))
    assert len(generated["value"]) == 24 and generated["value"].isalnum()

    # API tokens.
    token = c.create_api_token("python-live-token", "example", "tok_first_value", "development")
    cleanup.append(lambda: c._delete(f"/api-tokens/{token['id']}"))
    c.rotate_api_token(token["id"], "tok_second_value")

    # OpenSSL.
    ossl = c.generate_openssl_key("python-live-ossl", "ecdsa", curve="P-256")
    cleanup.append(lambda: c.delete_openssl_key(ossl["id"]))

    # Export with include flags, audit query and export.
    # This server build skips items whose Vault read fails and can return
    # "items": null, so only the envelope and type filtering are asserted.
    for flag, kind in (("include_secrets", "secret"), ("include_passwords", "password")):
        export = c.export_to_json(**{flag: True})
        assert export["format"] == "json" and export["count"] == len(export["items"] or [])
        assert all(item["type"] == kind for item in export["items"] or [])
    logs = c.get_audit_logs(limit=5, action="secret.update")
    assert isinstance(logs, dict)
    since = datetime.now(timezone.utc) - timedelta(hours=1)
    assert c.get_audit_logs(start_date=since, end_date=datetime.now(timezone.utc) + timedelta(hours=1))["logs"]
    assert "secret.update" in c.export_audit_logs(action="secret.update")
    assert isinstance(c.export_audit_logs("json", action="secret.update"), (list, dict))

    assert c.decode("aGVsbG8=") == "hello"
finally:
    for undo in reversed(cleanup):
        undo()

print("Python live contract PASS")
