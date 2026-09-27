"""Live contract test; run through scripts/live-integration.sh."""

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit


def live_env():
    """Return the harness settings or exit before any client exists.

    Only the SS_LIVE_* variables are read, never SS_API_URL/SS_API_KEY or the
    production default, and the URL must point at a loopback host.
    """
    url = os.environ.get("SS_LIVE_URL", "")
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
    except ValueError:
        parts, host = None, ""
    if not url or parts is None or "@" in parts.netloc or host not in ("localhost", "127.0.0.1", "::1"):
        sys.exit("live.py: refusing to run: SS_LIVE_URL must be set to a loopback URL (localhost, 127.0.0.1 or ::1)")
    missing = [name for name in ("SS_LIVE_KEY", "SS_LIVE_WRITE_KEY", "SS_LIVE_CONTAINER") if not os.environ.get(name)]
    if missing:
        sys.exit("live.py: refusing to run: " + ", ".join(missing) + " must be set")
    return url, os.environ["SS_LIVE_KEY"], os.environ["SS_LIVE_CONTAINER"], os.environ["SS_LIVE_WRITE_KEY"]


URL, KEY, CONTAINER, WRITE_KEY = live_env()

from secretserver import AuthError, ConflictError, PermissionError, SecretServerClient, SecretServerError  # noqa: E402

# The disposable server is 3075630 or newer, so the main clients opt in to
# partial updates; ``plain`` does not and must present an ETag instead.
c = SecretServerClient(KEY, URL, partial_updates=True)
writer = SecretServerClient(WRITE_KEY, URL, partial_updates=True)
plain = SecretServerClient(KEY, URL, partial_updates=False)
cleanup = []

# Flows that need something outside the disposable stack. Printed so the
# harness marks the run honestly; request shapes are pinned by
# tests/test_contract.py instead.
for flow, reason in (
    ("yubikey otp validation", "validates against the external Yubico API (yubikeys.go ValidateYubikeyOTP)"),
    ("share", "recipient must be an active user or group of the tenant (sharing.go); the harness provisions none"),
    ("webhook create", "netsafe.ValidateOutboundURL rejects loopback/private receivers; needs a public one"),
):
    print(f"SKIP {flow}: {reason}")


def secret_reads(name):
    logs = c.get_audit_logs(limit=1000, action="secret.read", resource=name)["logs"] or []
    return len(logs)


def expect_conflict(call):
    try:
        call()
    except ConflictError as exc:
        assert exc.status_code == 409 and exc.etag, exc
        assert KEY not in str(exc)
        return exc.etag
    raise AssertionError("stale precondition was accepted")


try:
    # Secrets and path access.
    c.create_secret("python-live", "first", description="live description", container_id=CONTAINER)
    cleanup.append(lambda: c.delete_secret("python-live"))
    c.update_secret("python-live", tags=["live"])
    assert any(s["name"] == "python-live" for s in c.list_secrets())
    assert c.secret("prod/python-live") == "first"

    # Partial update with a secrets:write-only key: no read permission is
    # needed and no secret.read audit event is produced.
    reads_before = secret_reads("python-live")
    updated = writer.update_secret("python-live", "second")
    assert updated.etag and updated["name"] == "python-live"
    assert secret_reads("python-live") == reads_before, "update produced a secret.read audit event"
    try:
        writer.secret("python-live")
        raise AssertionError("secrets:write key could read a secret")
    except PermissionError as exc:
        assert exc.status_code == 403 and WRITE_KEY not in str(exc)
    assert c.secret("python-live") == "second"
    assert secret_reads("python-live") > reads_before, "audit filter does not see secret.read events"
    assert c.secret("prod/python-live") == "second", "container lost on update"
    assert c.secret("prod/python-live/2") == "first"
    record = c.get_secret("python-live")
    assert (record["container_id"], record["description"], record["tags"]) == (CONTAINER, "live description", ["live"])

    # Explicit null clears; omitted fields are preserved.
    c.update_secret("python-live", description=None)
    record = c.get_secret("python-live")
    assert not record.get("description"), record.get("description")
    assert (record["container_id"], record["tags"]) == (CONTAINER, ["live"])
    assert c.secret("prod/python-live") == "second"

    # ETag round trip: the current ETag succeeds, the stale one conflicts.
    assert record.etag
    fresh = c.update_secret("python-live", "third", if_match=record.etag)
    assert fresh.etag and fresh.etag != record.etag
    assert expect_conflict(lambda: c.update_secret("python-live", "fourth", if_match=record.etag)) == fresh.etag
    expect_conflict(lambda: c.update_secret("python-live", "fourth", expected_version=record["version"]))
    assert c.secret("python-live") == "third"

    # Without the opt-in a partial update is refused unless it carries an
    # ETag from get(); with one it goes through and keeps the container.
    try:
        plain.update_secret("python-live", "unsent")
        raise AssertionError("partial update without opt-in or ETag was sent")
    except SecretServerError as exc:
        assert "3075630" in str(exc) and KEY not in str(exc)
    current = plain.get_secret("python-live")
    via_etag = plain.update_secret("python-live", "third", description="via etag", if_match=current.etag)
    assert via_etag.etag and via_etag.etag != current.etag
    assert c.secret("prod/python-live") == "third"
    assert c.get_secret("python-live")["description"] == "via etag"

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
    assert c.render("x=%%PYTHON_LIVE%%") == "x=third"
    assert c.resolve_document({"password": "%%PYTHON_LIVE%%", "count": 2}) == {"password": "third", "count": 2}
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

    # GPG: generate, list, export both halves, delete.
    gpg = c.generate_gpg_key("python-live-gpg", "gpg@example.test", "ED25519", comment="live")
    cleanup.append(lambda: c.delete_gpg_key(gpg["id"]))
    assert any(k["id"] == gpg["id"] for k in c.list_gpg_keys())
    public = c.export_gpg_key(gpg["id"])
    assert public["format"] == "public" and "BEGIN PGP PUBLIC KEY BLOCK" in public["key"]
    assert public["fingerprint"] == gpg["fingerprint"]
    private = c.export_gpg_key(gpg["id"], "private")
    assert "BEGIN PGP PRIVATE KEY BLOCK" in private["key"]

    # TOTP: create, list, code, export, delete.
    totp = c.create_totp_token("python-live-totp", "Example", "live@example.test", "JBSWY3DPEHPK3PXP")
    cleanup.append(lambda: c.delete_totp_token(totp["id"]))
    assert any(t["id"] == totp["id"] for t in c.list_totp_tokens())
    code = c.generate_totp_code(totp["id"])
    assert len(code["code"]) == 6 and code["code"].isdigit()
    uri = c.export_totp_to_uri(totp["id"])
    assert set(uri) == {"uri"} and uri["uri"].startswith("otpauth://totp/")

    # Certificates: enroll, read, raw PEM download. Enrollment generates an
    # RSA-4096 key server-side, which can outlast the default 10 s timeout.
    cert = SecretServerClient(KEY, URL, timeout=120).enroll_certificate("python-live-cert", "python-live.example.test", ["www.python-live.example.test"])
    cleanup.append(lambda: c.revoke_certificate(cert["id"]))
    assert c.get_certificate(cert["id"])["common_name"] == "python-live.example.test"
    pem = c.download_certificate(cert["id"])
    assert isinstance(pem, bytes) and pem.startswith(b"-----BEGIN CERTIFICATE-----")

    # JKS: create, partial update (null clears notes, password rotation),
    # ETag conflict, export, delete.
    jks = c.create_jks_keystore("python-live-jks", password="changeit", notes="live notes",
                                tags=["live"], container_id=CONTAINER)
    cleanup.append(lambda: c.delete_jks_keystore(jks["id"]))
    current = c.get_jks_keystore(jks["id"])
    assert current.etag and current["notes"] == "live notes"
    cleared = c.update_jks_keystore(jks["id"], {"notes": None}, if_match=current.etag)
    assert cleared.etag and cleared.etag != current.etag
    after = c.get_jks_keystore(jks["id"])
    assert not after.get("notes") and after["tags"] == ["live"] and after["container_id"] == CONTAINER
    assert after["name"] == "python-live-jks"
    assert expect_conflict(lambda: c.update_jks_keystore(jks["id"], {"notes": "x"}, if_match=current.etag)) == after.etag
    c.update_jks_keystore(jks["id"], {"password": "rotated-pass"})
    exported = c.export_jks_keystore(jks["id"])
    assert exported.get("jks"), sorted(exported)
    assert c.get_jks_keystore(jks["id"])["tags"] == ["live"]

    # YubiKey: create, partial update (null clears serial_number), delete.
    yk = c.create_yubikey("python-live-yk", "cccccccccccb", "12345", "c2VjcmV0LWtleQ==",
                          serial_number="9876543", notes="yk notes")
    cleanup.append(lambda: c.delete_yubikey(yk["id"]))
    current = c.get_yubikey(yk["id"])
    assert current.etag and current["serial_number"] == "9876543"
    c.update_yubikey(yk["id"], {"serial_number": None}, if_match=current.etag)
    after = c.get_yubikey(yk["id"])
    assert not after.get("serial_number") and after["notes"] == "yk notes" and after["public_id"] == "cccccccccccb"
    expect_conflict(lambda: c.update_yubikey(yk["id"], {"notes": "x"}, if_match=current.etag))

    # Export with include flags carries secret contents; audit query and export.
    export = c.export_to_json(include_secrets=True)
    assert export["format"] == "json" and export["count"] == len(export["items"])
    assert all(item["type"] == "secret" for item in export["items"])
    mine = [item for item in export["items"] if item["name"] == "python-live"]
    assert mine and json.loads(mine[0]["value"]) == {"value": "third"}, "secret contents missing from export"
    export = c.export_to_json(include_passwords=True)
    assert any(item["name"] == "python-live-pw" for item in export["items"])
    assert all(item["type"] == "password" for item in export["items"])
    logs = c.get_audit_logs(limit=5, action="secret.update")
    assert logs["logs"], logs
    since = datetime.now(timezone.utc) - timedelta(hours=1)
    assert c.get_audit_logs(start_date=since, end_date=datetime.now(timezone.utc) + timedelta(hours=1))["logs"]
    assert "secret.update" in c.export_audit_logs(action="secret.update")
    assert isinstance(c.export_audit_logs("json", action="secret.update"), (list, dict))

    assert c.decode("aGVsbG8=") == "hello"
finally:
    for undo in reversed(cleanup):
        undo()

print("Python live contract PASS")
