"""Offline tests pinning request shapes to the server's API contract."""

import io
import json
import urllib.error
import unittest
from datetime import datetime, timezone
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from secretserver.client import ConflictError, ETagDict, SecretServerClient, SecretServerError

OPEN = "urllib.request.OpenerDirector.open"
SID = "0b6f2c1e-7a4d-4c55-9d8e-1f2a3b4c5d6e"
UID = "11111111-2222-4333-8444-555555555555"


class Response:
    def __init__(self, body: bytes, headers=None):
        self.body = body
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, limit=None):
        return self.body


class Recorder:
    """Replays queued responses and records (method, url, json body).

    Request headers are kept in ``headers`` (one dict per call); a queued
    ``Response`` is returned as is, anything else is JSON-encoded.
    """

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []
        self.headers = []

    def __call__(self, request, **_kwargs):
        body = json.loads(request.data) if request.data else None
        self.calls.append((request.get_method(), request.full_url, body))
        self.headers.append(dict(request.header_items()))
        payload = self.responses.pop(0) if self.responses else {}
        if isinstance(payload, Response):
            return payload
        return Response(payload if isinstance(payload, bytes) else json.dumps(payload).encode())


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.client = SecretServerClient("sk_test", "https://example.test", partial_updates=True)

    def run_with(self, call, *responses):
        recorder = Recorder(*responses)
        with patch(OPEN, side_effect=recorder):
            result = call()
        return result, recorder.calls

    def test_secret_paths_accept_one_to_three_segments_only(self):
        _, calls = self.run_with(lambda: self.client.get_secret("prod/db/12"), {})
        self.assertTrue(calls[0][1].endswith("/api/v1/s/prod/db/12"))
        for bad in ("a/b/c/d", "prod/db/0", "prod/db/13", "prod/db/x"):
            with self.assertRaises(ValueError):
                self.client.get_secret(bad)
            with self.assertRaises(ValueError):
                self.client.secret(bad)

    def test_history_is_a_bare_array_and_type_is_validated(self):
        history, calls = self.run_with(lambda: self.client.get_history("secret", SID), [{"version": 2}])
        self.assertEqual(history, [{"version": 2}])
        self.assertTrue(calls[0][1].endswith(f"/api/v1/secret/{SID}/history"))
        with self.assertRaises(SecretServerError):
            self.run_with(lambda: self.client.get_history("secret", SID), {"versions": []})
        for bad_type in ("secrets", "../admin", "variables"):
            with self.assertRaises(ValueError):
                self.client.get_history(bad_type, SID)
        with self.assertRaises(ValueError):
            self.client.get_history("secret", "not-a-uuid")

    def test_share_requires_exactly_one_recipient(self):
        with self.assertRaises(ValueError):
            self.client.share("secret", SID)
        with self.assertRaises(ValueError):
            self.client.share("secret", SID, user_id=UID, group_id=UID)
        with self.assertRaises(ValueError):
            self.client.share("secret", SID, user_id=UID, permission="write")
        with self.assertRaises(ValueError):
            self.client.share("secret", SID, user_id="bob@example.test")
        expires = datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        _, calls = self.run_with(lambda: self.client.share("password", SID, group_id=UID, permission="manage",
                                                           expires_at=expires))
        self.assertEqual(calls[0][2], {"permission": "manage", "shared_with_group_id": UID,
                                       "expires_at": "2030-01-02T03:04:05Z"})
        self.assertTrue(calls[0][1].endswith(f"/api/v1/password/{SID}/shares"))

    def test_temp_access_duration_bounds(self):
        for bad in (59, 86401, True, "900"):
            with self.assertRaises(ValueError):
                self.client.create_temp_access("secret", SID, bad)
        _, calls = self.run_with(lambda: self.client.create_temp_access("ssh_key", SID, 60))
        self.assertEqual(calls[0][2], {"duration_seconds": 60})

    def test_password_create_and_generate_bodies(self):
        _, calls = self.run_with(lambda: self.client.create_password("p", "u", "v"))
        self.assertEqual(calls[0][2], {"name": "p", "username": "u", "value": "v"})
        record, calls = self.run_with(lambda: self.client.generate_password("gen", 20, use_symbols=False),
                                      {"id": SID, "value": "generated"})
        self.assertEqual(record["value"], "generated")
        self.assertEqual(calls[0][2], {"name": "gen", "length": 20, "use_lowercase": True,
                                       "use_uppercase": True, "use_digits": True, "use_symbols": False})
        for bad in (7, 129):
            with self.assertRaises(ValueError):
                self.client.generate_password("gen", bad)

    def test_api_token_create_and_rotate(self):
        with self.assertRaises(ValueError):
            self.client.create_api_token("t", "svc", "v", "prod")
        _, calls = self.run_with(lambda: self.client.create_api_token("t", "svc", "v", "staging"))
        self.assertEqual(calls[0][2], {"name": "t", "service": "svc", "value": "v", "environment": "staging"})
        _, calls = self.run_with(lambda: self.client.rotate_api_token(SID, "v2"))
        self.assertEqual(calls[0][2], {"value": "v2"})

    def test_gpg_contract(self):
        with self.assertRaises(ValueError):
            self.client.generate_gpg_key("n", "e@example.test", "rsa4096")
        _, calls = self.run_with(lambda: self.client.generate_gpg_key("n", "e@example.test", "ED25519", comment="c"))
        self.assertEqual(calls[0][2], {"name": "n", "email": "e@example.test", "algorithm": "ED25519", "comment": "c"})
        _, calls = self.run_with(lambda: self.client.import_gpg_key("ARMOR", name="n"))
        self.assertEqual(calls[0][2], {"armored_key": "ARMOR", "name": "n"})
        _, calls = self.run_with(lambda: self.client.export_gpg_key("k1", "private"))
        self.assertTrue(calls[0][1].endswith("/gpg-keys/k1/export?format=private"))
        with self.assertRaises(ValueError):
            self.client.export_gpg_key("k1", "armored")

    def test_openssl_contract(self):
        _, calls = self.run_with(lambda: self.client.generate_openssl_key("k", "ecdsa", curve="P-384"))
        self.assertEqual(calls[0][2], {"name": "k", "algorithm": "ecdsa", "curve": "P-384"})
        _, calls = self.run_with(lambda: self.client.generate_openssl_key("k", key_size=2048))
        self.assertEqual(calls[0][2], {"name": "k", "algorithm": "rsa", "key_size": 2048})
        _, calls = self.run_with(lambda: self.client.import_openssl_key("k", "ed25519", "PEM"))
        self.assertEqual(calls[0][2], {"name": "k", "algorithm": "ed25519", "private_key": "PEM"})
        with self.assertRaises(ValueError):
            self.client.generate_openssl_key("k", "dsa")

    def test_totp_list_envelope(self):
        tokens, _ = self.run_with(self.client.list_totp_tokens, {"tokens": [{"id": "t"}], "total": 1})
        self.assertEqual(tokens, [{"id": "t"}])

    def test_certificate_download_returns_raw_bytes(self):
        pem = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
        body, calls = self.run_with(lambda: self.client.download_certificate("c1"), pem)
        self.assertEqual(body, pem)
        self.assertTrue(calls[0][1].endswith("/certificates/c1/download?format=pem"))
        _, calls = self.run_with(lambda: self.client.download_certificate("c1", "p12", "pw&x"), b"\x30\x82")
        self.assertEqual(parse_qs(urlsplit(calls[0][1]).query), {"format": ["p12"], "password": ["pw&x"]})
        with self.assertRaises(ValueError):
            self.client.download_certificate("c1", "pfx")
        with self.assertRaises(ValueError):
            self.client.download_certificate("c1", "der")

    def test_audit_filters_are_encoded_and_empty_values_dropped(self):
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        _, calls = self.run_with(lambda: self.client.get_audit_logs(limit=5, action="secret.update",
                                                                    resource_id=SID, start_date=start))
        self.assertEqual(parse_qs(urlsplit(calls[0][1]).query), {
            "limit": ["5"], "offset": ["0"], "action": ["secret.update"], "resource_id": [SID],
            "start_date": ["2026-01-01T00:00:00Z"],
        })
        with self.assertRaises(ValueError):
            self.client.get_audit_logs(user_id="not-a-uuid")

    def test_audit_export_csv_default_and_json(self):
        text, calls = self.run_with(self.client.export_audit_logs, b"id,action\n1,x\n")
        self.assertEqual(text, "id,action\n1,x\n")
        self.assertTrue(calls[0][1].endswith("/audit/logs/export?format=csv"))
        data, _ = self.run_with(lambda: self.client.export_audit_logs("json"), b'[{"id": 1}]')
        self.assertEqual(data, [{"id": 1}])
        with self.assertRaises(SecretServerError):
            self.run_with(lambda: self.client.export_audit_logs("json"), b"not json")

    def test_export_sends_include_flags(self):
        _, calls = self.run_with(lambda: self.client.export_to_json(include_secrets=True, tags=["a"]))
        self.assertEqual(calls[0][2], {"include_passwords": False, "include_secrets": True,
                                       "include_ssh_keys": False, "include_certificates": False, "tags": ["a"]})
        _, calls = self.run_with(self.client.export_to_keychain)
        self.assertNotIn("items", calls[0][2])

    def test_webhook_create_fields(self):
        _, calls = self.run_with(lambda: self.client.create_webhook("w", "https://hook.example.test", ["secret.update"], "s3"))
        self.assertEqual(calls[0][2], {"name": "w", "url": "https://hook.example.test",
                                       "events": ["secret.update"], "secret": "s3"})

    def test_decode_returns_objects_for_structured_sources(self):
        result, _ = self.run_with(lambda: self.client.decode("{}", "json"), {"result": {"a": 1}})
        self.assertEqual(result, {"a": 1})

    def test_jks_and_yubikey_updates_send_only_supplied_fields(self):
        _, calls = self.run_with(lambda: self.client.update_jks_keystore(SID, {"notes": None, "password": "pw2"}))
        self.assertEqual([c[0] for c in calls], ["PUT"])
        self.assertTrue(calls[0][1].endswith(f"/api/v1/jks-keystores/{SID}"))
        self.assertEqual(calls[0][2], {"notes": None, "password": "pw2"})

        _, calls = self.run_with(lambda: self.client.update_yubikey(SID, {"serial_number": None, "name": "renamed"}))
        self.assertEqual([c[0] for c in calls], ["PUT"])
        self.assertEqual(calls[0][2], {"serial_number": None, "name": "renamed"})
        for bad in (None, [("name", "x")]):
            with self.assertRaises(ValueError):
                self.client.update_yubikey(SID, bad)
            with self.assertRaises(ValueError):
                self.client.update_jks_keystore(SID, bad)

    def test_get_methods_expose_the_etag_header(self):
        tag = '"2026-09-27T10:00:00.123456789Z"'
        for call, path in ((lambda: self.client.get_secret("db"), "/secrets/db"),
                           (lambda: self.client.get_jks_keystore(SID), f"/jks-keystores/{SID}"),
                           (lambda: self.client.get_yubikey(SID), f"/yubikeys/{SID}")):
            record, calls = self.run_with(call, Response(b'{"id": "x", "name": "n"}', {"ETag": tag}))
            self.assertIsInstance(record, ETagDict)
            self.assertEqual(record, {"id": "x", "name": "n"})
            self.assertEqual(record.etag, tag)
            self.assertTrue(calls[0][1].endswith("/api/v1" + path))
        record, _ = self.run_with(lambda: self.client.get_secret("prod/db"), {"name": "db"})
        self.assertIsNone(record.etag)

    def test_updates_send_if_match_and_return_the_new_etag(self):
        tag, new = '"2026-09-27T10:00:00.1Z"', '"2026-09-27T10:00:01.2Z"'
        for call in (lambda: self.client.update_secret("db", "v", if_match=tag),
                     lambda: self.client.update_jks_keystore(SID, {"notes": "n"}, if_match=tag),
                     lambda: self.client.update_yubikey(SID, {"notes": "n"}, if_match=tag)):
            recorder = Recorder(Response(b'{"message": "updated"}', {"ETag": new}))
            with patch(OPEN, side_effect=recorder):
                result = call()
            self.assertEqual(recorder.headers[0]["If-match"], tag)
            self.assertEqual(result.etag, new)
        recorder = Recorder({})
        with patch(OPEN, side_effect=recorder):
            self.client.update_secret("db", "v")
            self.client.update_secret("db", "v", if_match=7, expected_version=7)
        self.assertNotIn("If-match", recorder.headers[0])
        self.assertEqual(recorder.headers[1]["If-match"], "7")
        self.assertEqual(recorder.calls[1][2], {"data": {"value": "v"}, "expected_version": 7})

    def test_if_match_rejects_header_injection_and_bad_types(self):
        with patch(OPEN) as opened:
            for bad in ("", "  ", '"x"\r\nX-Evil: 1', "a\nb", "a\x00b", True, 1.5):
                with self.assertRaises(ValueError):
                    self.client.update_secret("db", "v", if_match=bad)
            for bad in (7, '"x"\r\nX-Evil: 1'):
                with self.assertRaises(ValueError):
                    self.client.update_jks_keystore(SID, {"notes": "n"}, if_match=bad)
                with self.assertRaises(ValueError):
                    self.client.update_yubikey(SID, {"notes": "n"}, if_match=bad)
        opened.assert_not_called()

    def test_conflict_raises_conflict_error_with_current_etag(self):
        current = '"2026-09-27T10:00:05.5Z"'
        key = "sk_conflict_key_do_not_leak"
        client = SecretServerClient(key, "https://example.test", partial_updates=True)
        for call in (lambda: client.update_secret("db", "v", if_match='"stale"'),
                     lambda: client.update_jks_keystore(SID, {"notes": "n"}, if_match='"stale"'),
                     lambda: client.update_yubikey(SID, {"notes": "n"}, if_match='"stale"')):
            error = urllib.error.HTTPError("https://example.test", 409, "Conflict", {"ETag": current},
                                           io.BytesIO(b'{"error": "body-must-not-leak"}'))
            with patch(OPEN, side_effect=error):
                with self.assertRaises(ConflictError) as ctx:
                    call()
            self.assertIsInstance(ctx.exception, SecretServerError)
            self.assertEqual((ctx.exception.status_code, ctx.exception.etag), (409, current))
            self.assertNotIn(key, str(ctx.exception))
            self.assertNotIn("body-must-not-leak", str(ctx.exception))
        error = urllib.error.HTTPError("https://example.test", 409, "Conflict", None, io.BytesIO(b""))
        with patch(OPEN, side_effect=error):
            with self.assertRaises(ConflictError) as ctx:
                client.update_secret("db", "v")
        self.assertIsNone(ctx.exception.etag)



class PartialUpdateGateTests(unittest.TestCase):
    """Servers before 3075630 treat these PUTs as a full replace and ignore
    If-Match, so partial bodies need an explicit opt-in or a server ETag."""

    ETAGS = ('"2026-09-27T10:00:00.1Z"', 'W/"2026-09-27T10:00:00.1Z"', '""')
    NOT_ETAGS = ("*", "7", "2026-09-27T10:00:00.1Z", '"unterminated', 'W/unquoted', '"a" "b"', 'w/"lower"')

    def client(self, **kwargs):
        return SecretServerClient("sk_gate_key_do_not_leak", "https://example.test", **kwargs)

    @staticmethod
    def updates(client, **kwargs):
        return (lambda: client.update_secret("db", "v", **kwargs),
                lambda: client.update_jks_keystore(SID, {"notes": "n"}, **kwargs),
                lambda: client.update_yubikey(SID, {"notes": "n"}, **kwargs))

    def assert_refused(self, call):
        with patch(OPEN) as opened:
            with self.assertRaises(SecretServerError) as ctx:
                call()
        opened.assert_not_called()
        message = str(ctx.exception)
        self.assertIn("partial updates require secretserver.io 3075630 or newer", message)
        self.assertIn("pass an ETag from get() as if_match or enable partial_updates", message)
        self.assertNotIn("sk_gate_key_do_not_leak", message)

    def assert_sent(self, call, if_match=None):
        recorder = Recorder(Response(b'{"message": "updated"}'))
        with patch(OPEN, side_effect=recorder):
            call()
        self.assertEqual([c[0] for c in recorder.calls], ["PUT"])
        self.assertEqual(recorder.headers[0].get("If-match"), if_match)

    def test_refused_without_opt_in_or_etag(self):
        with patch.dict("os.environ", {}, clear=True):
            client = self.client()
        self.assertFalse(client.partial_updates)
        for call in self.updates(client):
            self.assert_refused(call)

    def test_refused_with_version_star_or_unquoted_if_match(self):
        with patch.dict("os.environ", {}, clear=True):
            client = self.client()
        for call in (lambda: client.update_secret("db", "v", if_match=7),
                     lambda: client.update_secret("db", "v", expected_version=7),
                     lambda: client.update_secret("db", "v", if_match=7, expected_version=7)):
            self.assert_refused(call)
        for bad in self.NOT_ETAGS:
            with self.subTest(if_match=bad):
                for call in self.updates(client, if_match=bad):
                    self.assert_refused(call)

    def test_allowed_with_quoted_or_weak_etag(self):
        with patch.dict("os.environ", {}, clear=True):
            client = self.client()
        for tag in self.ETAGS:
            with self.subTest(if_match=tag):
                for call in self.updates(client, if_match=tag):
                    self.assert_sent(call, tag)

    def test_allowed_with_constructor_opt_in(self):
        with patch.dict("os.environ", {}, clear=True):
            client = self.client(partial_updates=True)
        for call in self.updates(client):
            self.assert_sent(call)
        self.assert_sent(lambda: client.update_secret("db", "v", if_match=7), "7")

    def test_env_opt_in(self):
        with patch.dict("os.environ", {"SS_PARTIAL_UPDATES": "1"}, clear=True):
            client = self.client()
        self.assertTrue(client.partial_updates)
        for call in self.updates(client):
            self.assert_sent(call)
        for value in ("0", "true", "yes", ""):
            with patch.dict("os.environ", {"SS_PARTIAL_UPDATES": value}, clear=True):
                client = self.client()
            self.assertFalse(client.partial_updates, value)
            self.assert_refused(self.updates(client)[0])
        with patch.dict("os.environ", {"SS_PARTIAL_UPDATES": "1"}, clear=True):
            client = self.client(partial_updates=False)
        self.assert_refused(self.updates(client)[0])


if __name__ == "__main__":
    unittest.main()
