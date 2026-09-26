"""Offline tests pinning request shapes to the server's API contract."""

import json
import unittest
from datetime import datetime, timezone
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from secretserver.client import SecretServerClient, SecretServerError

OPEN = "urllib.request.OpenerDirector.open"
SID = "0b6f2c1e-7a4d-4c55-9d8e-1f2a3b4c5d6e"
UID = "11111111-2222-4333-8444-555555555555"


class Response:
    def __init__(self, body: bytes):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, limit=None):
        return self.body


class Recorder:
    """Replays queued responses and records (method, url, json body)."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, request, **_kwargs):
        body = json.loads(request.data) if request.data else None
        self.calls.append((request.get_method(), request.full_url, body))
        payload = self.responses.pop(0) if self.responses else {}
        return Response(payload if isinstance(payload, bytes) else json.dumps(payload).encode())


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.client = SecretServerClient("sk_test", "https://example.test")

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

    def test_jks_and_yubikey_updates_read_merge_write(self):
        current = {"id": SID, "name": "ks", "notes": "n", "tags": ["x"], "container_id": UID, "store_type": "raw"}
        _, calls = self.run_with(lambda: self.client.update_jks_keystore(SID, {"notes": "new"}), current, {})
        self.assertEqual([c[0] for c in calls], ["GET", "PUT"])
        self.assertEqual(calls[1][2], {"container_id": UID, "name": "ks", "notes": "new", "tags": ["x"]})

        yubi = {"id": SID, "name": "yk", "public_id": "cccccccccccb", "client_id": "1", "validation_server": "v",
                "serial_number": "9", "notes": "", "tags": None}
        _, calls = self.run_with(lambda: self.client.update_yubikey(SID, {"name": "renamed"}), yubi, {})
        self.assertEqual(calls[1][2]["name"], "renamed")
        self.assertEqual(calls[1][2]["public_id"], "cccccccccccb")
        self.assertNotIn("api_key", calls[1][2])


if __name__ == "__main__":
    unittest.main()
