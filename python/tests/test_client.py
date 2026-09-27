import json
import io
import urllib.error
import unittest
from unittest.mock import patch

from secretserver.client import SecretServerClient


class FakeResponse:
    def __init__(self, payload=None):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, limit=None):
        if self.payload is None:
            return b""
        return json.dumps(self.payload).encode()


class ClientContractTests(unittest.TestCase):
    def test_normalizes_api_prefix_and_secret_list_envelope(self):
        client = SecretServerClient("sk_test", "https://example.test/api/v1")
        with patch("urllib.request.OpenerDirector.open", return_value=FakeResponse({
            "secrets": [{"id": "1", "name": "db"}], "total": 1
        })) as urlopen:
            self.assertEqual(client.list_secrets()[0]["name"], "db")
        self.assertEqual(urlopen.call_args.args[0].full_url, "https://example.test/api/v1/secrets")

    def test_update_sends_one_put_with_only_supplied_fields(self):
        client = SecretServerClient("sk_test", "https://example.test")
        calls = []

        def respond(request, **_kwargs):
            calls.append((request.get_method(), request.full_url, json.loads(request.data) if request.data else None))
            return FakeResponse({})

        with patch("urllib.request.OpenerDirector.open", side_effect=respond):
            client.update_secret("db", "new")
            client.update_secret("db", description="changed", tags=[])
            client.enroll_certificate("wildcard", "example.test", ["www.example.test"])

        self.assertEqual([c[0] for c in calls], ["PUT", "PUT", "POST"])
        self.assertTrue(calls[0][1].endswith("/api/v1/secrets/db"))
        self.assertEqual(calls[0][2], {"data": {"value": "new"}})
        self.assertEqual(calls[1][2], {"description": "changed", "tags": []})
        self.assertEqual(calls[2][2]["dns_names"], ["www.example.test"])
        self.assertNotIn("sans", calls[2][2])

    def test_update_distinguishes_omitted_from_cleared_metadata(self):
        client = SecretServerClient("sk_test", "https://example.test")
        puts = []

        def respond(request, **_kwargs):
            puts.append(request.data.decode())
            return FakeResponse({})

        with patch("urllib.request.OpenerDirector.open", side_effect=respond):
            client.update_secret("db", "kept")
            client.update_secret("db", description=None, tags=None, container_id=None)
            client.update_secret("db", container_id="6f0c5a4e-1111-4222-8333-444455556666")

        self.assertEqual(json.loads(puts[0]), {"data": {"value": "kept"}})
        self.assertEqual(json.loads(puts[1]), {"description": None, "tags": None, "container_id": None})
        self.assertIn('"description": null', puts[1])
        self.assertEqual(json.loads(puts[2]), {"container_id": "6f0c5a4e-1111-4222-8333-444455556666"})

    def test_update_refuses_to_clear_the_value(self):
        client = SecretServerClient("sk_test", "https://example.test")
        with patch("urllib.request.OpenerDirector.open") as urlopen:
            with self.assertRaises(ValueError):
                client.update_secret("db", None)
            with self.assertRaises(ValueError):
                client.update_secret("db", "v", expected_version="3")
        urlopen.assert_not_called()

    def test_path_envelope_and_empty_value(self):
        client = SecretServerClient("sk_test", "https://example.test")
        for value in ("", "actual-value"):
            with patch("urllib.request.OpenerDirector.open", return_value=FakeResponse({"meta":{}, "data":{"value":value}})):
                self.assertEqual(client.secret("prod/db"), value)

    def test_http_error_body_is_not_disclosed(self):
        client = SecretServerClient("sk_test", "https://example.test")
        error = urllib.error.HTTPError('https://example.test',403,'forbidden',{},io.BytesIO(b'{"error":"do-not-log"}'))
        with patch("urllib.request.OpenerDirector.open", side_effect=error):
            with self.assertRaises(Exception) as result:
                client.secret('prod/db')
        self.assertNotIn('do-not-log', str(result.exception))
        self.assertEqual(result.exception.status_code, 403)

    def test_generic_request_accepts_prefixed_path(self):
        client = SecretServerClient("sk_test", "https://example.test")
        with patch("urllib.request.OpenerDirector.open", return_value=FakeResponse([])) as urlopen:
            client.request("GET", "/api/v1/crypto/backends")
        self.assertEqual(urlopen.call_args.args[0].full_url, "https://example.test/api/v1/crypto/backends")


if __name__ == "__main__":
    unittest.main()
