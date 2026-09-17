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

    def test_update_and_enrollment_match_backend_fields(self):
        client = SecretServerClient("sk_test", "https://example.test")
        captured = []

        def respond(request, **_kwargs):
            captured.append(json.loads(request.data))
            return FakeResponse({})

        with patch("urllib.request.OpenerDirector.open", side_effect=respond):
            client.update_secret("prod/db", "new")
            client.enroll_certificate("wildcard", "example.test", ["www.example.test"])

        self.assertEqual(captured[0]["name"], "prod/db")
        self.assertEqual(captured[1]["dns_names"], ["www.example.test"])
        self.assertNotIn("sans", captured[1])

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
