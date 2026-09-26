"""Negative tests for the client's transport security policy."""

import io
import json
import ssl
import threading
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

from secretserver.client import SecretServerClient, SecretServerError

KEY = "sk_security_test_key_do_not_leak"
OPEN = "urllib.request.OpenerDirector.open"


class RawResponse:
    def __init__(self, payload: bytes):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, limit=None):
        return self.payload if limit is None else self.payload[:limit]


def ok(payload=None):
    return RawResponse(json.dumps({} if payload is None else payload).encode())


class BaseUrlPolicyTests(unittest.TestCase):
    def test_plain_http_to_remote_host_is_rejected(self):
        for url in ("http://example.test", "http://10.0.0.5:8080", "http://localhost.evil.test"):
            with self.assertRaises(ValueError) as ctx:
                SecretServerClient(KEY, url)
            self.assertNotIn(KEY, str(ctx.exception))

    def test_plain_http_to_loopback_is_allowed(self):
        for url in ("http://localhost:8080", "http://127.0.0.1:9", "http://[::1]:9/api/v1"):
            client = SecretServerClient(KEY, url)
            self.assertTrue(client.api_url.startswith("http://"))

    def test_other_schemes_are_rejected(self):
        for url in ("ftp://example.test", "file:///etc/passwd", "example.test", "https://"):
            with self.assertRaises(ValueError):
                SecretServerClient(KEY, url)

    def test_userinfo_is_rejected_without_echoing_it(self):
        for url in ("https://user:hunter2@example.test", "https://hunter2@example.test", "http://u:hunter2@localhost"):
            with self.assertRaises(ValueError) as ctx:
                SecretServerClient(KEY, url)
            self.assertNotIn("hunter2", str(ctx.exception))
            self.assertNotIn(KEY, str(ctx.exception))

    def test_query_and_fragment_are_rejected(self):
        for url in ("https://example.test/?x=1", "https://example.test/#frag"):
            with self.assertRaises(ValueError):
                SecretServerClient(KEY, url)

    def test_env_url_is_validated_too(self):
        with patch.dict("os.environ", {"SS_API_URL": "http://example.test"}):
            with self.assertRaises(ValueError):
                SecretServerClient(KEY)

    def test_api_key_with_header_injection_is_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            SecretServerClient(KEY + "\r\nX-Evil: 1", "https://example.test")
        self.assertNotIn(KEY, str(ctx.exception))


class TlsPolicyTests(unittest.TestCase):
    def test_verify_ssl_false_is_rejected(self):
        with self.assertRaises(ValueError):
            SecretServerClient(KEY, "https://example.test", verify_ssl=False)

    def test_default_context_verifies_and_requires_tls12(self):
        client = SecretServerClient(KEY, "https://example.test")
        self.assertEqual(client._ssl_ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(client._ssl_ctx.check_hostname)
        self.assertGreaterEqual(client._ssl_ctx.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_ca_file_is_loaded_into_a_verifying_context(self):
        real = ssl.create_default_context
        seen = {}

        def spy(*args, **kwargs):
            seen.update(kwargs)
            return real()

        with patch("ssl.create_default_context", side_effect=spy):
            client = SecretServerClient(KEY, "https://example.test", ca_file="/path/ca.pem")
        self.assertEqual(seen.get("cafile"), "/path/ca.pem")
        self.assertEqual(client._ssl_ctx.verify_mode, ssl.CERT_REQUIRED)

    def test_missing_ca_file_fails_closed(self):
        with self.assertRaises(OSError):
            SecretServerClient(KEY, "https://example.test", ca_file="/nonexistent/ca.pem")


class ResponsePolicyTests(unittest.TestCase):
    def setUp(self):
        self.client = SecretServerClient(KEY, "https://example.test")

    def test_oversize_json_response_is_rejected(self):
        body = b'{"secrets": [' + b" " * (4 * 1024 * 1024) + b"]}"
        with patch(OPEN, return_value=RawResponse(body)):
            with self.assertRaises(SecretServerError) as ctx:
                self.client.list_secrets()
        self.assertIn("too large", str(ctx.exception))

    def test_oversize_raw_download_is_rejected(self):
        body = b"A" * (16 * 1024 * 1024 + 1)
        with patch(OPEN, return_value=RawResponse(body)):
            with self.assertRaises(SecretServerError):
                self.client.download_certificate("c1")

    def test_invalid_json_success_is_rejected(self):
        with patch(OPEN, return_value=RawResponse(b"<html>not json</html>")):
            with self.assertRaises(SecretServerError) as ctx:
                self.client.list_secrets()
        self.assertNotIn("html", str(ctx.exception))

    def test_errors_do_not_include_key_or_body(self):
        body = json.dumps({"error": "leaky-body", "echo": KEY}).encode()
        for code in (400, 401, 403, 404, 500):
            error = urllib.error.HTTPError("https://example.test", code, "x", {}, io.BytesIO(body))
            with patch(OPEN, side_effect=error):
                with self.assertRaises(SecretServerError) as ctx:
                    self.client.secret("prod/db")
            message = str(ctx.exception)
            self.assertIn(f"HTTP {code}", message)
            self.assertNotIn("leaky-body", message)
            self.assertNotIn(KEY, message)
            self.assertIsNone(ctx.exception.__cause__)

    def test_connection_errors_do_not_include_key(self):
        with patch(OPEN, side_effect=urllib.error.URLError(KEY)):
            with self.assertRaises(SecretServerError) as ctx:
                self.client.list_secrets()
        self.assertNotIn(KEY, str(ctx.exception))
        with patch(OPEN, side_effect=TimeoutError("timed out")):
            with self.assertRaises(SecretServerError):
                self.client.list_secrets()


class PathEncodingTests(unittest.TestCase):
    def setUp(self):
        self.client = SecretServerClient(KEY, "https://example.test")

    def url_for(self, call, response=None):
        with patch(OPEN, return_value=ok(response)) as opener:
            call()
        return opener.call_args.args[0].full_url

    def test_ids_are_percent_encoded(self):
        base = "https://example.test/api/v1"
        cases = [
            (lambda: self.client.get_certificate("../admin"), f"{base}/certificates/..%2Fadmin"),
            (lambda: self.client.revoke_certificate("a/b"), f"{base}/certificates/a%2Fb/revoke"),
            (lambda: self.client.export_ssh_key("k?x=1"), f"{base}/ssh-keys/k%3Fx%3D1/export"),
            (lambda: self.client.get_gpg_key("g#f"), f"{base}/gpg-keys/g%23f"),
            (lambda: self.client.get_openssl_key("o k"), f"{base}/openssl-keys/o%20k"),
            (lambda: self.client.get_ntlm_hash("n/1"), f"{base}/ntlm/n%2F1"),
            (lambda: self.client.get_totp_token("t/1"), f"{base}/totp-tokens/t%2F1"),
            (lambda: self.client.get_yubikey("y/1"), f"{base}/yubikeys/y%2F1"),
            (lambda: self.client.test_webhook("w/1"), f"{base}/webhooks/w%2F1/test"),
            (lambda: self.client.credentials("wifi-credentials").get("c/1"), f"{base}/wifi-credentials/c%2F1"),
            (lambda: self.client.credentials("a/b").list(), f"{base}/a%2Fb"),
        ]
        for call, expected in cases:
            self.assertEqual(self.url_for(call), expected)

    def test_dot_segments_and_empty_ids_are_rejected(self):
        for bad in ("", ".", ".."):
            with self.assertRaises(ValueError):
                self.client.get_certificate(bad)
        with self.assertRaises(ValueError):
            self.client.secret("prod//db")

    def test_query_values_are_encoded(self):
        url = self.url_for(lambda: self.client.list_signing_keys("pkcs11&admin=1"))
        self.assertTrue(url.endswith("/crypto/signing-keys?backend=pkcs11%26admin%3D1"))
        url = self.url_for(lambda: self.client.get_audit_logs(action="x&limit=999999"))
        self.assertIn("action=x%26limit%3D999999", url)
        self.assertEqual(url.count("limit="), 1)


class _Redirector(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "http://127.0.0.1:1/stolen")
        self.end_headers()

    def log_message(self, *_args):
        pass


class RedirectTests(unittest.TestCase):
    def test_redirects_are_not_followed(self):
        server = HTTPServer(("127.0.0.1", 0), _Redirector)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = SecretServerClient(KEY, f"http://127.0.0.1:{server.server_port}", timeout=5)
            with self.assertRaises(SecretServerError) as ctx:
                client.list_secrets()
            self.assertEqual(ctx.exception.status_code, 302)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
