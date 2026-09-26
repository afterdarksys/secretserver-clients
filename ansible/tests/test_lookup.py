"""Offline tests for the secretserver lookup plugin's security policy.

Run with: python -m pytest ansible/tests (requires ansible-core).
"""

import io
import json
import os
import ssl
import sys
import tempfile
import threading
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

from ansible.errors import AnsibleError
from ansible.plugins.loader import lookup_loader

PLUGIN_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
lookup_loader.add_directory(PLUGIN_DIR)
sys.path.insert(0, os.path.join(os.path.dirname(PLUGIN_DIR), "python", "tests"))
from tls_fixture import CertUnavailable, TlsServer, make_cert  # noqa: E402

KEY = "sk_ansible_test_key_do_not_leak"
OPEN = "urllib.request.OpenerDirector.open"


class Raw:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, limit=None):
        return self.payload if limit is None else self.payload[:limit]


def lookup(term, **options):
    options.setdefault("api_key", KEY)
    options.setdefault("api_url", "https://secrets.example.test")
    return lookup_loader.get("secretserver").run([term], variables={}, **options)


class UrlPolicyTests(unittest.TestCase):
    def assert_rejected(self, url, secret=KEY):
        with patch(OPEN) as opener:
            with self.assertRaises(AnsibleError) as ctx:
                lookup("prod/db", api_url=url)
        opener.assert_not_called()
        self.assertNotIn(secret, str(ctx.exception))
        self.assertNotIn(KEY, str(ctx.exception))

    def test_plain_http_to_remote_host_is_rejected(self):
        for url in ("http://secrets.example.test", "http://10.1.2.3:8080", "http://localhost.evil.test"):
            self.assert_rejected(url)

    def test_other_schemes_and_malformed_urls_are_rejected(self):
        for url in ("ftp://secrets.example.test", "secrets.example.test", "https://", "https://h/?q=1"):
            self.assert_rejected(url)

    def test_userinfo_is_rejected_without_echoing_it(self):
        for url in ("https://u:hunter2@secrets.example.test", "http://hunter2@127.0.0.1:1"):
            self.assert_rejected(url, secret="hunter2")

    def test_loopback_http_and_https_are_allowed(self):
        body = json.dumps({"data": {"value": "v"}}).encode()
        for url, expected in (
            ("http://127.0.0.1:8200", "http://127.0.0.1:8200/api/v1/s/prod/db"),
            ("http://localhost:8200/api/v1", "http://localhost:8200/api/v1/s/prod/db"),
            ("http://[::1]:8200", "http://[::1]:8200/api/v1/s/prod/db"),
            ("https://secrets.example.test", "https://secrets.example.test/api/v1/s/prod/db"),
        ):
            with patch(OPEN, return_value=Raw(body)) as opener:
                self.assertEqual(lookup("prod/db", api_url=url), ["v"])
            self.assertEqual(opener.call_args.args[0].full_url, expected)

    def test_dot_and_empty_segments_are_rejected(self):
        for term in ("prod/../admin", "prod//db", "./db"):
            with patch(OPEN) as opener:
                with self.assertRaises(AnsibleError):
                    lookup(term)
            opener.assert_not_called()

    def test_segments_are_percent_encoded(self):
        body = json.dumps({"data": {"value": "v"}}).encode()
        with patch(OPEN, return_value=Raw(body)) as opener:
            lookup("pr od/d?b#x")
        self.assertTrue(opener.call_args.args[0].full_url.endswith("/api/v1/s/pr%20od/d%3Fb%23x"))


class TlsPolicyTests(unittest.TestCase):
    def capture_context(self, **options):
        seen = {}
        real = ssl.create_default_context

        def spy(*args, **kwargs):
            seen["cafile"] = kwargs.get("cafile")
            seen["ctx"] = real()
            return seen["ctx"]

        body = json.dumps({"data": {"value": "v"}}).encode()
        with patch("ssl.create_default_context", side_effect=spy), patch(OPEN, return_value=Raw(body)):
            lookup("prod/db", **options)
        return seen

    def test_ss_insecure_no_longer_disables_verification(self):
        with patch.dict(os.environ, {"SS_INSECURE": "1"}):
            seen = self.capture_context()
        self.assertEqual(seen["ctx"].verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(seen["ctx"].check_hostname)
        self.assertGreaterEqual(seen["ctx"].minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_missing_ca_path_fails_closed(self):
        with patch(OPEN) as opener:
            with self.assertRaises(AnsibleError) as ctx:
                lookup("prod/db", ca_path="/nonexistent/ca.pem")
        opener.assert_not_called()
        self.assertIn("ca_path", str(ctx.exception))


class RealTlsHandshakeTests(unittest.TestCase):
    """Handshakes against a local HTTPS server with a throwaway self-signed certificate."""

    BODY = {"data": {"value": "tls-ok"}}

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        try:
            self.cert, self.key = make_cert(tmp.name, "private-ca")
            self.other_cert, self.other_key = make_cert(tmp.name, "system-ca")
        except CertUnavailable as exc:
            self.skipTest(str(exc))
        env = patch.dict(os.environ, {"no_proxy": "*", "NO_PROXY": "*"})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("SS_CA_PATH", None)

    def test_untrusted_certificate_fails_before_any_request(self):
        with TlsServer(self.cert, self.key, self.BODY) as server:
            with self.assertRaises(AnsibleError) as ctx:
                lookup("prod/db", api_url=server.url, timeout=5)
        self.assertEqual(str(ctx.exception), "SecretServer connection failed")
        self.assertNotIn(KEY, str(ctx.exception))
        self.assertEqual(server.requests, [])

    def test_wrong_ca_path_still_rejects(self):
        with TlsServer(self.cert, self.key, self.BODY) as server:
            with self.assertRaises(AnsibleError):
                lookup("prod/db", api_url=server.url, timeout=5, ca_path=self.other_cert)
        self.assertEqual(server.requests, [])

    def test_ca_path_option_trusts_the_private_ca(self):
        with TlsServer(self.cert, self.key, self.BODY) as server:
            self.assertEqual(lookup("prod/db", api_url=server.url, timeout=5, ca_path=self.cert), ["tls-ok"])
        self.assertEqual(server.requests, ["Bearer " + KEY])

    def test_ca_path_env_trusts_the_private_ca(self):
        with TlsServer(self.cert, self.key, self.BODY) as server:
            with patch.dict(os.environ, {"SS_CA_PATH": self.cert}):
                self.assertEqual(lookup("prod/db", api_url=server.url, timeout=5), ["tls-ok"])
        self.assertEqual(server.requests, ["Bearer " + KEY])

    def test_ca_path_is_added_to_the_system_trust_store(self):
        plugin = lookup_loader.get("secretserver")
        make_ssl_context = sys.modules[type(plugin).__module__].make_ssl_context
        default = ssl.create_default_context().cert_store_stats()["x509"]
        self.assertEqual(make_ssl_context(self.cert).cert_store_stats()["x509"], default + 1)
        # A server trusted only through the default store (SSL_CERT_FILE) still
        # verifies. Apple's system LibreSSL ignores SSL_CERT_FILE; there the
        # store count above is the evidence that the defaults were kept.
        with patch.dict(os.environ, {"SSL_CERT_FILE": self.other_cert}):
            if ssl.create_default_context().cert_store_stats()["x509"] != 1:
                return
            with TlsServer(self.other_cert, self.other_key, self.BODY) as server:
                self.assertEqual(lookup("prod/db", api_url=server.url, timeout=5, ca_path=self.cert), ["tls-ok"])
        self.assertEqual(server.requests, ["Bearer " + KEY])


class ResponsePolicyTests(unittest.TestCase):
    def test_http_error_is_closed_and_free_of_key_and_body(self):
        for term in ("prod/db", "%%NAME%%"):
            fp = io.BytesIO(json.dumps({"error": "leaky-body", "key": KEY}).encode())
            error = urllib.error.HTTPError("https://x", 401, "no", {}, fp)
            with patch(OPEN, side_effect=error):
                with self.assertRaises(AnsibleError) as ctx:
                    lookup(term)
            message = str(ctx.exception)
            self.assertIn("HTTP 401", message)
            self.assertNotIn("leaky-body", message)
            self.assertNotIn(KEY, message)
            self.assertIsNone(ctx.exception.__cause__)
            self.assertTrue(fp.closed)

    def test_connection_error_is_free_of_key(self):
        with patch(OPEN, side_effect=urllib.error.URLError(KEY)):
            with self.assertRaises(AnsibleError) as ctx:
                lookup("prod/db")
        self.assertNotIn(KEY, str(ctx.exception))

    def test_oversize_response_is_rejected(self):
        body = b'{"data": {"value": "' + b"A" * (4 * 1024 * 1024) + b'"}}'
        with patch(OPEN, return_value=Raw(body)):
            with self.assertRaises(AnsibleError) as ctx:
                lookup("prod/db")
        self.assertIn("size limit", str(ctx.exception))

    def test_invalid_json_is_rejected(self):
        with patch(OPEN, return_value=Raw(b"<html>secret-ish</html>")):
            with self.assertRaises(AnsibleError) as ctx:
                lookup("prod/db")
        self.assertNotIn("secret-ish", str(ctx.exception))


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
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with patch.dict(os.environ, {"no_proxy": "*"}):
                with self.assertRaises(AnsibleError) as ctx:
                    lookup("prod/db", api_url="http://127.0.0.1:{}".format(server.server_port))
            self.assertIn("HTTP 302", str(ctx.exception))
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
