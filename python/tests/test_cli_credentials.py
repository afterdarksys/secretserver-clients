"""cli_credential_provider against fake `ss` executables (no real CLI or server)."""

import json
import os
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from secretserver import AuthError, SecretServerClient, SecretServerError, cli_credential_provider
from test_contract import OPEN, Response

TOKEN = "eyJ.cli-session-token-do-not-leak.sig"


def fake_ss(test, body):
    """Write a fake `ss` that counts its runs and refuses any argv but the documented one."""
    d = tempfile.mkdtemp()
    path, count = os.path.join(d, "ss"), os.path.join(d, "count")
    with open(path, "w") as f:
        f.write(f"""#!/bin/sh
echo run >> '{count}'
if [ "$#" -ne 4 ] || [ "$1" != auth ] || [ "$2" != print-access-token ] || [ "$3" != --format ] || [ "$4" != json ]; then
  echo "unexpected argv: $*" >&2; exit 1
fi
{body}
""")
    os.chmod(path, 0o700)

    def runs():
        if not os.path.exists(count):
            return 0
        with open(count) as f:
            return f.read().count("run\n")
    return path, runs


def token_json(expires_in, api_url="", token=TOKEN):
    expires = (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = json.dumps({"access_token": token, "expires_at": expires, "api_url": api_url, "tenant_id": "t-1"})
    return f"printf '%s' '{payload}'"


class CliCredentialProviderTests(unittest.TestCase):
    def assert_no_token(self, exc):
        for text in (str(exc), repr(exc), repr(exc.__cause__), repr(exc.__context__)):
            self.assertNotIn(TOKEN, text)

    def test_success_and_cache(self):
        path, runs = fake_ss(self, token_json(3600, "https://api.example.test"))
        p = cli_credential_provider(cli_path=path)
        for _ in range(3):
            self.assertEqual(p(), TOKEN)
        self.assertEqual(p.api_url(), "https://api.example.test")
        self.assertEqual(runs(), 1)
        self.assertNotIn(TOKEN, repr(p))

    def test_refresh_within_60s_of_expiry(self):
        path, runs = fake_ss(self, token_json(30))
        p = cli_credential_provider(cli_path=path)
        p(); p()
        self.assertEqual(runs(), 2)

    def test_ss_cli_path_env(self):
        path, runs = fake_ss(self, token_json(3600))
        with patch.dict(os.environ, {"SS_CLI_PATH": path}):
            self.assertEqual(cli_credential_provider()(), TOKEN)
        self.assertEqual(runs(), 1)

    def test_exit_2_is_auth_error(self):
        path, _ = fake_ss(self, 'echo "not logged in" >&2; exit 2')
        with self.assertRaises(AuthError) as ctx:
            cli_credential_provider(cli_path=path)()
        self.assertIn("ss login", str(ctx.exception))

    def test_failures_fail_closed_without_leaking_token(self):
        big = "head -c 70000 /dev/zero | tr '\\0' a; " + token_json(3600)
        cases = {
            "exit 1": (f'echo "network unreachable" >&2; printf \'{TOKEN}\'; exit 1', "network unreachable"),
            "malformed json": (f"printf '{{\"access_token\":\"{TOKEN}\",'", "invalid JSON"),
            "bad expires_at": (f"printf '{{\"access_token\":\"{TOKEN}\",\"expires_at\":\"soon\"}}'", "expires_at"),
            "empty token": ("printf '{\"access_token\":\"\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'", "access_token"),
            "header injection": ("printf '{\"access_token\":\"a\\\\r\\\\nX: y\",\"expires_at\":\"2099-01-01T00:00:00Z\"}'", "access_token"),
            "oversized stdout": (big, "exceeds 65536 bytes"),
        }
        for name, (body, want) in cases.items():
            with self.subTest(name):
                path, _ = fake_ss(self, body)
                with self.assertRaises(SecretServerError) as ctx:
                    cli_credential_provider(cli_path=path)()
                self.assertNotIsInstance(ctx.exception, AuthError)
                self.assertIn(want, str(ctx.exception))
                self.assert_no_token(ctx.exception)

    def test_timeout(self):
        path, _ = fake_ss(self, "exec sleep 10")
        start = time.monotonic()
        with self.assertRaises(SecretServerError) as ctx:
            cli_credential_provider(cli_path=path, timeout=0.2)()
        self.assertIn("timed out", str(ctx.exception))
        self.assertLess(time.monotonic() - start, 5)

    def test_missing_binary(self):
        with self.assertRaises(SecretServerError) as ctx:
            cli_credential_provider(cli_path=os.path.join(tempfile.mkdtemp(), "no-such-ss"))()
        self.assertIn("not found", str(ctx.exception))
        with self.assertRaises(ValueError):
            cli_credential_provider(timeout=0)

    def test_client_uses_cli_token_and_api_url(self):
        path, runs = fake_ss(self, token_json(3600, "https://cli.example.test/api/v1"))
        # pinned's own CLI session reports an origin equal to its explicit
        # api_url modulo case and a trailing slash: not a mismatch.
        pinned_path, pinned_runs = fake_ss(self, token_json(3600, "https://Pinned.example.test/"))
        seen = []

        def response(req, **kwargs):
            seen.append((req.full_url, req.get_header("Authorization")))
            return Response(b"{}")
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SS_API_URL", None)
            c = SecretServerClient(credential_provider=cli_credential_provider(cli_path=path))
            pinned = SecretServerClient(credential_provider=cli_credential_provider(cli_path=pinned_path),
                                        api_url="https://pinned.example.test")
        self.assertEqual(pinned_runs(), 0, "mismatch check is deferred to first request")
        with patch(OPEN, side_effect=response):
            c.request("GET", "/health"); c.request("GET", "/health")
            pinned.request("GET", "/health")
        self.assertEqual(seen, [("https://cli.example.test/api/v1/health", f"Bearer {TOKEN}")] * 2
                         + [("https://pinned.example.test/api/v1/health", f"Bearer {TOKEN}")])
        self.assertEqual(runs(), 1)  # eager at construction (no explicit api_url); cached across requests
        self.assertEqual(pinned_runs(), 1)  # checked and cached together on first use

    def test_client_refuses_mismatched_api_url(self):
        path, runs = fake_ss(self, token_json(3600, "https://cli.example.test"))
        c = SecretServerClient(credential_provider=cli_credential_provider(cli_path=path), api_url="https://pinned.example.test")
        self.assertEqual(runs(), 0, "mismatch check is deferred to first request")
        with patch(OPEN) as transport:
            with self.assertRaises(SecretServerError) as ctx:
                c.request("GET", "/health")
            transport.assert_not_called()
        message = str(ctx.exception)
        self.assertIn("https://pinned.example.test", message)
        self.assertIn("https://cli.example.test", message)
        self.assertNotIn(TOKEN, message)

    def test_client_surfaces_login_error_without_request(self):
        path, _ = fake_ss(self, "exit 2")
        c = SecretServerClient(credential_provider=cli_credential_provider(cli_path=path), api_url="https://x.example.test")
        with patch(OPEN) as transport:
            with self.assertRaises(AuthError) as ctx:
                c.request("GET", "/x")
            transport.assert_not_called()
        self.assertIn("ss login", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
