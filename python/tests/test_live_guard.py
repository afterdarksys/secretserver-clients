"""The live contract test must refuse to run against anything but loopback."""

import os
import subprocess
import sys
import unittest

LIVE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "live.py")
GOOD = {
    "SS_LIVE_URL": "http://127.0.0.1:9",
    "SS_LIVE_KEY": "sk_live_guard_key_do_not_leak",
    "SS_LIVE_WRITE_KEY": "sk_live_guard_write_key",
    "SS_LIVE_CONTAINER": "11111111-2222-4333-8444-555555555555",
}


class LiveGuardTests(unittest.TestCase):
    def run_live(self, **overrides):
        # Normal client settings are present to prove they are never used.
        env = {"PATH": os.environ.get("PATH", ""), "SS_API_URL": "https://example.invalid",
               "SS_API_KEY": "sk_normal_client_key"}
        env.update(GOOD)
        for name, value in overrides.items():
            if value is None:
                env.pop(name, None)
            else:
                env[name] = value
        # A marker module makes any client construction visible: the guard
        # must exit before secretserver is even imported.
        code = ("import sys, runpy; sys.argv = [%r]; "
                "sys.modules['secretserver'] = None; runpy.run_path(%r, run_name='__main__')") % (LIVE, LIVE)
        return subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=30)

    def assert_refused(self, result, needle):
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to run", result.stderr)
        self.assertIn(needle, result.stderr)
        self.assertNotIn("ImportError", result.stderr)
        self.assertNotIn("sk_live_guard_key_do_not_leak", result.stderr + result.stdout)

    def test_refuses_missing_or_non_loopback_url(self):
        for url in (None, "", "https://api.secretserver.io", "https://example.invalid",
                    "http://10.0.0.1:8080", "http://127.0.0.1@example.invalid",
                    "http://localhost.example.invalid", "http://[::2]:80", "not a url", "http://[::1"):
            with self.subTest(url=url):
                self.assert_refused(self.run_live(SS_LIVE_URL=url), "SS_LIVE_URL")

    def test_refuses_missing_keys_without_falling_back(self):
        for name in ("SS_LIVE_KEY", "SS_LIVE_WRITE_KEY", "SS_LIVE_CONTAINER"):
            with self.subTest(missing=name):
                self.assert_refused(self.run_live(**{name: None}), name)

    def test_loopback_urls_pass_the_guard(self):
        # Passing the guard reaches the client import, which the marker blocks.
        for url in ("http://127.0.0.1:9", "http://localhost:9", "http://[::1]:9", "https://LOCALHOST:9"):
            with self.subTest(url=url):
                result = self.run_live(SS_LIVE_URL=url)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("refusing to run", result.stderr)
                self.assertIn("secretserver", result.stderr)


if __name__ == "__main__":
    unittest.main()
