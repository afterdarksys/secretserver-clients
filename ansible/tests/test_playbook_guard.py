"""The Ansible live playbook must refuse to run against anything but loopback.

Run with: python -m pytest ansible/tests (requires ansible-core).
"""

import os
import shutil
import subprocess
import sys
import unittest

TESTS = os.path.dirname(os.path.abspath(__file__))
PLAYBOOK = os.path.join(TESTS, "live.yml")
KEY = "sk_ansible_live_guard_key"


def ansible_playbook():
    local = os.path.join(os.path.dirname(sys.executable), "ansible-playbook")
    return local if os.path.exists(local) else shutil.which("ansible-playbook")


class LiveGuardTests(unittest.TestCase):
    def run_play(self, **overrides):
        env = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", TESTS),
               "ANSIBLE_NOCOLOR": "1", "ANSIBLE_LOOKUP_PLUGINS": os.path.dirname(TESTS),
               "SS_API_URL": "https://example.invalid", "SS_API_KEY": "sk_normal_client_key",
               "SS_LIVE_URL": "http://127.0.0.1:9", "SS_LIVE_KEY": KEY,
               "SS_LIVE_CONTAINER": "11111111-2222-4333-8444-555555555555"}
        for name, value in overrides.items():
            if value is None:
                env.pop(name, None)
            else:
                env[name] = value
        return subprocess.run([ansible_playbook(), "-i", "localhost,", PLAYBOOK], env=env, cwd=TESTS,
                              capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)

    def assert_refused(self, result):
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, output)
        self.assertIn("refusing to run", output)
        self.assertNotIn("Create a secret to read back", output)
        self.assertNotIn(KEY, output)

    def test_refuses_non_loopback_url(self):
        for url in (None, "https://api.secretserver.io", "https://example.invalid",
                    "http://127.0.0.1@example.invalid", "http://10.0.0.1:8080", "not a url"):
            with self.subTest(url=url):
                self.assert_refused(self.run_play(SS_LIVE_URL=url))

    def test_refuses_missing_key_without_falling_back(self):
        self.assert_refused(self.run_play(SS_LIVE_KEY=None))

    def test_loopback_passes_the_guard(self):
        # Nothing listens on port 9, so the first real task fails after the guard.
        result = self.run_play()
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, output)
        self.assertNotIn("refusing to run", output)
        self.assertIn("Create a secret to read back", output)


if __name__ == "__main__":
    unittest.main()
