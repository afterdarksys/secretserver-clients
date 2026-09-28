import json
import pickle
import unittest
from unittest.mock import patch
from secretserver import SecretServerClient, SecretServerError, AuthError
from test_contract import Response, OPEN

class MemoryTests(unittest.TestCase):
    def test_owned_credential_cleanup(self):
        c = SecretServerClient("secret-marker")
        self.assertNotIn("secret-marker", repr(c))
        self.assertNotIn("secret-marker", repr(vars(c)))
        with self.assertRaises(TypeError): pickle.dumps(c)
        owned = c._credential._value
        with c:
            self.assertEqual(c.api_key, "secret-marker")
        self.assertEqual(owned, bytearray())
        self.assertEqual(c.api_key, "")
        c.close()
        with patch(OPEN) as transport:
            with self.assertRaises(SecretServerError): c.list_secrets()
            transport.assert_not_called()

    def test_provider_rotation_and_errors(self):
        keys = iter(["first", "second"])
        c = SecretServerClient(credential_provider=lambda: next(keys))
        seen = []
        def response(req, **kwargs):
            seen.append(req.get_header("Authorization"))
            return Response(b"{}")
        with patch(OPEN, side_effect=response):
            c.request("GET", "/x"); c.request("GET", "/x")
        self.assertEqual(seen, ["Bearer first", "Bearer second"])
        self.assertEqual(c.api_key, "")
        def fail(): raise ValueError("secret-marker")
        c = SecretServerClient(credential_provider=fail)
        with patch(OPEN) as transport:
            with self.assertRaises(AuthError) as error: c.request("GET", "/x")
            self.assertNotIn("secret-marker", str(error.exception))
            transport.assert_not_called()
        c = SecretServerClient(credential_provider=lambda: "bad\ncredential")
        with self.assertRaises(AuthError): c.request("GET", "/x")

    def test_remote_signing_handle(self):
        c = SecretServerClient("test")
        key = c.signing_key("server-key", "pkcs11")
        def response(req, **kwargs):
            self.assertTrue(req.full_url.endswith("/crypto/sign"))
            self.assertEqual(json.loads(req.data), {"backend":"pkcs11", "key_id":"server-key", "message":"AP8=", "purpose":"release"})
            return Response(b'{"signature":"result"}')
        with patch(OPEN, side_effect=response):
            self.assertEqual(key.sign(b"\x00\xff", "release")["signature"], "result")
        with self.assertRaises(TypeError): pickle.dumps(key)
        c.close()
        with patch(OPEN) as transport:
            with self.assertRaises(SecretServerError): key.sign(b"x", "release")
            transport.assert_not_called()

    def test_close_racing_credential_replacement(self):
        import threading
        from secretserver.client import _Credential
        c = SecretServerClient("before")
        entered, release = threading.Event(), threading.Event()
        original = _Credential.__init__
        def delayed(value_self, value):
            if value == "replacement":
                entered.set()
                if not release.wait(5): raise RuntimeError("test timed out")
            original(value_self, value)
        with patch.object(_Credential, "__init__", delayed):
            setter = threading.Thread(target=lambda: setattr(c, "api_key", "replacement"))
            setter.start()
            self.assertTrue(entered.wait(5))
            closer = threading.Thread(target=c.close)
            closer.start()
            release.set()
            setter.join(5); closer.join(5)
            self.assertFalse(setter.is_alive() or closer.is_alive())
        self.assertTrue(c._closed)
        self.assertEqual(c.api_key, "")
