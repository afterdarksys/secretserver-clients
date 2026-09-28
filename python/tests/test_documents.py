import unittest
from unittest.mock import patch
from secretserver.client import SecretServerClient
from test_contract import Response, OPEN

class DocumentTests(unittest.TestCase):
    def test_wire_contract(self):
        calls = []
        def respond(req, **kwargs):
            calls.append(req)
            return Response(b"\x00\xff\n\x80" if "/pages/" in req.full_url or req.full_url.endswith("/download") else b"{}")
        c = SecretServerClient("test", "https://example.test")
        with patch(OPEN, side_effect=respond):
            pdf = b"%PDF-\x00\xff"
            c.upload_document("a & b.pdf", pdf)
            self.assertEqual(calls[-1].data, pdf)
            self.assertEqual(calls[-1].get_header("Content-type"), "application/pdf")
            self.assertTrue(calls[-1].full_url.endswith("/documents?name=a+%26+b.pdf"))
            self.assertEqual(c.preview_document("doc", 2, for_print=True), b"\x00\xff\n\x80")
            self.assertTrue(calls[-1].full_url.endswith("/pages/2?purpose=print"))
            self.assertEqual(c.download_document("doc"), b"\x00\xff\n\x80")
            c.grant_document("doc", "2030-01-01T00:00:00Z", recipient_email="member@example.com")
            import json
            body = json.loads(calls[-1].data)
            self.assertFalse(body["allow_download"])
            self.assertFalse(body["allow_print"])
            c.list_documents(); c.get_document("doc"); c.list_document_grants("doc"); c.revoke_document_grant("doc", "grant")
            self.assertEqual(calls[-1].get_method(), "DELETE")
            count = len(calls)
            for invoke in (lambda: c.preview_document("doc", 0), lambda: c.upload_document("x", b"x" * (8*1024*1024+1)), lambda: c.grant_document("doc", "x")):
                with self.assertRaises(ValueError): invoke()
            self.assertEqual(len(calls), count)
