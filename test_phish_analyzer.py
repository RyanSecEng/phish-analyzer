"""Tests for phish-analyzer.

Run with:  python -m unittest discover -v

The module filename contains a hyphen, so it is loaded via importlib rather than
a normal import. Standard library only, no third-party packages.
"""
import importlib.util
import os
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "phish_analyzer", os.path.join(_HERE, "phish-analyzer.py"))
pa = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pa)


def _write_eml(text):
    """Write an .eml to a temp file and return its path."""
    fd, path = tempfile.mkstemp(suffix=".eml")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


class ProofpointDecodeTests(unittest.TestCase):
    def test_v2_decode_reveals_real_destination(self):
        url = ("https://urldefense.proofpoint.com/v2/url?"
               "u=http-3A__evil.ru_login&d=DwIFaQ&c=abc")
        self.assertEqual(pa.decode_proofpoint(url), "http://evil.ru/login")

    def test_v2_preserves_literal_hyphen(self):
        # A hyphen NOT followed by two hex digits must survive intact.
        url = ("https://urldefense.proofpoint.com/v2/url?"
               "u=http-3A__my-team.example.com_x&d=DwIFaQ")
        self.assertEqual(pa.decode_proofpoint(url),
                         "http://my-team.example.com/x")

    def test_v3_decode_reveals_real_destination(self):
        url = "https://urldefense.com/v3/__https://evil.ru/login__;Kw!!abc$"
        self.assertEqual(pa.decode_proofpoint(url), "https://evil.ru/login")

    def test_non_proofpoint_url_passes_through(self):
        url = "https://example.com/a?b=c"
        self.assertEqual(pa.decode_proofpoint(url), url)


class RegistrableDomainTests(unittest.TestCase):
    def test_simple_domain(self):
        self.assertEqual(pa.registrable_domain("example.com"), "example.com")

    def test_subdomain_collapses_to_etld_plus_one(self):
        self.assertEqual(pa.registrable_domain("a.b.example.com"), "example.com")

    def test_multi_label_suffix_co_uk(self):
        self.assertEqual(pa.registrable_domain("mail.corp.co.uk"), "corp.co.uk")

    def test_same_family_subdomain_vs_apex(self):
        self.assertTrue(pa.same_domain_family("mail.corp.com", "corp.com"))

    def test_lookalike_is_not_same_family(self):
        self.assertFalse(pa.same_domain_family("corp.com", "corp.com.evil.ru"))

    def test_cousin_domains_under_shared_suffix_differ(self):
        self.assertFalse(
            pa.same_domain_family("servicea.gov.uk", "serviceb.gov.uk"))


class SanitizeTests(unittest.TestCase):
    def test_strips_ansi_escape_sequences(self):
        self.assertEqual(pa.sanitize("\x1b[31mred\x1b[0m"), "red")

    def test_replaces_nonprintable_with_question_mark(self):
        self.assertEqual(pa.sanitize("a\x07b"), "a?b")


class HelperTests(unittest.TestCase):
    def test_get_domain_extracts_from_address(self):
        self.assertEqual(
            pa.get_domain("Bob <bob@Example.COM>"), "example.com")

    def test_dest_domain_handles_schemeless_url(self):
        self.assertEqual(pa.dest_domain("evil.ru/login"), "evil.ru")


class EndToEndTests(unittest.TestCase):
    def test_phishing_email_scores_high(self):
        eml = (
            "From: IT Security <security-alerts@gmail.com>\n"
            "Reply-To: noreply@mailer-relay.ru\n"
            "Subject: URGENT: Your account will be suspended\n"
            "Authentication-Results: mx.test; spf=fail; dkim=fail; dmarc=fail\n"
            "Content-Type: text/html\n"
            "\n"
            "<html><body>Dear user, please verify your account."
            '<a href="https://evil.ru/signin">paypal.com</a>'
            "</body></html>\n"
        )
        path = _write_eml(eml)
        try:
            findings, info, decoded, pp, pp_flagged = pa.analyze(path)
        finally:
            os.remove(path)
        score = sum(w for w, _ in findings)
        self.assertGreaterEqual(score, 6)  # HIGH tier

    def test_clean_email_scores_minimal(self):
        eml = (
            "From: Alice <alice@example.com>\n"
            "Subject: Lunch tomorrow?\n"
            "Authentication-Results: mx.test; spf=pass; dkim=pass; dmarc=pass\n"
            "Message-ID: <123@example.com>\n"
            "Content-Type: text/plain\n"
            "\n"
            "Hi Bob, are you free for lunch tomorrow at noon?\n"
        )
        path = _write_eml(eml)
        try:
            findings, info, decoded, pp, pp_flagged = pa.analyze(path)
        finally:
            os.remove(path)
        score = sum(w for w, _ in findings)
        self.assertEqual(score, 0)


if __name__ == "__main__":
    unittest.main()
