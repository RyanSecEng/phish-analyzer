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

    def test_external_link_alone_does_not_score(self):
        # A link to a third-party domain (tracker/CDN/unsubscribe) is normal in
        # legit mail and must not score on its own. Only a text-vs-href mismatch
        # should. This guards against re-adding the old false-positive signal.
        eml = (
            "From: Alice <alice@example.com>\n"
            "Subject: Newsletter\n"
            "Authentication-Results: mx.test; spf=pass; dkim=pass; dmarc=pass\n"
            "Message-ID: <1@example.com>\n"
            "Content-Type: text/html\n"
            "\n"
            "<html><body>Hello!"
            '<a href="https://track.mailchimp.com/x">read more</a>'
            "</body></html>\n"
        )
        path = _write_eml(eml)
        try:
            findings, info, decoded, pp, pp_flagged = pa.analyze(path)
        finally:
            os.remove(path)
        score = sum(w for w, _ in findings)
        self.assertEqual(score, 0)


def _descs(findings):
    return " | ".join(d.lower() for _, d in findings)


class TyposquatTests(unittest.TestCase):
    def test_digit_swap_imitates_brand(self):
        self.assertEqual(pa.typosquat_target("paypa1.com"), "paypal.com")
        self.assertEqual(pa.typosquat_target("micros0ft.com"), "microsoft.com")

    def test_real_brand_is_not_flagged(self):
        self.assertEqual(pa.typosquat_target("paypal.com"), "")

    def test_one_char_off_sender_is_flagged(self):
        self.assertEqual(
            pa.typosquat_target("examp1e.com", "example.com"), "example.com")

    def test_unrelated_lookalike_does_not_false_positive(self):
        # goggle.com / doodle.com are real sites a hair away from a brand.
        self.assertEqual(pa.typosquat_target("goggle.com"), "")
        self.assertEqual(pa.typosquat_target("doodle.com"), "")


class HomographTests(unittest.TestCase):
    def test_mixed_script_label_is_flagged(self):
        # 'paypal' with a Cyrillic 'a'.
        host = "pаypal.com"
        self.assertEqual(pa.idn_homograph(host), ["pаypal"])

    def test_punycode_homograph_is_flagged(self):
        host = pa._normalize("pаypal.com")
        self.assertTrue(host.startswith("xn--"))
        self.assertTrue(pa.idn_homograph(host))

    def test_legit_diacritics_are_not_flagged(self):
        self.assertEqual(pa.idn_homograph("müller.de"), [])


class LevenshteinTests(unittest.TestCase):
    def test_known_distances(self):
        self.assertEqual(pa._levenshtein("kitten", "sitting"), 3)
        self.assertEqual(pa._levenshtein("abc", "abc"), 0)
        self.assertEqual(pa._levenshtein("abc", "abd"), 1)


class AttachmentTests(unittest.TestCase):
    def test_double_extension_is_flagged(self):
        eml = (
            "From: Alice <alice@example.com>\n"
            "Subject: invoice\n"
            "Authentication-Results: mx.test; spf=pass; dkim=pass; dmarc=pass\n"
            "Message-ID: <1@example.com>\n"
            'Content-Type: multipart/mixed; boundary="b"\n'
            "\n"
            "--b\n"
            "Content-Type: text/plain\n"
            "\n"
            "See attached.\n"
            "--b\n"
            "Content-Type: application/octet-stream\n"
            'Content-Disposition: attachment; filename="invoice.pdf.exe"\n'
            "Content-Transfer-Encoding: base64\n"
            "\n"
            "TVpwYXlsb2Fk\n"
            "--b--\n"
        )
        path = _write_eml(eml)
        try:
            findings, info, decoded, pp, pp_flagged = pa.analyze(path)
        finally:
            os.remove(path)
        self.assertIn("double extension", _descs(findings))
        # the sha256 of the payload is surfaced for hash lookups
        self.assertTrue(any("sha256=" in line for line in info))

    def test_benign_pdf_attachment_does_not_score(self):
        eml = (
            "From: Alice <alice@example.com>\n"
            "Subject: report\n"
            "Authentication-Results: mx.test; spf=pass; dkim=pass; dmarc=pass\n"
            "Message-ID: <1@example.com>\n"
            'Content-Type: multipart/mixed; boundary="b"\n'
            "\n"
            "--b\n"
            "Content-Type: text/plain\n"
            "\n"
            "Here is the report.\n"
            "--b\n"
            "Content-Type: application/pdf\n"
            'Content-Disposition: attachment; filename="report.pdf"\n'
            "Content-Transfer-Encoding: base64\n"
            "\n"
            "JVBERi0=\n"
            "--b--\n"
        )
        path = _write_eml(eml)
        try:
            findings, info, decoded, pp, pp_flagged = pa.analyze(path)
        finally:
            os.remove(path)
        self.assertEqual(sum(w for w, _ in findings), 0)


class HiddenContentTests(unittest.TestCase):
    def test_hidden_lure_text_and_zero_width(self):
        eml = (
            "From: Alice <alice@example.com>\n"
            "Subject: hello\n"
            "Authentication-Results: mx.test; spf=pass; dkim=pass; dmarc=pass\n"
            "Message-ID: <1@example.com>\n"
            'Content-Type: text/html; charset="utf-8"\n'
            "\n"
            "<html><body>Hi​ there"
            '<div style="display:none">verify your account</div>'
            "</body></html>\n"
        )
        path = _write_eml(eml)
        try:
            findings, info, decoded, pp, pp_flagged = pa.analyze(path)
        finally:
            os.remove(path)
        descs = _descs(findings)
        self.assertIn("hidden (css) text", descs)
        self.assertIn("zero-width", descs)

    def test_short_hidden_preheader_does_not_score(self):
        # Legit marketing preheaders are hidden but carry no lure phrase.
        eml = (
            "From: Alice <alice@example.com>\n"
            "Subject: newsletter\n"
            "Authentication-Results: mx.test; spf=pass; dkim=pass; dmarc=pass\n"
            "Message-ID: <1@example.com>\n"
            "Content-Type: text/html\n"
            "\n"
            "<html><body>"
            '<div style="display:none">This week at our company</div>'
            "Welcome to our newsletter.</body></html>\n"
        )
        path = _write_eml(eml)
        try:
            findings, info, decoded, pp, pp_flagged = pa.analyze(path)
        finally:
            os.remove(path)
        self.assertEqual(sum(w for w, _ in findings), 0)


class TyposquatLinkTests(unittest.TestCase):
    def test_typosquat_link_in_body_is_flagged(self):
        eml = (
            "From: Alice <alice@example.com>\n"
            "Subject: notice\n"
            "Authentication-Results: mx.test; spf=pass; dkim=pass; dmarc=pass\n"
            "Message-ID: <1@example.com>\n"
            "Content-Type: text/html\n"
            "\n"
            '<html><body><a href="https://paypa1.com/login">click</a>'
            "</body></html>\n"
        )
        path = _write_eml(eml)
        try:
            findings, info, decoded, pp, pp_flagged = pa.analyze(path)
        finally:
            os.remove(path)
        self.assertIn("imitates 'paypal.com'", _descs(findings))


if __name__ == "__main__":
    unittest.main()
