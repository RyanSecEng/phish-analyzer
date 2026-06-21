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
            findings, context, info, decoded, pp, pp_flagged = pa.analyze(path)
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
            findings, context, info, decoded, pp, pp_flagged = pa.analyze(path)
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
            findings, context, info, decoded, pp, pp_flagged = pa.analyze(path)
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
            findings, context, info, decoded, pp, pp_flagged = pa.analyze(path)
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
            findings, context, info, decoded, pp, pp_flagged = pa.analyze(path)
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
            findings, context, info, decoded, pp, pp_flagged = pa.analyze(path)
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
            findings, context, info, decoded, pp, pp_flagged = pa.analyze(path)
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
            findings, context, info, decoded, pp, pp_flagged = pa.analyze(path)
        finally:
            os.remove(path)
        self.assertIn("imitates 'paypal.com'", _descs(findings))


def _analyze(eml):
    """Analyze an .eml string and return the full result tuple."""
    path = _write_eml(eml)
    try:
        return pa.analyze(path)
    finally:
        os.remove(path)


class GetDomainSpoofTests(unittest.TestCase):
    def test_uses_real_address_not_display_name(self):
        # An '@domain' planted in the display name must not be read as the sender.
        self.assertEqual(
            pa.get_domain('"billing@paypal.com" <real@evil.ru>'), "evil.ru")

    def test_plain_address(self):
        self.assertEqual(pa.get_domain("Bob <bob@Example.COM>"), "example.com")


class DisplayNameSpoofTests(unittest.TestCase):
    def test_address_in_display_name_mismatch_is_flagged(self):
        eml = (
            'From: "billing@paypal.com" <attacker@scam-domain.tld>\n'
            "Subject: hello\n"
            "Authentication-Results: gw.test; dmarc=fail\n"
            "Content-Type: text/plain\n\n"
            "Hi.\n"
        )
        findings, _ctx, _info, _dec, _pp, _ppf = _analyze(eml)
        self.assertIn("display name claims 'paypal.com'", _descs(findings))


class SenderLookalikeTests(unittest.TestCase):
    def test_sender_domain_typosquat_is_flagged(self):
        eml = (
            "From: PayPal <service@paypa1.com>\n"
            "Subject: notice\n"
            "Authentication-Results: gw.test; spf=pass; dkim=pass; dmarc=pass\n"
            "Content-Type: text/plain\n\n"
            "Hello.\n"
        )
        findings, _ctx, _info, _dec, _pp, _ppf = _analyze(eml)
        # Hard signal: a DMARC pass must not suppress it.
        self.assertIn("imitates 'paypal.com'", _descs(findings))


class AuthTrustTests(unittest.TestCase):
    def test_forged_lower_authresults_does_not_grant_trust(self):
        # Top (trusted) header fails; a forged lower header claims pass. The
        # forged pass must NOT move soft language signals into context.
        eml = (
            "From: Account Team <noreply@unrelated-domain.example>\n"
            "Subject: please verify your account\n"
            "Authentication-Results: gw.mycorp.test; dmarc=fail\n"
            "Authentication-Results: attacker-supplied; dmarc=pass\n"
            "Content-Type: text/html\n\n"
            "<html><body>Dear user, please verify your account."
            '<a href="https://paypa1.com/login">click</a></body></html>\n'
        )
        findings, _ctx, info, _dec, _pp, _ppf = _analyze(eml)
        descs = _descs(findings)
        self.assertIn("imitates 'paypal.com'", descs)        # hard signal present
        self.assertIn("verify your account", descs)          # soft, still SCORED
        self.assertTrue(any("not treated as trusted" in i for i in info))

    def test_top_header_pass_is_trusted(self):
        eml = (
            "From: News <news@example.com>\n"
            "Subject: please verify your account now\n"
            "Authentication-Results: gw.mycorp.test; dmarc=pass\n"
            "Content-Type: text/plain\n\n"
            "Dear user, please verify your account.\n"
        )
        findings, context, _info, _dec, _pp, _ppf = _analyze(eml)
        # No hard signal + trusted => language signals parked in context, score 0.
        self.assertEqual(sum(w for w, _ in findings), 0)
        self.assertTrue(context)


class HeaderMismatchTests(unittest.TestCase):
    def test_returnpath_mismatch_not_scored_when_dmarc_passes(self):
        eml = (
            "From: News <news@example.com>\n"
            "Return-Path: <bounce@example.net>\n"
            "Subject: Weekly update\n"
            "Authentication-Results: gw.test; spf=pass; dkim=pass; dmarc=pass\n"
            "Message-ID: <1@example.com>\n"
            "Content-Type: text/plain\n\n"
            "Here is your weekly update.\n"
        )
        findings, _ctx, _info, _dec, _pp, _ppf = _analyze(eml)
        self.assertEqual(sum(w for w, _ in findings), 0)

    def test_replyto_to_freemail_is_hard_even_with_dmarc_pass(self):
        eml = (
            "From: CEO <ceo@company-corp.example>\n"
            "Reply-To: ceo.personal@gmail.com\n"
            "Subject: quick task\n"
            "Authentication-Results: gw.test; spf=pass; dkim=pass; dmarc=pass\n"
            "Content-Type: text/plain\n\n"
            "Are you at your desk?\n"
        )
        findings, _ctx, _info, _dec, _pp, _ppf = _analyze(eml)
        self.assertIn("reply-to points to an unrelated address", _descs(findings))


class HtmlAttachmentTests(unittest.TestCase):
    def test_html_attachment_is_flagged(self):
        eml = (
            "From: Alice <alice@example.com>\n"
            "Subject: invoice\n"
            "Authentication-Results: gw.test; dmarc=pass\n"
            'Content-Type: multipart/mixed; boundary="b"\n\n'
            "--b\n"
            "Content-Type: text/plain\n\n"
            "See attached.\n"
            "--b\n"
            "Content-Type: text/html\n"
            'Content-Disposition: attachment; filename="invoice.html"\n\n'
            "<html><body>login here</body></html>\n"
            "--b--\n"
        )
        findings, _ctx, _info, _dec, _pp, _ppf = _analyze(eml)
        self.assertIn("html/script attachment", _descs(findings))


class HtmlLinkTrickTests(unittest.TestCase):
    def test_external_form_action_is_flagged(self):
        eml = (
            "From: Alice <alice@example.com>\n"
            "Subject: form\n"
            "Authentication-Results: gw.test; dmarc=pass\n"
            "Content-Type: text/html\n\n"
            '<html><body><form action="https://harvest.evil-site.example/login">'
            '<input name="pw"></form></body></html>\n'
        )
        findings, _ctx, _info, _dec, _pp, _ppf = _analyze(eml)
        self.assertIn("form in the email submits to an external domain",
                      _descs(findings))

    def test_meta_refresh_is_flagged(self):
        eml = (
            "From: Alice <alice@example.com>\n"
            "Subject: redirect\n"
            "Authentication-Results: gw.test; dmarc=pass\n"
            "Content-Type: text/html\n\n"
            '<html><head><meta http-equiv="refresh" '
            'content="0;url=https://go.evil-site.example/x"></head>'
            "<body>hi</body></html>\n"
        )
        findings, _ctx, _info, _dec, _pp, _ppf = _analyze(eml)
        self.assertIn("auto-redirect (meta refresh)", _descs(findings))

    def test_javascript_href_is_flagged(self):
        eml = (
            "From: Alice <alice@example.com>\n"
            "Subject: js\n"
            "Authentication-Results: gw.test; dmarc=pass\n"
            "Content-Type: text/html\n\n"
            '<html><body><a href="javascript:steal()">click</a></body></html>\n'
        )
        findings, _ctx, _info, _dec, _pp, _ppf = _analyze(eml)
        self.assertIn("'javascript:' uri", _descs(findings))


class ReportSmokeTests(unittest.TestCase):
    """Guards the crash class where analyze()/report() signatures drift apart."""
    def _render(self, eml):
        import contextlib
        import io
        result = _analyze(eml)
        self.assertEqual(len(result), 6)  # report() unpacks exactly six values
        findings, context, info, decoded, pp, pp_flagged = result
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            pa.report(findings, context, info, decoded, pp, pp_flagged, quiet=True)
            pa.report(findings, context, info, decoded, pp, pp_flagged)
            pa.report(findings, context, info, decoded, pp, pp_flagged, verbose=True)
        return buf.getvalue()

    def test_report_renders_clean_mail(self):
        out = self._render(
            "From: Alice <alice@example.com>\n"
            "Subject: lunch\n"
            "Authentication-Results: gw.test; dmarc=pass\n"
            "Content-Type: text/plain\n\nHi Bob.\n")
        self.assertIn("RISK SCORE", out)

    def test_report_renders_phish_with_context(self):
        out = self._render(
            "From: IT Security <x@gmail.com>\n"
            "Subject: urgent verify your account\n"
            "Authentication-Results: gw.test; dmarc=fail\n"
            "Content-Type: text/html\n\n"
            '<html><body>Dear user<a href="https://paypa1.com">paypal.com</a>'
            "</body></html>\n")
        self.assertIn("RISK SCORE", out)
        self.assertIn("SIGNALS", out)


class VerdictTierTests(unittest.TestCase):
    def test_tiers(self):
        self.assertEqual(pa.verdict_for(0)[0].split()[0], "MINIMAL")
        self.assertEqual(pa.verdict_for(2)[0].split()[0], "LOW")
        self.assertEqual(pa.verdict_for(4)[0].split()[0], "MEDIUM")
        self.assertEqual(pa.verdict_for(8)[0].split()[0], "HIGH")


class SignalGroupTests(unittest.TestCase):
    def test_buckets(self):
        cases = {
            "SPF failed": "Authentication",
            "DMARC failed": "Authentication",
            "Reply-To points to an unrelated address (gmail.com) while From is x":
                "Sender / headers",
            "Sender domain 'paypa1.com' imitates 'paypal.com' (typosquat)":
                "Sender / headers",
            "Link domain 'x.tk' is on the known-bad list": "Links",
            "Form in the email submits to an external domain: 'evil.ru'": "Links",
            "Dangerous attachment type (.exe): 'x.exe'": "Attachments",
            "Credential-harvesting phrase: 'verify your account'": "Content",
        }
        for desc, group in cases.items():
            self.assertEqual(pa._signal_group(desc), group, desc)


class ReportLayoutTests(unittest.TestCase):
    def test_verdict_heading_and_groups_render(self):
        import contextlib
        import io
        result = _analyze(
            "From: IT Security <x@gmail.com>\n"
            "Subject: urgent verify your account\n"
            "Authentication-Results: gw.test; spf=fail; dmarc=fail\n"
            "Content-Type: text/html\n\n"
            '<html><body>Dear user'
            '<a href="https://paypa1.com">paypal.com</a></body></html>\n')
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            pa.report(*result)
        out = buf.getvalue()
        self.assertIn("VERDICT", out)
        self.assertIn("SIGNALS", out)
        self.assertIn("Links", out)        # group heading


class BatchTests(unittest.TestCase):
    def test_gather_targets_expands_dir_to_eml_only(self):
        d = tempfile.mkdtemp()
        for fn in ("a.eml", "b.eml", "notes.txt"):
            with open(os.path.join(d, fn), "w", encoding="utf-8") as fh:
                fh.write("x")
        targets = pa._gather_targets([d])
        self.assertEqual([os.path.basename(t) for t in targets], ["a.eml", "b.eml"])

    def test_summary_row_ok_and_error(self):
        result = _analyze(
            "From: Alice <alice@example.com>\n"
            "Subject: hi\n"
            "Authentication-Results: gw.test; dmarc=pass\n"
            "Content-Type: text/plain\n\nHi.\n")
        ok = pa._summary_row("/tmp/clean.eml", result, None)
        self.assertIn("MINIMAL", ok)
        self.assertIn("clean.eml", ok)
        err = pa._summary_row("/tmp/bad.eml", None, "boom")
        self.assertIn("ERROR", err)
        self.assertIn("boom", err)


def _all_descs(findings, context):
    return (_descs(findings) + " | " + _descs(context)).lower()


class HeaderObfuscationTests(unittest.TestCase):
    def test_homoglyph_in_subject_and_zero_width(self):
        eml = (
            "From: Support <help@example.com>\n"
            "Subject: Verify your Аccount now​\n"  # Cyrillic A + ZWSP
            "Authentication-Results: gw.test; dmarc=fail\n"
            "Content-Type: text/plain\n\nhi\n"
        )
        findings, _ctx, _info, _dec, _pp, _ppf = _analyze(eml)
        descs = _descs(findings)
        self.assertIn("homograph) subject", descs)
        self.assertIn("zero-width/bidi characters in the subject", descs)

    def test_mixed_script_words_helper(self):
        self.assertEqual(pa.mixed_script_words("Аpple"), ["Аpple"])
        self.assertEqual(pa.mixed_script_words("Ivan Smith"), [])


class OriginatingHopTests(unittest.TestCase):
    def test_reads_past_proofpoint(self):
        received = [
            "from mx.recipient.com by mail.recipient.com",
            "from mx1.pphosted.com (mx1.pphosted.com [205.220.165.32]) "
            "by mail.recipient.com",
            "from evil-sender.ru (evil-sender.ru [203.0.113.66]) by mx1.pphosted.com",
        ]
        self.assertEqual(pa.originating_hop(received),
                         ("evil-sender.ru", "203.0.113.66"))

    def test_private_ip(self):
        for ip in ("10.0.0.1", "192.168.1.1", "127.0.0.1", "172.16.5.5"):
            self.assertTrue(pa._is_private_ip(ip), ip)
        for ip in ("203.0.113.66", "8.8.8.8"):
            self.assertFalse(pa._is_private_ip(ip), ip)


class DkimFallbackTests(unittest.TestCase):
    def _msg(self, with_pp):
        return (
            "DKIM-Signature: v=1; a=rsa-sha256; d=unrelated-signer.net; s=k1\n"
            + ("X-Proofpoint-Virus-Version: vendor=baseline\n" if with_pp else "")
            + "From: Billing <ar@company-corp.com>\n"
            "Subject: hello\n"
            "Content-Type: text/plain\n\nhi\n"
        )

    def test_misaligned_dkim_flagged_without_proofpoint(self):
        findings, context, _info, _dec, _pp, _ppf = _analyze(self._msg(False))
        self.assertIn("dkim signing domain", _all_descs(findings, context))

    def test_dkim_not_scored_under_proofpoint(self):
        findings, context, info, _dec, _pp, _ppf = _analyze(self._msg(True))
        self.assertNotIn("does not align", _all_descs(findings, context))
        self.assertTrue(any("dkim-signature d=" in i.lower() for i in info))


class DateSanityTests(unittest.TestCase):
    def test_future_date_flagged(self):
        eml = (
            "From: a <a@example.com>\n"
            "Subject: hi\n"
            "Date: Wed, 01 Jan 2099 00:00:00 +0000\n"
            "Content-Type: text/plain\n\nhi\n"
        )
        findings, context, _info, _dec, _pp, _ppf = _analyze(eml)
        self.assertIn("date header is in the future", _all_descs(findings, context))


class FuzzTests(unittest.TestCase):
    """A security tool must not crash on hostile input."""
    def _run(self, raw):
        import contextlib
        import io
        fd, path = tempfile.mkstemp(suffix=".eml")
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
        try:
            result = pa.analyze(path)
            self.assertEqual(len(result), 6)
            with contextlib.redirect_stdout(io.StringIO()):
                pa.report(*result)
        finally:
            os.remove(path)

    def test_malformed_inputs_do_not_crash(self):
        cases = [
            b"",
            b"\x00\x01\x02\x03 not an email at all",
            b"From: a@b.com\nSubject: x\n\n" + b"A" * 10000,
            ("From: a@b.com\nContent-Type: multipart/mixed; boundary=b\n\n"
             "--b\n" * 40).encode(),
            ("From: a@b.com\nContent-Type: text/html\n\n"
             + "<div>" * 1000 + "hi").encode(),
            ("From: a@b.com\nContent-Type: text/html\n\n<a href="
             + "javascript:" + "x" * 5000 + ">y</a>").encode(),
            ("Received: " + "from a.b.com " * 500 + "\nFrom: a@b.com\n\nhi").encode(),
            b"Subject: =?utf-8?B?////?=\nFrom: a@b.com\n\nhi",
        ]
        for raw in cases:
            self._run(raw)


class LinkFlagTests(unittest.TestCase):
    def test_implicated_link_marked_benign_not(self):
        import contextlib
        import io
        result = _analyze(
            "From: a <a@example.com>\n"
            "Subject: hi\n"
            "Authentication-Results: gw.test; dmarc=pass\n"
            "Content-Type: text/html\n\n"
            '<html><body>'
            '<a href="https://paypa1.com/login">x</a>'
            '<a href="https://track.mailchimp.com/o">y</a>'
            "</body></html>\n")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            pa.report(*result, raw=True)  # raw so the literal domains are present
        links_block = buf.getvalue().split("LINKS (decoded)")[1].split("SIGNALS")[0]
        # The typosquat link is flagged; the ESP tracker is not.
        self.assertIn("(!)", links_block)
        for line in links_block.splitlines():
            if "paypa1.com" in line:
                self.assertIn("(!)", line)
            if "mailchimp.com" in line:
                self.assertNotIn("(!)", line)


class SenderAuthTests(unittest.TestCase):
    def test_auth_status_helper(self):
        self.assertEqual(pa._auth_status('dmarc=pass', 'dmarc=pass', False, '')[0],
                         'PASS')
        self.assertEqual(pa._auth_status('', 'dmarc=fail', False, '')[0], 'FAIL')
        self.assertEqual(pa._auth_status('', 'spf=fail', False, '')[0], 'FAIL')
        # Proofpoint makes raw auth unreliable, so never a hard FAIL verdict.
        self.assertEqual(pa._auth_status('', 'dmarc=fail', True, '')[0], 'UNKNOWN')
        self.assertEqual(pa._auth_status('', '', False, '')[0], 'UNKNOWN')

    def test_verdict_line_in_info(self):
        spoof = _analyze("From: IT <it@bank.com>\nSubject: hi\n"
                         "Authentication-Results: gw.test; dmarc=fail\n"
                         "Content-Type: text/plain\n\nhi\n")[2]
        self.assertTrue(any(i.startswith("Sender authentication: FAIL")
                            for i in spoof))
        clean = _analyze("From: a <a@example.com>\nSubject: hi\n"
                         "Authentication-Results: gw.test; dmarc=pass\n"
                         "Content-Type: text/plain\n\nhi\n")[2]
        self.assertTrue(any(i.startswith("Sender authentication: PASS")
                            for i in clean))

    def test_multiple_from_addresses_flagged(self):
        findings, context, _i, _d, _p, _pf = _analyze(
            "From: a@example.com, b@evil.ru\nSubject: hi\n"
            "Authentication-Results: gw.test; dmarc=fail\n"
            "Content-Type: text/plain\n\nhi\n")
        self.assertIn("from header lists 2 addresses", _all_descs(findings, context))

    def test_received_spf_fallback_when_no_authresults(self):
        findings, context, info, _d, _p, _pf = _analyze(
            "From: a <a@example.com>\nReceived-SPF: fail (bad)\nSubject: hi\n"
            "Content-Type: text/plain\n\nhi\n")
        self.assertIn("received-spf: fail", _all_descs(findings, context))
        self.assertTrue(any("Received-SPF=fail" in i for i in info))


class DefangTests(unittest.TestCase):
    def test_defang_helper(self):
        self.assertEqual(pa.defang("https://evil.com/a"), "hxxps://evil[.]com/a")

    def test_links_defanged_by_default_raw_optout(self):
        import contextlib
        import io
        result = _analyze(
            "From: a <a@example.com>\n"
            "Subject: hi\n"
            "Authentication-Results: gw.test; dmarc=pass\n"
            "Content-Type: text/html\n\n"
            '<html><body><a href="https://evil-site.example/x">y</a></body></html>\n')

        def render(**kw):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                pa.report(*result, **kw)
            return buf.getvalue().split("LINKS (decoded)")[1].split("SIGNALS")[0]

        default = render()
        self.assertIn("hxxps://evil-site[.]example", default)
        self.assertNotIn("https://evil-site.example", default)

        raw = render(raw=True)
        self.assertIn("https://evil-site.example", raw)


class ColorInfoTests(unittest.TestCase):
    def test_noop_when_color_disabled(self):
        # COLOR_ENABLED is False under test (stdout is not a tty), so the helper
        # must return the line untouched.
        for line in ("Proofpoint in path: YES",
                     "Originating sender: host [1.2.3.4]",
                     "[note] something",
                     "From:        a@b.com"):
            self.assertEqual(pa._color_info(line), line)


class PdfActiveContentTests(unittest.TestCase):
    def _eml_with_pdf(self, pdf_bytes):
        import base64
        b64 = base64.b64encode(pdf_bytes).decode()
        return (
            "From: a <a@example.com>\n"
            "Subject: invoice\n"
            "Authentication-Results: gw.test; dmarc=pass\n"
            'Content-Type: multipart/mixed; boundary="b"\n\n'
            "--b\nContent-Type: text/plain\n\nsee attached\n"
            "--b\n"
            "Content-Type: application/pdf\n"
            'Content-Disposition: attachment; filename="invoice.pdf"\n'
            "Content-Transfer-Encoding: base64\n\n" + b64 + "\n--b--\n")

    def test_active_content_flagged_strong(self):
        pdf = (b"%PDF-1.4\n1 0 obj<< /OpenAction << /S /JavaScript "
               b"/JS (app.alert('x')) >> >>\n%%EOF\n")
        findings, _c, _i, _d, _p, _pf = _analyze(self._eml_with_pdf(pdf))
        self.assertIn("pdf attachment has active content", _descs(findings))
        self.assertTrue(any(w == 3 and "active content" in d for w, d in findings))

    def test_benign_pdf_not_flagged(self):
        pdf = b"%PDF-1.4\n1 0 obj<< /Type /Catalog >>\ntrailer\n%%EOF\n"
        findings, _c, _i, _d, _p, _pf = _analyze(self._eml_with_pdf(pdf))
        self.assertNotIn("active content", _descs(findings))


class CliTests(unittest.TestCase):
    def _run_main(self, argv):
        import contextlib
        import io
        import sys
        buf = io.StringIO()
        old = sys.argv
        sys.argv = ["phish-analyzer.py"] + argv
        try:
            with contextlib.redirect_stdout(buf):
                with self.assertRaises(SystemExit) as cm:
                    pa.main()
            return cm.exception.code, buf.getvalue()
        finally:
            sys.argv = old

    def test_help_exits_zero(self):
        code, out = self._run_main(["--help"])
        self.assertEqual(code, 0)
        self.assertIn("--no-color", out)
        self.assertIn("Examples:", out)

    def test_unknown_flag_errors(self):
        code, out = self._run_main(["--bogus"])
        self.assertEqual(code, 1)
        self.assertIn("Unknown option", out)

    def test_no_args_shows_usage(self):
        code, out = self._run_main([])
        self.assertEqual(code, 1)
        self.assertIn("Usage:", out)


if __name__ == "__main__":
    unittest.main()
