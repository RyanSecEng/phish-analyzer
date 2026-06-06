"""
phish-analyzer.py — parses a saved email and scores it for phishing signals.

PROOFPOINT-AWARE + CONTENT ANALYSIS (v3):

Header / auth (strongest, deterministic signals):
  - Detects Proofpoint in the mail path.
  - Decodes URL Defense links (v2/v3) to reveal the REAL destination.
  - SPF/DKIM/DMARC failures scored LOW-confidence when Proofpoint is present
    (URL rewriting breaks DKIM; relay hop breaks SPF/DMARC on clean mail).
  - Reads ALL Authentication-Results headers, not just the first.
  - Uses Proofpoint's own X-Proofpoint verdict as a primary signal.
  - Compares domains at the registrable (eTLD+1) level using a bundled Public
    Suffix List, so Reply-To/Return-Path/link mismatches reason about real
    organizational boundaries (e.g. distinguishes co.uk second-level domains).

Content (softer signals — see the note at the bottom of the output):
  - Link TEXT vs actual HREF mismatch (e.g. shows paypal.com, goes to evil.ru).
  - Credential-harvesting phrases ("verify your account", "confirm password").
  - Generic greetings ("Dear Customer" instead of your name).
  - Urgency/pressure language in the body (not just the subject).

TRIAGE AID, not a verdict. A human analyst makes the final call.
Runs fully local. Standard library only.

Usage:
  python3 phish-analyzer.py <email.eml>
"""
import email
import os
import re
import sys
import urllib.parse
from email import policy
from html.parser import HTMLParser

# Refuse to load absurdly large files — a multi-GB or MIME-bomb .eml would
# otherwise exhaust memory since the whole file and every body part are read in.
MAX_FILE_BYTES = 25 * 1024 * 1024  # 25 MB

FREEMAIL = {'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
            'aol.com', 'icloud.com', 'proton.me', 'protonmail.com'}

URGENCY = ['verify', 'suspend', 'urgent', 'password', 'expire', 'locked',
           'unusual activity', 'confirm your', 'account will', 'immediately',
           'payment', 'invoice', 'wire transfer', 'gift card', 'action required']

IMPERSONATION_TERMS = ['support', 'security', 'helpdesk', 'help desk', 'it ',
                       'admin', 'microsoft', 'office365', 'docusign', 'paypal',
                       'amazon', 'bank', 'ceo', 'hr ', 'payroll', 'service desk']

GENERIC_GREETINGS = ['dear customer', 'dear user', 'dear valued customer',
                     'dear account holder', 'dear member', 'dear sir or madam',
                     'dear sir/madam', 'valued customer', 'dear client',
                     'attention user', 'dear email user', 'dear cardholder']

CRED_HARVEST = ['confirm your password', 'verify your account', 'update your payment',
                'validate your account', 'confirm your identity', 'verify your identity',
                'click here to verify', 'log in to confirm', 'update your billing',
                'update your account', 'verify your email', 'confirm your account',
                'unlock your account', 'sign in to verify', 'reconfirm your',
                're-enter your', 'update your credentials']

PP_BAD_TOKENS = ['rule=spam', 'rule=phish', 'rule=malware', 'rule=impostor',
                 'classifier=phish', 'classifier=malware', 'definitive=phish']

SKIP_TAGS = {'script', 'style'}

# Exclude control bytes (incl. the ESC byte 0x1b) so terminal escape sequences
# can't be smuggled into a "URL" and later printed unsanitized.
URL_RE = re.compile(r'https?://[^\s"\'<>)\x00-\x1f\x7f]+', re.IGNORECASE)
DOMAIN_RE = re.compile(r'@([A-Za-z0-9.-]+\.[A-Za-z]{2,})')
TEXT_DOMAIN_RE = re.compile(
    r'\b([a-z0-9][a-z0-9-]+\.(?:com|net|org|io|gov|edu|co|us|info|biz|ru|cn|xyz|top|live|app'
    r'|click|work|online|shop|site|win|club|bond|digital|link|email|tech|store|space))\b')

# Matches -XX where XX are hex digits — used to reverse Proofpoint v2's %→- substitution
# without corrupting literal hyphens (e.g. my-company.com stays intact).
_PP_V2_HEX_RE = re.compile(r'-([0-9A-Fa-f]{2})')

# ANSI escape sequences that could manipulate terminal output when decoded URLs are printed.
_ANSI_RE = re.compile(r'\x1b(?:\[[0-9;]*[a-zA-Z]|\].*?(?:\x07|\x1b\\))')


def sanitize(s):
    """Strip ANSI escape sequences and non-printable characters."""
    s = _ANSI_RE.sub('', s)
    return ''.join(c if c.isprintable() else '?' for c in s)


def _normalize(name):
    """Lowercase a domain/rule and IDNA-encode any non-ASCII labels to punycode,
    so unicode PSL entries and xn-- hostnames compare on the same footing."""
    out = []
    for lab in name.split('.'):
        if lab and lab != '*' and not lab.isascii():
            try:
                lab = lab.encode('idna').decode('ascii')
            except Exception:
                pass
        out.append(lab.lower())
    return '.'.join(out)


def _init_psl(path):
    """Load the bundled Public Suffix List. Returns (rules, exceptions, warning).

    Never raises: if the .dat file is missing or unreadable, returns empty sets
    plus a warning string so the tool degrades to a last-two-labels heuristic
    instead of hard-failing.
    """
    rules, exceptions = set(), set()
    try:
        with open(path, encoding='utf-8') as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith('//'):
                    continue
                if line.startswith('!'):
                    exceptions.add(_normalize(line[1:]))
                else:
                    rules.add(_normalize(line))
    except OSError as exc:
        return set(), set(), (
            f"[WARN] Public Suffix List unavailable ({exc}); "
            "domain comparison fell back to a simple last-two-labels heuristic.")
    return rules, exceptions, None


_PSL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         'public_suffix_list.dat')
_PSL_RULES, _PSL_EXCEPTIONS, PSL_WARNING = _init_psl(_PSL_PATH)


def registrable_domain(host):
    """Return the registrable domain (eTLD+1) of a host, per the Public Suffix
    List — e.g. 'a.b.example.co.uk' -> 'example.co.uk'. Returns '' if the host is
    itself a public suffix, and falls back to the last two labels if the PSL
    failed to load."""
    host = host.strip().strip('.')
    if not host:
        return ''
    if not _PSL_RULES:
        labels = host.lower().split('.')
        return '.'.join(labels[-2:]) if len(labels) >= 2 else host.lower()

    labels = _normalize(host).split('.')
    n = len(labels)

    # Exception rules (e.g. !www.ck) take priority over everything else.
    for i in range(n):
        if '.'.join(labels[i:]) in _PSL_EXCEPTIONS:
            # Public suffix is the matched rule minus its leftmost label;
            # registrable domain is that suffix plus one more label.
            return '.'.join(labels[i:])

    # Otherwise the longest matching normal or wildcard rule wins.
    best = 0
    for i in range(n):
        seg = labels[i:]
        if '.'.join(seg) in _PSL_RULES:
            best = max(best, len(seg))
        elif '.'.join(['*'] + seg[1:]) in _PSL_RULES:
            best = max(best, len(seg))
    if best == 0:
        best = 1  # default "*" rule: the public suffix is the rightmost label
    if best >= n:
        return ''  # host is itself a public suffix (no registrable part)
    return '.'.join(labels[n - best - 1:])


def same_domain_family(a, b):
    """True if a and b share the same registrable domain (eTLD+1).

    This is the organizational-identity test behind every domain-mismatch
    signal: 'mail.corp.com' and 'corp.com' match; 'corp.com' and a lookalike
    'corp.com.evil.ru' do not."""
    if not a or not b:
        return False
    ra, rb = registrable_domain(a), registrable_domain(b)
    return bool(ra) and ra == rb


def get_domain(addr):
    if not addr:
        return ''
    m = DOMAIN_RE.search(addr)
    return m.group(1).lower() if m else ''


def dest_domain(url):
    """Best-effort host for a (possibly scheme-less) URL.

    Proofpoint v3 decoding can yield a URL without an http(s):// scheme, in
    which case urlparse() puts everything in .path and .netloc is empty. Fall
    back to the leading path segment so destination checks still work.
    """
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname  # already lowercased, strips any userinfo and :port
    if not host and parsed.path:
        # Scheme-less (often from v3 decoding): take the leading path segment,
        # dropping any userinfo (@) or port (:) that may ride along.
        host = parsed.path.split('/', 1)[0].split('@')[-1].split(':', 1)[0]
    return (host or '').lower()


def decode_proofpoint(url):
    """Return the real destination behind a Proofpoint URL Defense link."""
    if 'urldefense.proofpoint.com/v2/' in url or 'urldefense.com/v2/url?' in url:
        try:
            q = urllib.parse.urlparse(url).query
            u = urllib.parse.parse_qs(q).get('u', [''])[0]
            # Proofpoint v2 encodes % as - and / as _.  Reverse only the -XX sequences
            # (which represent %XX percent-encoded chars) so literal hyphens in domain
            # names and paths are not corrupted.
            u = _PP_V2_HEX_RE.sub(r'%\1', u)
            u = u.replace('_', '/')
            return urllib.parse.unquote(u)
        except Exception:
            return url
    if 'urldefense.com/v3/' in url or 'urldefense.us/v3/' in url:
        m = re.search(r'/v3/__(.+?)__;', url)
        if m:
            real = m.group(1)
            if '*' in real:
                real += '  [* = encoded chars, verify manually]'
            return real
    return url


def proofpoint_in_path(msg):
    for h in msg.keys():
        if h.lower().startswith('x-proofpoint'):
            return True
    received = ' '.join(str(v) for v in msg.get_all('Received', [])).lower()
    return 'pphosted.com' in received or 'proofpoint' in received


class HtmlAnalyzer(HTMLParser):
    """Pulls anchor links (href + displayed text) and visible text from HTML."""
    def __init__(self):
        super().__init__()
        self.links = []           # (href, displayed_text)
        self.text_parts = []
        self._href = None
        self._buf = []
        self._skip = 0            # depth counter for <script>/<style> blocks

    def handle_starttag(self, tag, attrs):
        if tag in SKIP_TAGS:
            self._skip += 1
            return
        if tag == 'a' and not self._skip:
            self._href = dict(attrs).get('href')
            self._buf = []

    def handle_data(self, data):
        if self._skip:
            return
        self.text_parts.append(data)
        if self._href is not None:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag in SKIP_TAGS:
            if self._skip:
                self._skip -= 1
            return
        if tag == 'a' and self._href is not None:
            self.links.append((self._href, ''.join(self._buf).strip()))
            self._href = None
            self._buf = []

    def visible_text(self):
        return ' '.join(self.text_parts)


def domain_in_text(text):
    m = TEXT_DOMAIN_RE.search(text.lower())
    return m.group(1) if m else ''


def analyze(path):
    size = os.path.getsize(path)
    if size > MAX_FILE_BYTES:
        raise ValueError(f"file too large to analyze ({size} bytes, limit {MAX_FILE_BYTES})")
    with open(path, 'rb') as fh:
        msg = email.message_from_binary_file(fh, policy=policy.default)

    findings = []   # (weight, description)
    info = []
    if PSL_WARNING:
        info.append(PSL_WARNING)
    pp = proofpoint_in_path(msg)

    frm = str(msg.get('From', ''))
    reply_to = str(msg.get('Reply-To', ''))
    return_path = str(msg.get('Return-Path', ''))
    subject = str(msg.get('Subject', ''))
    msg_id = str(msg.get('Message-ID', ''))

    from_dom = get_domain(frm)
    reply_dom = get_domain(reply_to)
    rp_dom = get_domain(return_path)

    info.append(f"Proofpoint in path: {'YES' if pp else 'no'}")
    info.append(f"From:        {frm}")
    info.append(f"Reply-To:    {reply_to or '(none)'}")
    info.append(f"Return-Path: {return_path or '(none)'}")
    info.append(f"Subject:     {subject}")

    # ---------- HEADER / AUTH SIGNALS ----------
    auth_headers = msg.get_all('Authentication-Results', [])
    all_auth = ' '.join(str(a).lower() for a in auth_headers)
    for i, a in enumerate(auth_headers):
        info.append(f"[Auth-Results #{i+1}] {str(a)[:160]}")

    pp_flagged = False
    for h in msg.keys():
        if h.lower().startswith('x-proofpoint'):
            val = str(msg.get(h))
            info.append(f"[PPS] {h}: {val[:160]}")
            if any(tok in val.lower() for tok in PP_BAD_TOKENS):
                findings.append((4, f"Proofpoint itself flagged this message ({h})"))
                pp_flagged = True

    # Compared at the registrable-domain (eTLD+1) level, so a legitimate
    # subdomain split like reply at mail.corp.com vs From corp.com is not flagged.
    if reply_dom and from_dom and not same_domain_family(reply_dom, from_dom):
        findings.append((2, f"Reply-To domain ({reply_dom}) != From domain ({from_dom})"))
    if rp_dom and from_dom and not same_domain_family(rp_dom, from_dom):
        findings.append((2, f"Return-Path domain ({rp_dom}) != From domain ({from_dom})"))

    # Only check display name when a distinct display name component is present;
    # bare addresses like support@company.com have no display name to evaluate.
    if '<' in frm:
        display = frm.split('<')[0].strip().lower()
        # Match whole words only so short terms ('it', 'hr') don't fire inside
        # unrelated words ('Smith', 'unit').
        matched = [t for t in (term.strip() for term in IMPERSONATION_TERMS)
                   if re.search(r'\b' + re.escape(t) + r'\b', display)]
        if matched:
            if from_dom in FREEMAIL:
                findings.append((3, f"Authority/brand display name from freemail ({from_dom})"))
            else:
                for term in matched:
                    if term not in from_dom:
                        findings.append((3, f"Display name implies '{term}' but domain is {from_dom}"))
                        break

    if auth_headers:
        spf_w, dkim_w, dmarc_w = (1, 1, 1) if pp else (2, 2, 3)
        note = "  (LOW conf — Proofpoint may have broken this)" if pp else ""
        if 'spf=fail' in all_auth or 'spf=softfail' in all_auth:
            findings.append((spf_w, "SPF failed" + note))
        if 'dkim=fail' in all_auth:
            findings.append((dkim_w, "DKIM failed" + (
                "  (LOW conf — URL rewriting breaks DKIM body hash)" if pp else "")))
        if 'dmarc=fail' in all_auth:
            findings.append((dmarc_w, "DMARC failed" + note))
    else:
        findings.append((1, "No Authentication-Results header found"))

    mid_dom = msg_id.split('@')[-1].strip('>').lower() if '@' in msg_id else ''
    if mid_dom and from_dom and not same_domain_family(mid_dom, from_dom):
        findings.append((1, f"Message-ID domain ({mid_dom}) differs from From ({from_dom})"))

    subject_urgency = set()
    if any(word in subject.lower() for word in URGENCY):
        hit = next(w for w in URGENCY if w in subject.lower())
        subject_urgency = {w for w in URGENCY if w in subject.lower()}
        findings.append((1, f"Urgency/lure keyword in SUBJECT: '{hit}'"))

    # ---------- BODY EXTRACTION ----------
    text_body, html_body = '', ''
    for part in msg.walk():
        ct = part.get_content_type()
        try:
            if ct == 'text/plain':
                text_body += part.get_content()
            elif ct == 'text/html':
                html_body += part.get_content()
        except Exception as exc:
            info.append(f"[WARN] Could not decode {ct} part: {exc}")

    parser = HtmlAnalyzer()
    if html_body:
        try:
            parser.feed(html_body)
        except Exception:
            pass
    visible = (text_body + ' ' + parser.visible_text()).lower()
    raw_body = text_body + ' ' + html_body

    # ---------- LINK ANALYSIS ----------
    decoded = []
    seen_decoded = set()
    flagged_dest = set()
    for u in URL_RE.findall(raw_body):
        real = decode_proofpoint(u)
        if real not in seen_decoded:
            decoded.append(real)
            seen_decoded.add(real)
        real_dom = dest_domain(real)
        if real_dom and from_dom and not same_domain_family(from_dom, real_dom):
            if real_dom not in flagged_dest:
                findings.append((2, f"Link goes to {real_dom}, not sender domain {from_dom}"))
                flagged_dest.add(real_dom)

    # Link TEXT vs real HREF — the strongest content signal.
    seen_mismatch = set()
    for href, text in parser.links:
        real = decode_proofpoint(href)
        real_dom = dest_domain(real)
        claimed = domain_in_text(text)
        if claimed and real_dom and not same_domain_family(claimed, real_dom):
            key = (claimed, real_dom)
            if key not in seen_mismatch:
                findings.append((3, f"Link DISPLAYS '{claimed}' but actually goes to '{real_dom}'"))
                seen_mismatch.add(key)

    # ---------- CONTENT / LANGUAGE SIGNALS (softer) ----------
    for phrase in CRED_HARVEST:
        if phrase in visible:
            findings.append((2, f"Credential-harvesting phrase: '{phrase}'"))
            break
    for greet in GENERIC_GREETINGS:
        if greet in visible:
            findings.append((1, f"Generic greeting (no real name): '{greet}'"))
            break
    # Exclude words already scored via the subject to avoid double-counting.
    body_urgency = [w for w in URGENCY if w in visible and w not in subject_urgency]
    if body_urgency:
        findings.append((1, f"Urgency/pressure language in body (e.g. '{body_urgency[0]}')"))

    return findings, info, decoded, pp, pp_flagged


def report(findings, info, decoded, pp, pp_flagged):
    print("\n=== HEADER SUMMARY ===")
    for line in info:
        print("  " + sanitize(line))

    print("\n=== LINKS (Proofpoint-decoded) ===")
    if decoded:
        for d in decoded[:25]:
            print("  -> " + sanitize(d))
    else:
        print("  (no links found)")

    score = sum(w for w, _ in findings)
    print("\n=== SIGNALS ===")
    if not findings:
        print("  (no scored signals fired)")
    for w, desc in findings:
        print(f"  [+{w}] {sanitize(desc)}")

    if score >= 6:
        verdict = "HIGH — strong phishing indicators"
    elif score >= 3:
        verdict = "MEDIUM — suspicious, investigate further"
    elif score >= 1:
        verdict = "LOW — minor signals, likely benign but verify"
    else:
        verdict = "MINIMAL — no scored signals"

    print(f"\n=== RISK SCORE: {score}  ->  {verdict} ===")

    if pp:
        print("\nProofpoint detected: raw SPF/DKIM/DMARC fails scored LOW (they")
        print("break on clean mail here). " + (
            "PPS flagged this — weight heavily." if pp_flagged
            else "PPS did not flag it (context)."))
    print("\nNote: content signals (greetings, urgency, phrasing) are SOFT —")
    print("modern AI-written phishing has clean grammar and personalized")
    print("greetings. Your strongest evidence is the decoded link destinations,")
    print("link-text/href mismatches, and Proofpoint's own verdict. Triage aid")
    print("only — you make the call.")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 phish-analyzer.py <email.eml>")
        sys.exit(1)
    path = sys.argv[1]
    print(f"Analyzing {path}...")
    try:
        findings, info, decoded, pp, pp_flagged = analyze(path)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {path}")
        print("Fail loud, never fail silent.")
        sys.exit(1)
    except (OSError, ValueError) as exc:
        print(f"[ERROR] Could not read {path}: {exc}")
        sys.exit(1)
    except Exception as exc:
        print(f"[ERROR] Failed to parse email: {type(exc).__name__}: {exc}")
        sys.exit(1)
    report(findings, info, decoded, pp, pp_flagged)


if __name__ == '__main__':
    main()
