"""
phish-analyzer.py - parse a saved .eml and score it for phishing signals.

Looks at header/auth signals (Proofpoint detection, URL Defense decoding,
SPF/DKIM/DMARC in context, domain mismatches at the registrable-domain level)
and softer content signals (link text vs href, lure phrases, urgency).

A triage aid, not a verdict. Runs offline, standard library only.

Usage:
  python phish-analyzer.py [-q|--quiet] [-v|--verbose] <email.eml>
"""
import email
import hashlib
import os
import re
import sys
import unicodedata
import urllib.parse
from email import policy
from html.parser import HTMLParser

# Force UTF-8 so box-drawing glyphs survive on Windows consoles.
try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except Exception:
    pass

# Color only on a real terminal; off when piped/redirected or NO_COLOR is set.
COLOR_ENABLED = sys.stdout.isatty() and os.environ.get('NO_COLOR') is None

if COLOR_ENABLED and os.name == 'nt':
    # Turn on ANSI processing for older Windows consoles.
    try:
        import ctypes
        _k32 = ctypes.windll.kernel32
        _h = _k32.GetStdHandle(-11)
        _mode = ctypes.c_uint32()
        if _k32.GetConsoleMode(_h, ctypes.byref(_mode)):
            _k32.SetConsoleMode(_h, _mode.value | 0x0004)
    except Exception:
        COLOR_ENABLED = False

RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'
GREEN = '\033[32m'
CYAN = '\033[36m'
YELLOW = '\033[33m'
RED = '\033[31m'
BRAND = CYAN


def c(text, *codes):
    if not COLOR_ENABLED or not codes:
        return text
    return ''.join(codes) + text + RESET


BANNER = r"""
                 ____  _   _ ___ ____  _   _
                |  _ \| | | |_ _/ ___|| | | |
                | |_) | |_| || |\___ \| |_| |
                |  __/|  _  || | ___) |  _  |
                |_|   |_| |_|___|____/|_| |_|

    _     _   _     _     _     __   __ _____  _____  ____
   / \   | \ | |   / \   | |    \ \ / /|__  / | ____||  _ \
  / _ \  |  \| |  / _ \  | |     \ V /   / /  |  _|  | |_) |
 / ___ \ | |\  | / ___ \ | |___   | |   / /_  | |___ |  _ <
/_/   \_\|_| \_|/_/   \_\|_____|  |_|  /____| |_____||_| \_\

          local .eml phishing triage - runs 100% offline
"""


def print_banner():
    print(c(BANNER, BRAND, BOLD))


def _supported(ch):
    try:
        ch.encode(sys.stdout.encoding or 'ascii')
        return True
    except Exception:
        return False


_BAR_FULL = '█' if _supported('█') else '#'
_BAR_EMPTY = '░' if _supported('░') else '-'


def risk_meter(score, color, cells=10):
    filled = max(0, min(score, cells))
    bar = _BAR_FULL * filled + _BAR_EMPTY * (cells - filled)
    return c('[' + bar + ']', color)


def weight_color(w):
    if w >= 4:
        return RED
    if w == 3:
        return YELLOW
    if w == 2:
        return CYAN
    return DIM


# Cap input size; the whole file and every body part get read into memory.
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

# Brands phishing commonly imitates, used for typosquat/homoglyph comparison.
BRANDS = ['microsoft.com', 'office365.com', 'outlook.com', 'paypal.com',
          'amazon.com', 'apple.com', 'google.com', 'docusign.com',
          'dropbox.com', 'linkedin.com', 'netflix.com', 'facebook.com',
          'instagram.com', 'wellsfargo.com', 'chase.com', 'bankofamerica.com',
          'americanexpress.com', 'coinbase.com', 'adobe.com']

# Attachment extensions that run code on open, or that hide one.
DANGEROUS_EXT = {'.exe', '.scr', '.com', '.pif', '.bat', '.cmd', '.js', '.jse',
                 '.vbs', '.vbe', '.wsf', '.wsh', '.hta', '.jar', '.lnk', '.iso',
                 '.img', '.msi', '.ps1', '.reg', '.cpl', '.msc', '.gadget'}
MACRO_EXT = {'.docm', '.xlsm', '.pptm', '.dotm', '.xlam', '.xltm', '.potm'}
ARCHIVE_EXT = {'.zip', '.rar', '.7z', '.ace', '.cab', '.gz', '.tar', '.iso'}

SKIP_TAGS = {'script', 'style'}

# Void/self-closing tags never get a close tag, so we don't push them on the
# tag stack the HTML parser keeps for tracking hidden ancestors.
VOID_TAGS = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
             'link', 'meta', 'param', 'source', 'track', 'wbr'}

# Bound the tag stack so crafted, absurdly nested HTML can't blow up memory or
# CPU. Real email HTML never nests anywhere near this deep.
_MAX_NEST = 200

# Exclude control bytes (including ESC) so escape sequences can't be smuggled
# into a "URL" and printed later.
URL_RE = re.compile(r'https?://[^\s"\'<>)\x00-\x1f\x7f]+', re.IGNORECASE)
DOMAIN_RE = re.compile(r'@([A-Za-z0-9.-]+\.[A-Za-z]{2,})')
TEXT_DOMAIN_RE = re.compile(
    r'\b([a-z0-9][a-z0-9-]+\.(?:com|net|org|io|gov|edu|co|us|info|biz|ru|cn|xyz|top|live|app'
    r'|click|work|online|shop|site|win|club|bond|digital|link|email|tech|store|space))\b')

# Reverse Proofpoint v2's %->- substitution without touching literal hyphens.
_PP_V2_HEX_RE = re.compile(r'-([0-9A-Fa-f]{2})')

_ANSI_RE = re.compile(r'\x1b(?:\[[0-9;]*[a-zA-Z]|\].*?(?:\x07|\x1b\\))')

# CSS that hides an element from the reader (used for poison/keyword-stuffed text).
_HIDDEN_STYLE_RE = re.compile(
    r'display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?![.\d])'
    r'|font-size\s*:\s*0(?![.\d])|font-size\s*:\s*1px|max-height\s*:\s*0',
    re.IGNORECASE)

# Zero-width, soft-hyphen and bidi control characters that don't belong in body
# text and are used to break up words or reverse displayed text.
_ZW_RE = re.compile(
    '[­​‌‍‎‏‪-‮⁠﻿]')

# Common character swaps in typosquats, mapped back to what they imitate.
_CONFUSE_MAP = str.maketrans({'0': 'o', '1': 'l', '3': 'e', '4': 'a',
                              '5': 's', '7': 't', '$': 's', '@': 'a'})


def sanitize(s):
    """Strip ANSI escape sequences and non-printable characters."""
    s = _ANSI_RE.sub('', s)
    return ''.join(c if c.isprintable() else '?' for c in s)


def _normalize(name):
    """Lowercase a domain and punycode any non-ASCII labels, so unicode PSL
    entries and xn-- hostnames compare on the same footing."""
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
    """Load the bundled Public Suffix List into (rules, exceptions, warning).

    Never raises: a missing or unreadable file yields empty sets and a warning,
    so the tool falls back to a last-two-labels heuristic instead of dying.
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
    """Return the registrable domain (eTLD+1) of host, e.g.
    'a.b.example.co.uk' -> 'example.co.uk'. Empty string if host is itself a
    public suffix; falls back to the last two labels if the PSL didn't load."""
    host = host.strip().strip('.')
    if not host:
        return ''
    if not _PSL_RULES:
        labels = host.lower().split('.')
        return '.'.join(labels[-2:]) if len(labels) >= 2 else host.lower()

    labels = _normalize(host).split('.')
    n = len(labels)

    # Exception rules (e.g. !www.ck) win over everything else.
    for i in range(n):
        if '.'.join(labels[i:]) in _PSL_EXCEPTIONS:
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
        best = 1  # default rule: the rightmost label is the public suffix
    if best >= n:
        return ''
    return '.'.join(labels[n - best - 1:])


def same_domain_family(a, b):
    """True if a and b share the same registrable domain (eTLD+1)."""
    if not a or not b:
        return False
    ra, rb = registrable_domain(a), registrable_domain(b)
    return bool(ra) and ra == rb


def _levenshtein(a, b):
    if a == b:
        return 0
    if not a or not b:
        return len(a) or len(b)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                           prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _deconfuse(s):
    """Undo common look-alike swaps (0->o, 1->l, rn->m ...) so a disguised
    domain can be matched against the real thing it imitates."""
    return s.translate(_CONFUSE_MAP).replace('rn', 'm').replace('vv', 'w')


def typosquat_target(domain, sender_domain=''):
    """If `domain` looks like a disguised version of a known brand or of the
    sender's own domain, return the domain it imitates, else ''."""
    if not domain:
        return ''
    targets = set(BRANDS)
    if sender_domain:
        targets.add(sender_domain)
    if domain in targets:
        return ''
    dc = _deconfuse(domain)
    if dc != domain and dc in targets:
        return dc
    # One-character typo away from the actual sender is a strong, specific tell.
    if sender_domain and sender_domain != domain and len(sender_domain) >= 6:
        if _levenshtein(domain, sender_domain) == 1:
            return sender_domain
    return ''


def _label_script(label):
    """Set of script families (LATIN, CYRILLIC, ...) used by the letters in a
    single domain label."""
    scripts = set()
    for ch in label:
        if not ch.isalpha():
            continue
        try:
            scripts.add(unicodedata.name(ch).split(' ', 1)[0])
        except ValueError:
            scripts.add('?')
    return scripts


def idn_homograph(host):
    """Return labels that mix Latin with a confusable script (e.g. a Cyrillic
    'a' inside 'paypal'). Pure non-Latin IDNs are left alone; only mixed-script
    labels, which are almost always spoofing, are reported."""
    bad = []
    confusable = {'CYRILLIC', 'GREEK', 'ARMENIAN', 'CHEROKEE'}
    for label in host.split('.'):
        decoded = label
        if label.startswith('xn--'):
            try:
                decoded = label.encode('ascii').decode('idna')
            except Exception:
                decoded = label
        scripts = _label_script(decoded)
        if 'LATIN' in scripts and scripts & confusable:
            bad.append(decoded)
    return bad


def get_domain(addr):
    if not addr:
        return ''
    m = DOMAIN_RE.search(addr)
    return m.group(1).lower() if m else ''


def dest_domain(url):
    """Best-effort host for a possibly scheme-less URL. Proofpoint v3 decoding
    can drop the scheme, leaving the host in .path, so fall back to that."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    if not host and parsed.path:
        host = parsed.path.split('/', 1)[0].split('@')[-1].split(':', 1)[0]
    return (host or '').lower()


def decode_proofpoint(url):
    """Return the real destination behind a Proofpoint URL Defense link."""
    if 'urldefense.proofpoint.com/v2/' in url or 'urldefense.com/v2/url?' in url:
        try:
            q = urllib.parse.urlparse(url).query
            u = urllib.parse.parse_qs(q).get('u', [''])[0]
            # v2 encodes % as - and / as _. Only undo -XX so literal hyphens survive.
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


def _is_hidden(attrs):
    d = dict(attrs)
    if 'hidden' in d:
        return True
    return bool(_HIDDEN_STYLE_RE.search(d.get('style') or ''))


class HtmlAnalyzer(HTMLParser):
    """Pulls anchor links (href + displayed text), visible text, and any text
    that CSS hides from the reader, out of HTML."""
    def __init__(self):
        super().__init__()
        self.links = []
        self.text_parts = []
        self.hidden_parts = []
        self._href = None
        self._buf = []
        self._skip = 0
        self._stack = []    # (tag, hidden) for each open, non-void element
        self._hidden = 0    # number of open ancestors that are hidden

    def handle_starttag(self, tag, attrs):
        if tag in SKIP_TAGS:
            self._skip += 1
            return
        if tag not in VOID_TAGS and len(self._stack) < _MAX_NEST:
            hidden = _is_hidden(attrs)
            self._stack.append((tag, hidden))
            if hidden:
                self._hidden += 1
        if tag == 'a' and not self._skip:
            self._href = dict(attrs).get('href')
            self._buf = []

    def handle_data(self, data):
        if self._skip:
            return
        if self._hidden:
            self.hidden_parts.append(data)
        else:
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
        # Match the top of the stack only (O(1)); best-effort on malformed HTML,
        # but a mismatched close tag can't trigger a costly full-stack scan.
        if self._stack and self._stack[-1][0] == tag:
            _, was_hidden = self._stack.pop()
            if was_hidden:
                self._hidden -= 1

    def visible_text(self):
        return ' '.join(self.text_parts)

    def hidden_text(self):
        return ' '.join(self.hidden_parts)


def domain_in_text(text):
    m = TEXT_DOMAIN_RE.search(text.lower())
    return m.group(1) if m else ''


def attachments(msg):
    """Yield (filename, size, sha256, extensions) for each attached part.

    `extensions` is the list of trailing extensions, so a double extension like
    invoice.pdf.exe comes back as ['.pdf', '.exe'] for the caller to judge.
    """
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        fn = part.get_filename()
        if not fn and part.get_content_disposition() != 'attachment':
            continue
        payload = part.get_payload(decode=True) or b''
        name = sanitize(fn or '(unnamed)')
        exts = [e.lower() for e in re.findall(r'\.[A-Za-z0-9]{1,8}', name)][-2:]
        yield name, len(payload), hashlib.sha256(payload).hexdigest(), exts


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

    # Compare at eTLD+1 so a legit mail.corp.com vs corp.com split isn't flagged.
    if reply_dom and from_dom and not same_domain_family(reply_dom, from_dom):
        findings.append((2, f"Reply-To domain ({reply_dom}) != From domain ({from_dom})"))
    if rp_dom and from_dom and not same_domain_family(rp_dom, from_dom):
        findings.append((2, f"Return-Path domain ({rp_dom}) != From domain ({from_dom})"))

    if '<' in frm:
        display = frm.split('<')[0].strip().lower()
        # Whole-word match so short terms ('it', 'hr') don't fire inside words.
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
        note = "  (LOW conf - Proofpoint may have broken this)" if pp else ""
        if 'spf=fail' in all_auth or 'spf=softfail' in all_auth:
            findings.append((spf_w, "SPF failed" + note))
        if 'dkim=fail' in all_auth:
            findings.append((dkim_w, "DKIM failed" + (
                "  (LOW conf - URL rewriting breaks DKIM body hash)" if pp else "")))
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
    # Decode every link so the analyst sees the real destinations. We do not
    # score "link goes to a domain other than the sender" on its own: legit mail
    # routinely links to trackers, CDNs and third parties, so it just floods the
    # report with false positives. The text-vs-href mismatch below is the tell.
    decoded = []
    seen_decoded = set()
    for u in URL_RE.findall(raw_body):
        real = decode_proofpoint(u)
        if real not in seen_decoded:
            decoded.append(real)
            seen_decoded.add(real)

    # Look-alike destinations: mixed-script homographs and typosquats of the
    # sender or a known brand. These are deliberate disguises, not noise.
    from_reg = registrable_domain(from_dom) if from_dom else ''
    seen_lookalike = set()
    for real in decoded:
        host = dest_domain(real)
        if not host or host in seen_lookalike:
            continue
        for lab in idn_homograph(host):
            findings.append((3, f"Mixed-script (homograph) domain in link: '{lab}'"))
            seen_lookalike.add(host)
        reg = registrable_domain(host)
        target = typosquat_target(reg, from_reg)
        if target and host not in seen_lookalike:
            findings.append((3, f"Link domain '{reg}' imitates '{target}' (typosquat)"))
            seen_lookalike.add(host)

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

    # ---------- CONTENT / LANGUAGE SIGNALS ----------
    for phrase in CRED_HARVEST:
        if phrase in visible:
            findings.append((2, f"Credential-harvesting phrase: '{phrase}'"))
            break
    for greet in GENERIC_GREETINGS:
        if greet in visible:
            findings.append((1, f"Generic greeting (no real name): '{greet}'"))
            break
    # Skip subject words already scored above so we don't double-count.
    body_urgency = [w for w in URGENCY if w in visible and w not in subject_urgency]
    if body_urgency:
        findings.append((1, f"Urgency/pressure language in body (e.g. '{body_urgency[0]}')"))

    # CSS-hidden text. Short hidden text is usually a legit preview/preheader, so
    # only score it when it carries a lure phrase, which is a real evasion trick.
    hidden = parser.hidden_text().lower()
    hidden_hit = next((p for p in (CRED_HARVEST + URGENCY) if p in hidden), '')
    if hidden_hit:
        findings.append((2, f"Hidden (CSS) text contains a lure phrase: '{hidden_hit}'"))

    if _ZW_RE.search(raw_body):
        findings.append((1, "Zero-width or bidi control characters in body (obfuscation)"))

    # ---------- ATTACHMENTS ----------
    for name, size, digest, exts in attachments(msg):
        info.append(f"[Attachment] {name}  ({size} bytes)  sha256={digest}")
        last = exts[-1] if exts else ''
        if len(exts) >= 2 and exts[-2] not in DANGEROUS_EXT and last in DANGEROUS_EXT:
            findings.append((3, f"Misleading double extension on attachment: '{name}'"))
        elif last in DANGEROUS_EXT:
            findings.append((3, f"Dangerous attachment type ({last}): '{name}'"))
        elif last in MACRO_EXT:
            findings.append((2, f"Macro-enabled attachment ({last}): '{name}'"))
        elif last in ARCHIVE_EXT:
            findings.append((1, f"Archive attachment ({last}) may hide a payload: '{name}'"))

    return findings, info, decoded, pp, pp_flagged


def _hdr(title):
    return c(f"=== {title} ===", BRAND, BOLD)


def report(findings, info, decoded, pp, pp_flagged, quiet=False, verbose=False):
    score = sum(w for w, _ in findings)

    if score >= 6:
        verdict, vcolor = "HIGH - strong phishing indicators", RED
    elif score >= 3:
        verdict, vcolor = "MEDIUM - suspicious, investigate further", YELLOW
    elif score >= 1:
        verdict, vcolor = "LOW - minor signals, likely benign but verify", CYAN
    else:
        verdict, vcolor = "MINIMAL - no scored signals", GREEN

    meter = risk_meter(score, vcolor)
    verdict_line = (f"=== RISK SCORE: {score}  {meter}  "
                    f"{c(verdict, vcolor, BOLD)} ===")

    if quiet:
        print(verdict_line)
        return

    print("\n" + _hdr("HEADER SUMMARY"))
    for line in info:
        print("  " + sanitize(line))

    print("\n" + _hdr("LINKS (Proofpoint-decoded)"))
    if decoded:
        shown = decoded if verbose else decoded[:25]
        for d in shown:
            print("  -> " + sanitize(d))
        if not verbose and len(decoded) > 25:
            print(c(f"  ... +{len(decoded) - 25} more (use --verbose to show all)", DIM))
    else:
        print("  (no links found)")

    print("\n" + _hdr("SIGNALS"))
    if not findings:
        print("  (no scored signals fired)")
    for w, desc in findings:
        print(f"  {c(f'[+{w}]', weight_color(w), BOLD)} {sanitize(desc)}")

    print("\n" + verdict_line)

    if pp:
        print("\nProofpoint detected: raw SPF/DKIM/DMARC fails scored LOW (they")
        print("break on clean mail here). " + (
            "PPS flagged this - weight heavily." if pp_flagged
            else "PPS did not flag it (context)."))
    print(c("\nNote: content signals (greetings, urgency, phrasing) are soft;", DIM))
    print(c("modern AI-written phishing has clean grammar and personalized", DIM))
    print(c("greetings. The strongest evidence is the decoded link destinations,", DIM))
    print(c("link-text/href mismatches, and Proofpoint's own verdict.", DIM))


USAGE = "Usage: python phish-analyzer.py [-q|--quiet] [-v|--verbose] <email.eml>"


def main():
    quiet = verbose = False
    paths = []
    for arg in sys.argv[1:]:
        if arg in ('-q', '--quiet'):
            quiet = True
        elif arg in ('-v', '--verbose'):
            verbose = True
        else:
            paths.append(arg)

    if quiet and verbose:
        print("[ERROR] --quiet and --verbose are mutually exclusive.")
        sys.exit(1)
    if not paths:
        print(USAGE)
        sys.exit(1)
    path = paths[0]
    safe_path = sanitize(path)

    if not quiet:
        print_banner()
        print(f"Analyzing {safe_path}...")
    try:
        findings, info, decoded, pp, pp_flagged = analyze(path)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {safe_path}")
        sys.exit(1)
    except (OSError, ValueError) as exc:
        print(f"[ERROR] Could not read {safe_path}: {sanitize(str(exc))}")
        sys.exit(1)
    except Exception as exc:
        print(f"[ERROR] Failed to parse email: {type(exc).__name__}: {sanitize(str(exc))}")
        sys.exit(1)
    report(findings, info, decoded, pp, pp_flagged, quiet=quiet, verbose=verbose)


if __name__ == '__main__':
    main()
