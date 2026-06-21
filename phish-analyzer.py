"""
phish-analyzer.py - parse a saved .eml and score it for phishing signals.

Looks at header/auth signals (Proofpoint detection, URL Defense decoding,
SPF/DKIM/DMARC in context, domain mismatches at the registrable-domain level)
and softer content signals (link text vs href, lure phrases, urgency).

A triage aid, not a verdict. Runs offline, standard library only.

Usage:
  python phish-analyzer.py [-q|--quiet] [-v|--verbose] <email.eml>
"""
import datetime
import email
import hashlib
import os
import re
import sys
import time
import unicodedata
import urllib.parse
from email import policy
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
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
                 ____  _   _ ___ ____  _   _          ><(((">
                |  _ \| | | |_ _/ ___|| | | |
                | |_) | |_| || |\___ \| |_| |       ><>
                |  __/|  _  || | ___) |  _  |
                |_|   |_| |_|___|____/|_| |_|              <">><

    _     _   _     _     _     __   __ _____  _____  ____
   / \   | \ | |   / \   | |    \ \ / /|__  / | ____||  _ \
  / _ \  |  \| |  / _ \  | |     \ V /   / /  |  _|  | |_) |
 / ___ \ | |\  | / ___ \ | |___   | |   / /_  | |___ |  _ <
/_/   \_\|_| \_|/_/   \_\|_____|  |_|  /____| |_____||_| \_\
 ._______________________________________________________.
 |  local .eml phishing triage  .  no cloud, 100% offline |
 '-------------------------------------------------------'
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

# Brands phishing tends to imitate. brands.txt adds to this.
_BUILTIN_BRANDS = ['microsoft.com', 'office365.com', 'outlook.com', 'paypal.com',
                   'amazon.com', 'apple.com', 'google.com', 'docusign.com',
                   'dropbox.com', 'linkedin.com', 'netflix.com', 'facebook.com',
                   'instagram.com', 'wellsfargo.com', 'chase.com',
                   'bankofamerica.com', 'americanexpress.com', 'coinbase.com',
                   'adobe.com']

# Attachment extensions that run code on open, or that hide one.
DANGEROUS_EXT = {'.exe', '.scr', '.com', '.pif', '.bat', '.cmd', '.js', '.jse',
                 '.vbs', '.vbe', '.wsf', '.wsh', '.hta', '.jar', '.lnk', '.iso',
                 '.img', '.msi', '.ps1', '.reg', '.cpl', '.msc', '.gadget'}
MACRO_EXT = {'.docm', '.xlsm', '.pptm', '.dotm', '.xlam', '.xltm', '.potm'}
ARCHIVE_EXT = {'.zip', '.rar', '.7z', '.ace', '.cab', '.gz', '.tar', '.iso'}
# HTML/SVG attachments open a local phishing page, or run script (svg).
HTML_ATTACH_EXT = {'.html', '.htm', '.shtml', '.xhtml', '.mht', '.mhtml', '.svg'}
# PDF markers for active content. Matched as raw bytes (no PDF parsing); a
# compressed object stream can still hide these, so it's best-effort.
PDF_ACTIVE = (b'/JavaScript', b'/OpenAction', b'/Launch', b'/EmbeddedFile')

SKIP_TAGS = {'script', 'style'}

# Self-closing tags have no end tag, so we keep them off the nesting stack.
VOID_TAGS = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
             'link', 'meta', 'param', 'source', 'track', 'wbr'}

# Nothing legit nests this deep; the cap bounds work on malformed HTML.
_MAX_NEST = 200

# No control bytes, so an escape sequence can't hide in a URL and fire on print.
URL_RE = re.compile(r'https?://[^\s"\'<>)\x00-\x1f\x7f]+', re.IGNORECASE)
DOMAIN_RE = re.compile(r'@([A-Za-z0-9.-]+\.[A-Za-z]{2,})')
TEXT_DOMAIN_RE = re.compile(
    r'\b([a-z0-9][a-z0-9-]+\.(?:com|net|org|io|gov|edu|co|us|info|biz|ru|cn|xyz|top|live|app'
    r'|click|work|online|shop|site|win|club|bond|digital|link|email|tech|store|space))\b')

# Reverse Proofpoint v2's %->- substitution without touching literal hyphens.
_PP_V2_HEX_RE = re.compile(r'-([0-9A-Fa-f]{2})')

_ANSI_RE = re.compile(r'\x1b(?:\[[0-9;]*[a-zA-Z]|\].*?(?:\x07|\x1b\\))')

# CSS that hides an element from the reader.
_HIDDEN_STYLE_RE = re.compile(
    r'display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?![.\d])'
    r'|font-size\s*:\s*0(?![.\d])|font-size\s*:\s*1px|max-height\s*:\s*0',
    re.IGNORECASE)

# Zero-width, soft-hyphen and bidi characters used to split or reverse words.
_ZW_RE = re.compile(
    '[­​‌‍‎‏‪-‮⁠﻿]')

# Common character swaps in typosquats, mapped back to what they imitate.
_CONFUSE_MAP = str.maketrans({'0': 'o', '1': 'l', '3': 'e', '4': 'a',
                              '5': 's', '7': 't', '$': 's', '@': 'a'})

# Scripts whose letters are routinely used to fake Latin ones.
_CONFUSABLE_SCRIPTS = {'CYRILLIC', 'GREEK', 'ARMENIAN', 'CHEROKEE'}

# Caps so crafted mail can't exhaust CPU/memory. Set well above any real email
# (legit mail tops out around a few hundred links and a couple dozen attachments).
_MAX_LINKS = 1000
_MAX_ATTACH = 50
_MAX_HOPS = 50


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


def _load_list(filename):
    """Load a one-per-line list file (domains, TLDs, etc.) sitting next to this
    script. Lines starting with # are comments; blank lines and trailing inline
    # comments are ignored, and a leading dot is stripped so '.zip' and 'zip'
    both work. A missing file just yields an empty set, so the tool still runs."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    items = set()
    try:
        with open(path, encoding='utf-8') as fh:
            for line in fh:
                line = line.split('#', 1)[0].strip().lower().lstrip('.')
                if line:
                    items.add(line)
    except OSError:
        pass
    return items


# Optional reference lists, one entry per line, kept next to this script.
ALLOWLIST = _load_list('allowlist.txt')           # senders you trust
ESP_DOMAINS = _load_list('esp_domains.txt')       # bulk mail / tracker domains
SHORTENERS = _load_list('shorteners.txt')         # link shorteners
SUSPICIOUS_TLDS = _load_list('suspicious_tlds.txt')  # high-abuse TLDs
# Your curated list plus the feed file written by update_feeds.py.
PHISH_DOMAINS = _load_list('phish_domains.txt') | _load_list('phish_domains.feed.txt')
BRANDS = sorted(set(_BUILTIN_BRANDS) | _load_list('brands.txt'))

_FEED_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          'phish_domains.feed.txt')


def _feed_note():
    """Freshness line for the known-bad feed, shown in the header summary."""
    n = len(PHISH_DOMAINS)
    if not os.path.exists(_FEED_PATH):
        return (f"Known-bad list: {n} hosts (no feed file; run update_feeds.py "
                "for the full offline blocklist)")
    age = (time.time() - os.path.getmtime(_FEED_PATH)) / 86400
    stale = "  (stale, run update_feeds.py)" if age > 14 else ""
    return f"Known-bad list: {n} hosts, feed {age:.0f} day(s) old{stale}"


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
    for label in host.split('.'):
        decoded = label
        if label.startswith('xn--'):
            try:
                decoded = label.encode('ascii').decode('idna')
            except Exception:
                decoded = label
        scripts = _label_script(decoded)
        if 'LATIN' in scripts and scripts & _CONFUSABLE_SCRIPTS:
            bad.append(decoded)
    return bad


def mixed_script_words(text):
    """Words mixing Latin with a confusable script, e.g. 'Аpple' with Cyrillic A.
    Per-word so a normal Latin + Cyrillic name across two words isn't flagged."""
    bad = []
    for word in re.findall(r'[^\W\d_]{2,}', text):
        scripts = _label_script(word)
        if 'LATIN' in scripts and scripts & _CONFUSABLE_SCRIPTS:
            bad.append(word)
    return bad


def _is_private_ip(ip):
    p = ip.split('.')
    if len(p) != 4:
        return False
    a, b = int(p[0]), int(p[1])
    return (a in (0, 10, 127) or (a == 192 and b == 168)
            or (a == 172 and 16 <= b <= 31))


def originating_hop(received):
    """Real sender (host, ip) from the Received chain, read past any Proofpoint
    relay. Received headers are newest-first, so we walk from the oldest hop and
    take the first one whose 'from' side is external (the hop where Proofpoint, or
    your MX, accepted the mail from the real sender)."""
    for r in list(reversed(received))[:_MAX_HOPS]:
        s = str(r)
        host_m = re.search(r'from\s+([a-z0-9.-]{1,255}\.[a-z]{2,24})', s, re.I)
        host = host_m.group(1).lower() if host_m else ''
        # Skip a hop only if the sender side is Proofpoint, not the receiving side.
        if 'pphosted.com' in host or 'proofpoint' in host:
            continue
        ip_m = re.search(r'[\[(]((?:\d{1,3}\.){3}\d{1,3})[\])]', s)
        ip = ip_m.group(1) if ip_m else ''
        if ip and _is_private_ip(ip):
            ip = ''
        if host or ip:
            return host, ip
    return '', ''


def get_domain(addr):
    """Registrable host of the REAL address, i.e. the one in angle brackets,
    parsed with parseaddr so an '@domain' planted in the display name (a common
    spoof) can't be mistaken for the sending domain."""
    if not addr:
        return ''
    _name, email_addr = parseaddr(addr)
    if email_addr and '@' in email_addr:
        return email_addr.rsplit('@', 1)[-1].strip().strip('>').lower()
    m = DOMAIN_RE.search(addr)
    return m.group(1).lower() if m else ''


def dest_domain(url):
    """Host for a possibly scheme-less URL. Proofpoint v3 decoding can drop the
    scheme, leaving the host in .path, so fall back to that."""
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


# Hosts that rewrite links for security. We unwrap them but don't treat their
# redirects as the "link inside a link" trick.
_SECURITY_WRAPPERS = ('urldefense.proofpoint.com', 'urldefense.com',
                      'urldefense.us', 'safelinks.protection.outlook.com',
                      'mimecast.com', 'linkprotect.cudasvc.com', 'ampproject.org')

# Query params that usually carry a redirect target. 'q' is excluded since it's
# normally a search term.
_REDIRECT_PARAMS = ('url', 'redirect', 'redirect_uri', 'redirecturl', 'next',
                    'return', 'returnurl', 'dest', 'destination', 'u', 'target',
                    'link', 'goto', 'continue')


def _get_param(url, *names):
    """First query-string value whose key matches any of names (case-insensitive)."""
    try:
        params = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    except Exception:
        return ''
    lower = {k.lower(): v for k, v in params.items()}
    for n in names:
        if lower.get(n):
            return lower[n][0]
    return ''


def decode_redirect(url):
    """Unwrap known link-protection and redirect wrappers (Proofpoint, Microsoft
    Safelinks, Mimecast, Barracuda, Google AMP) to the real destination. Returns
    the input unchanged if nothing matches."""
    real = decode_proofpoint(url)
    if real != url:
        return real
    host = dest_domain(url)
    low = url.lower()
    if 'safelinks.protection.outlook.com' in host:
        t = _get_param(url, 'url')
        if t:
            return urllib.parse.unquote(t)
    if 'linkprotect.cudasvc.com' in host:
        t = _get_param(url, 'a')
        if t:
            return urllib.parse.unquote(t)
    if 'mimecast.com' in host and '/s/' in url:
        dom = _get_param(url, 'domain')
        if dom:
            return 'https://' + dom.strip().lstrip('/')
    if 'ampproject.org' in host or '/amp/s/' in low:
        m = re.search(r'/(?:amp/s|c/s)/(.+)', url)
        if m:
            tail = m.group(1)
            return tail if tail.startswith('http') else 'https://' + tail
    return url


def open_redirect_target(url, trusted_hosts=frozenset()):
    """If url is a generic open-redirect (not a known security wrapper) whose
    query carries a full URL on a different registrable domain, return that
    domain. This catches the 'link hidden inside a link' cloaking trick."""
    host = dest_domain(url)
    if not host or any(w in host for w in _SECURITY_WRAPPERS):
        return ''
    if registrable_domain(host) in trusted_hosts:
        return ''
    val = _get_param(url, *_REDIRECT_PARAMS)
    if not val:
        return ''
    val = urllib.parse.unquote(val)
    if '://' not in val and not val.startswith('//'):
        return ''
    target = dest_domain(val)
    if target and not same_domain_family(target, host):
        return registrable_domain(target) or target
    return ''


def _is_ip_host(host):
    """True if host is a raw IP literal: dotted IPv4, IPv6, or a hex/decimal
    integer that some clients still resolve as an address."""
    if not host:
        return False
    if ':' in host:
        return True
    if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', host):
        return True
    if re.fullmatch(r'0x[0-9a-f]+', host) or re.fullmatch(r'\d{6,}', host):
        return True
    return False


def decode_idna_host(host):
    """Turn xn-- punycode labels back into readable Unicode so a disguised host
    can be shown as it actually reads."""
    out = []
    for lab in host.split('.'):
        if lab.startswith('xn--'):
            try:
                lab = lab.encode('ascii').decode('idna')
            except Exception:
                pass
        out.append(lab)
    return '.'.join(out)


def defang(s):
    """Make a URL/host unclickable for safe display: http->hxxp, . -> [.]"""
    return s.replace('http', 'hxxp').replace('.', '[.]')


def _auth_status(top_auth, all_auth, pp, received_spf):
    """One-line spoof verdict from the auth headers. Advisory; the SPF/DKIM/DMARC
    scoring below is separate. PASS only on a real aligned DMARC pass."""
    if 'dmarc=pass' in top_auth:
        return 'PASS', 'From domain authenticated (DMARC aligned)'
    if pp:
        return 'UNKNOWN', 'Proofpoint may have altered auth; weigh links/content'
    if 'dmarc=fail' in all_auth:
        return 'FAIL', 'DMARC failed, From may be spoofed'
    if any(x in all_auth for x in ('spf=fail', 'spf=softfail', 'dkim=fail')):
        return 'FAIL', 'SPF/DKIM failed, From may be spoofed'
    if all_auth:
        return 'UNKNOWN', 'no DMARC verdict (domain may not enforce DMARC)'
    if received_spf:
        return 'UNKNOWN', f'no Authentication-Results; Received-SPF={received_spf}'
    return 'UNKNOWN', 'no Authentication-Results in this .eml'


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
        self.form_actions = []
        self.meta_refresh = []
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
        d = dict(attrs)
        if tag == 'a' and not self._skip:
            self._href = d.get('href')
            self._buf = []
        elif tag == 'form':
            if d.get('action'):
                self.form_actions.append(d['action'])
        elif tag == 'meta' and (d.get('http-equiv') or '').lower() == 'refresh':
            m = re.search(r'url\s*=\s*([^\s;]+)', d.get('content') or '',
                          re.IGNORECASE)
            if m:
                self.meta_refresh.append(m.group(1).strip('\'"'))

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
            if len(self.links) < _MAX_LINKS:
                self.links.append((self._href, ''.join(self._buf).strip()))
            self._href = None
            self._buf = []
        # Only pop when the top of the stack matches; a stray close tag is ignored.
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
    """Yield (filename, size, sha256, extensions, pdf_active) for each attached
    part. `extensions` is the trailing extensions (invoice.pdf.exe -> ['.pdf',
    '.exe']); `pdf_active` lists active-content markers found in a PDF payload."""
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        fn = part.get_filename()
        if not fn and part.get_content_disposition() != 'attachment':
            continue
        payload = part.get_payload(decode=True) or b''
        name = sanitize(fn or '(unnamed)')
        exts = [e.lower() for e in re.findall(r'\.[A-Za-z0-9]{1,8}', name)][-2:]
        pdf_active = []
        if b'%PDF-' in payload[:1024]:  # byte search only, never parse the PDF
            pdf_active = [t[1:].decode() for t in PDF_ACTIVE if t in payload]
        yield name, len(payload), hashlib.sha256(payload).hexdigest(), exts, pdf_active


def analyze(path):
    size = os.path.getsize(path)
    if size > MAX_FILE_BYTES:
        raise ValueError(f"file too large to analyze ({size} bytes, limit {MAX_FILE_BYTES})")
    with open(path, 'rb') as fh:
        msg = email.message_from_binary_file(fh, policy=policy.default)

    hard = []   # (weight, desc) structural/auth/link/attachment signals
    soft = []   # (weight, desc) language signals, scored only with corroboration
    info = []
    if PSL_WARNING:
        info.append(PSL_WARNING)
    info.append(_feed_note())
    pp = proofpoint_in_path(msg)

    frm = str(msg.get('From', ''))
    reply_to = str(msg.get('Reply-To', ''))
    return_path = str(msg.get('Return-Path', ''))
    subject = str(msg.get('Subject', ''))
    msg_id = str(msg.get('Message-ID', ''))

    from_dom = get_domain(frm)
    reply_dom = get_domain(reply_to)
    rp_dom = get_domain(return_path)
    from_reg = registrable_domain(from_dom) if from_dom else ''

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
    # Only the top Authentication-Results header can grant trust: your own gateway
    # stamps it last, so a remote sender can't forge a pass below it. Failure
    # checks still scan every header.
    top_auth = str(auth_headers[0]).lower() if auth_headers else ''
    dmarc_pass = 'dmarc=pass' in top_auth
    if 'dmarc=pass' in all_auth and not dmarc_pass:
        info.append("[note] A lower Authentication-Results header claims dmarc=pass "
                    "but the top (trusted) header does not; not treated as trusted.")

    # Received-SPF is a second auth source when Authentication-Results is absent.
    spf_hdr = msg.get('Received-SPF')
    received_spf = str(spf_hdr).strip().split(None, 1)[0].lower() if spf_hdr else ''

    auth_state, auth_detail = _auth_status(top_auth, all_auth, pp, received_spf)
    info.append(f"Sender authentication: {auth_state} - {auth_detail}")

    # Who DKIM-signed (the d= tag), checked for From alignment. Unverified offline,
    # so it's context only; scored just when there's no Authentication-Results.
    d_doms = [m.group(1).strip().lower() for m in
              (re.search(r'(?:^|;)\s*d\s*=\s*([^;]+)', str(sig), re.I)
               for sig in msg.get_all('DKIM-Signature', [])) if m]
    d_aligned = any(same_domain_family(d, from_dom)
                    or registrable_domain(d) in ESP_DOMAINS for d in d_doms)
    if d_doms:
        info.append(f"[note] DKIM-Signature d={', '.join(d_doms[:3])} "
                    f"({'aligned' if d_aligned else 'not aligned'} with From, unverified)")

    pp_flagged = False
    for h in msg.keys():
        if h.lower().startswith('x-proofpoint'):
            val = str(msg.get(h))
            info.append(f"[PPS] {h}: {val[:160]}")
            if any(tok in val.lower() for tok in PP_BAD_TOKENS):
                hard.append((4, f"Proofpoint itself flagged this message ({h})"))
                pp_flagged = True

    # Reply-To and Return-Path splits are normal for ESPs and bounce domains. A
    # Reply-To to freemail or a known-bad domain is the real BEC tell and stays
    # hard; the rest is soft, and skipped when DMARC passed or the domain is a
    # known ESP.
    if reply_dom and from_dom and not same_domain_family(reply_dom, from_dom):
        reply_reg = registrable_domain(reply_dom)
        if reply_dom in FREEMAIL or reply_reg in PHISH_DOMAINS:
            hard.append((2, f"Reply-To points to an unrelated address ({reply_dom}) "
                            f"while From is {from_dom}"))
        elif not dmarc_pass and reply_reg not in ESP_DOMAINS:
            soft.append((1, f"Reply-To domain ({reply_dom}) differs from From ({from_dom})"))
    if rp_dom and from_dom and not same_domain_family(rp_dom, from_dom):
        if not dmarc_pass and registrable_domain(rp_dom) not in ESP_DOMAINS:
            soft.append((1, f"Return-Path domain ({rp_dom}) differs from From ({from_dom})"))

    if '<' in frm and from_dom:
        display = frm.split('<', 1)[0].strip().strip('"\'').lower()
        # Display name embedding someone else's address/domain, e.g.
        # "security@microsoft.com" <attacker@evil.ru>.
        m = re.search(r'[\w.+-]+@([a-z0-9.-]+\.[a-z]{2,})', display)
        claimed_dom = m.group(1) if m else domain_in_text(display)
        if claimed_dom and not same_domain_family(claimed_dom, from_dom):
            hard.append((3, f"Display name claims '{claimed_dom}' but the real "
                            f"sender domain is {from_dom}"))
        else:
            # Whole-word match so short terms ('it', 'hr') don't fire inside words.
            matched = [t for t in (term.strip() for term in IMPERSONATION_TERMS)
                       if re.search(r'\b' + re.escape(t) + r'\b', display)]
            if matched:
                if from_dom in FREEMAIL:
                    hard.append((3, f"Authority/brand display name from freemail ({from_dom})"))
                else:
                    for term in matched:
                        if term not in from_dom:
                            hard.append((3, f"Display name implies '{term}' but domain is {from_dom}"))
                            break

    # Sender domain itself imitating a brand (paypa1.com) or mixing scripts.
    if from_reg:
        ft = typosquat_target(from_reg)
        if ft:
            hard.append((3, f"Sender domain '{from_reg}' imitates '{ft}' (typosquat)"))
    for lab in idn_homograph(from_dom):
        hard.append((3, f"Mixed-script (homograph) sender domain: '{lab}'"))

    # Same homoglyph/bidi tricks, but in the readable headers, not just links.
    display_raw = frm.split('<', 1)[0] if '<' in frm else frm
    for w in mixed_script_words(display_raw):
        hard.append((2, f"Mixed-script (homograph) From display name: '{w}'"))
    for w in mixed_script_words(subject):
        hard.append((2, f"Mixed-script (homograph) Subject: '{w}'"))
    if _ZW_RE.search(frm):
        hard.append((2, "Zero-width/bidi characters in the From header"))
    if _ZW_RE.search(subject):
        hard.append((1, "Zero-width/bidi characters in the Subject"))

    # More than one address in From confuses DMARC alignment and what clients show.
    from_addrs = [a for _n, a in getaddresses(msg.get_all('From', [])) if '@' in a]
    if len(from_addrs) > 1:
        hard.append((2, f"From header lists {len(from_addrs)} addresses "
                        "(used to confuse DMARC/display)"))

    if auth_headers:
        spf_w, dkim_w, dmarc_w = (1, 1, 1) if pp else (2, 2, 3)
        note = "  (LOW conf - Proofpoint may have broken this)" if pp else ""
        if 'spf=fail' in all_auth or 'spf=softfail' in all_auth:
            hard.append((spf_w, "SPF failed" + note))
        if 'dkim=fail' in all_auth:
            hard.append((dkim_w, "DKIM failed" + (
                "  (LOW conf - URL rewriting breaks DKIM body hash)" if pp else "")))
        if 'dmarc=fail' in all_auth:
            hard.append((dmarc_w, "DMARC failed" + note))
    else:
        # No verdict to read (often the .eml was exported before auth ran). Fall
        # back to the unverified DKIM d= alignment and Received-SPF; soft only,
        # and skipped under Proofpoint, which rewrites the body and may re-sign.
        info.append("[note] No Authentication-Results header (often stripped when "
                    "saving an .eml); not scored.")
        if d_doms and not d_aligned and from_dom and not pp:
            soft.append((1, f"DKIM signing domain ({d_doms[0]}) does not align "
                            f"with From ({from_dom}); unverified"))
        if received_spf in ('fail', 'softfail') and not pp:
            soft.append((1, f"Received-SPF: {received_spf} (no Authentication-Results)"))

    # The real sender sits below any Proofpoint relay, so the top Received hop is
    # Proofpoint's IP, not the sender's. Surface the originating hop instead.
    received = msg.get_all('Received', [])
    if received:
        info.append(f"Received: {len(received)} hop(s)")
        o_host, o_ip = originating_hop(received)
        if o_host or o_ip:
            detail = ' '.join(x for x in (o_host, f"[{o_ip}]" if o_ip else '') if x)
            info.append(f"Originating sender: {detail}"
                        + ("  (read past Proofpoint relay)" if pp else ""))
            if o_host and registrable_domain(o_host) in PHISH_DOMAINS:
                soft.append((1, f"Originating relay '{o_host}' is on the known-bad list"))

    # Date sanity: missing or wildly off is a mild tell.
    date_hdr = msg.get('Date')
    if not date_hdr:
        soft.append((1, "Missing Date header"))
    else:
        try:
            dt = parsedate_to_datetime(str(date_hdr))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            off_days = (datetime.datetime.now(datetime.timezone.utc) - dt).days
            if off_days < -2:
                soft.append((1, "Date header is in the future"))
            elif off_days > 3650:
                soft.append((1, "Date header is implausibly old"))
        except Exception:
            soft.append((1, "Unparseable Date header"))

    # Common for legit mail services, so keep it as a soft hint.
    mid_dom = msg_id.split('@')[-1].strip('>').lower() if '@' in msg_id else ''
    if mid_dom and from_dom and not same_domain_family(mid_dom, from_dom):
        soft.append((1, f"Message-ID domain ({mid_dom}) differs from From ({from_dom})"))

    subject_urgency = set()
    if any(word in subject.lower() for word in URGENCY):
        hit = next(w for w in URGENCY if w in subject.lower())
        subject_urgency = {w for w in URGENCY if w in subject.lower()}
        soft.append((1, f"Urgency/lure keyword in SUBJECT: '{hit}'"))

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

    # A benign text/plain part paired with very different HTML is a way to show
    # scanners one story and the reader another. Only fires when both parts are
    # substantial, so legit "view in browser" stubs don't trip it.
    plain_words = set(re.findall(r'[a-z0-9]{4,}', text_body.lower()))
    html_words = set(re.findall(r'[a-z0-9]{4,}', parser.visible_text().lower()))
    if len(plain_words) >= 5 and len(html_words) >= 5:
        overlap = len(plain_words & html_words) / len(plain_words | html_words)
        if overlap < 0.15:
            soft.append((1, "text/plain and text/html parts differ sharply "
                            "(possible scanner evasion)"))

    # ---------- LINK ANALYSIS ----------
    # Decode each link so the real destinations are visible. We don't score
    # "links off-domain" by itself; legit mail links to trackers and CDNs all the
    # time. The checks below look for deliberate disguises instead.
    raw_urls = []
    for m in URL_RE.finditer(raw_body):
        raw_urls.append(m.group(0))
        if len(raw_urls) >= _MAX_LINKS:
            break
    decoded = []
    seen_decoded = set()
    for u in raw_urls:
        real = decode_redirect(u)
        if real not in seen_decoded:
            decoded.append(real)
            seen_decoded.add(real)

    # Open-redirect cloaking: a link on one site whose query forwards to another.
    seen_redir = set()
    for u in raw_urls:
        tgt = open_redirect_target(u, ESP_DOMAINS | ALLOWLIST)
        if tgt and tgt not in seen_redir:
            wrap = registrable_domain(dest_domain(u))
            hard.append((3, f"Open-redirect link on '{wrap}' forwards to '{tgt}'"))
            seen_redir.add(tgt)

    seen = {k: set() for k in
            ('at', 'bad', 'ip', 'homo', 'brand', 'typo', 'short', 'tld',
             'port', 'deep', 'puny')}
    for real in decoded:
        host = dest_domain(real)
        if not host:
            continue
        reg = registrable_domain(host)
        is_esp = reg in ESP_DOMAINS

        # The "@" trick: http://microsoft.com@evil.ru actually goes to evil.ru.
        try:
            if urllib.parse.urlparse(real).username and host not in seen['at']:
                hard.append((3, f"Deceptive '@' in link: real destination is '{host}'"))
                seen['at'].add(host)
        except Exception:
            pass

        if (reg in PHISH_DOMAINS or host in PHISH_DOMAINS) and host not in seen['bad']:
            hard.append((4, f"Link domain '{reg or host}' is on the known-bad list"))
            seen['bad'].add(host)

        if _is_ip_host(host) and host not in seen['ip']:
            hard.append((2, f"Link points to a raw IP address: '{host}'"))
            seen['ip'].add(host)

        if host not in seen['homo']:
            homo = idn_homograph(host)
            for lab in homo:
                hard.append((3, f"Mixed-script (homograph) domain in link: '{lab}'"))
                seen['homo'].add(host)
            # Punycode that isn't an outright homograph is still worth noting.
            if not homo and 'xn--' in host and host not in seen['puny']:
                soft.append((1, f"Punycode (internationalized) domain in link: "
                                f"'{host}' [reads as {decode_idna_host(host)}]"))
                seen['puny'].add(host)

        # Brand name buried as a subdomain, e.g. microsoft.com.verify-account.ru.
        if host not in seen['brand']:
            for b in BRANDS:
                if ('.' + b + '.') in ('.' + host + '.') and not (
                        host == b or host.endswith('.' + b)):
                    hard.append((3, f"Brand domain '{b}' appears inside link host "
                                    f"but the real domain is '{reg}'"))
                    seen['brand'].add(host)
                    break

        target = typosquat_target(reg, from_reg)
        if target and host not in seen['typo']:
            hard.append((3, f"Link domain '{reg}' imitates '{target}' (typosquat)"))
            seen['typo'].add(host)

        # Soft hints, skipped for ESP domains that use these patterns legitimately.
        if is_esp:
            continue
        if reg in SHORTENERS and host not in seen['short']:
            soft.append((1, f"Shortened link hides its real destination: '{host}'"))
            seen['short'].add(host)
        tld = reg.rsplit('.', 1)[-1] if reg else ''
        if tld and tld in SUSPICIOUS_TLDS and host not in seen['tld']:
            soft.append((1, f"Link uses a high-abuse TLD ('.{tld}'): '{reg}'"))
            seen['tld'].add(host)
        try:
            port = urllib.parse.urlparse(real).port
        except Exception:
            port = None
        if port not in (None, 80, 443) and host not in seen['port']:
            soft.append((1, f"Link uses a non-standard port ({port}): '{host}'"))
            seen['port'].add(host)
        if host.count('.') >= 5 and host not in seen['deep']:
            soft.append((1, f"Link host has unusually many subdomains: '{host}'"))
            seen['deep'].add(host)

    seen_mismatch = set()
    for href, text in parser.links[:_MAX_LINKS]:
        real = decode_redirect(href)
        real_dom = dest_domain(real)
        if registrable_domain(real_dom) in ESP_DOMAINS:
            continue
        claimed = domain_in_text(text)
        if claimed and real_dom and not same_domain_family(claimed, real_dom):
            key = (claimed, real_dom)
            if key not in seen_mismatch:
                hard.append((3, f"Link DISPLAYS '{claimed}' but actually goes to '{real_dom}'"))
                seen_mismatch.add(key)

    # Anchors whose href is a script or inline-data URI rather than a real link.
    seen_scheme = set()
    for href, _text in parser.links[:_MAX_LINKS]:
        scheme = urllib.parse.urlparse(href).scheme.lower()
        if scheme in ('javascript', 'data', 'vbscript') and scheme not in seen_scheme:
            hard.append((2, f"Link uses a '{scheme}:' URI instead of a normal web link"))
            seen_scheme.add(scheme)

    # A form posting to an external site is a credential trap, and clients usually
    # strip forms anyway, so any external target stands out.
    seen_form = set()
    for action in parser.form_actions:
        adom = dest_domain(decode_redirect(action))
        if not adom or adom in seen_form:
            continue
        if registrable_domain(adom) in ESP_DOMAINS or same_domain_family(adom, from_dom):
            continue
        hard.append((3, f"Form in the email submits to an external domain: '{adom}'"))
        seen_form.add(adom)

    # Auto-redirect via <meta http-equiv="refresh">; legit mail almost never does.
    seen_meta = set()
    for tgt in parser.meta_refresh:
        mdom = dest_domain(decode_redirect(tgt))
        if not mdom or mdom in seen_meta:
            continue
        if registrable_domain(mdom) in ESP_DOMAINS or same_domain_family(mdom, from_dom):
            continue
        hard.append((2, f"Auto-redirect (meta refresh) to '{mdom}'"))
        seen_meta.add(mdom)

    # Brand named in the text but no link to it. Soft, so a plain mention of a
    # company name on its own stays quiet.
    link_regs = {registrable_domain(dest_domain(d)) for d in decoded}
    link_regs.discard('')
    ext_regs = sorted(r for r in link_regs if r not in ESP_DOMAINS)
    if ext_regs:
        brand_text = (subject + ' ' + visible)[:65536].lower()
        for b in BRANDS:
            bname = b.split('.', 1)[0]
            if len(bname) < 4:
                continue
            if re.search(r'\b' + re.escape(bname) + r'\b', brand_text) and \
                    not any(same_domain_family(r, b) for r in link_regs):
                soft.append((1, f"Body mentions '{bname}' but no link goes to {b} "
                                f"(links: {', '.join(ext_regs[:3])})"))
                break

    # ---------- CONTENT / LANGUAGE SIGNALS ----------
    for phrase in CRED_HARVEST:
        if phrase in visible:
            soft.append((2, f"Credential-harvesting phrase: '{phrase}'"))
            break
    for greet in GENERIC_GREETINGS:
        if greet in visible:
            soft.append((1, f"Generic greeting (no real name): '{greet}'"))
            break
    # Skip subject words already scored above so we don't double-count.
    body_urgency = [w for w in URGENCY if w in visible and w not in subject_urgency]
    if body_urgency:
        soft.append((1, f"Urgency/pressure language in body (e.g. '{body_urgency[0]}')"))

    # Hidden text and zero-width tricks are active evasion, so they stay hard
    # even when the sender authenticates.
    hidden = parser.hidden_text().lower()
    hidden_hit = next((p for p in (CRED_HARVEST + URGENCY) if p in hidden), '')
    if hidden_hit:
        hard.append((2, f"Hidden (CSS) text contains a lure phrase: '{hidden_hit}'"))
    if _ZW_RE.search(raw_body):
        hard.append((1, "Zero-width or bidi control characters in body (obfuscation)"))

    # ---------- ATTACHMENTS ----------
    for i, (name, asize, digest, exts, pdf_active) in enumerate(attachments(msg)):
        if i >= _MAX_ATTACH:
            break
        info.append(f"[Attachment] {name}  ({asize} bytes)  sha256={digest}")
        last = exts[-1] if exts else ''
        if len(exts) >= 2 and exts[-2] not in DANGEROUS_EXT and last in DANGEROUS_EXT:
            hard.append((3, f"Misleading double extension on attachment: '{name}'"))
        elif last in DANGEROUS_EXT:
            hard.append((3, f"Dangerous attachment type ({last}): '{name}'"))
        elif last in MACRO_EXT:
            hard.append((2, f"Macro-enabled attachment ({last}): '{name}'"))
        elif last in HTML_ATTACH_EXT:
            hard.append((3, f"HTML/script attachment can host a local phishing page "
                            f"({last}): '{name}'"))
        elif last in ARCHIVE_EXT:
            soft.append((1, f"Archive attachment ({last}) may hide a payload: '{name}'"))
        # Active content in a PDF: auto-run actions weigh heavier than embedded JS.
        if pdf_active:
            strong = any(t in ('OpenAction', 'Launch') for t in pdf_active)
            hard.append((3 if strong else 2,
                         f"PDF attachment has active content "
                         f"({', '.join(pdf_active)}): '{name}'"))

    # ---------- CORROBORATION GATE ----------
    # Language signals only count when a hard signal also fired and the sender
    # didn't pass DMARC or sit on the allowlist. Otherwise they show as context.
    # This gate is what keeps the false-positive rate down.
    allowlisted = bool(from_reg) and (from_reg in ALLOWLIST or from_dom in ALLOWLIST)
    trusted = dmarc_pass or allowlisted
    count_soft = bool(hard) and not trusted

    findings = list(hard)
    context = []
    if count_soft:
        findings.extend(soft)
    elif soft:
        context = list(soft)
        if trusted:
            why = "sender passed DMARC" if dmarc_pass else "sender is on your allowlist"
            info.append(f"[note] Language signals below not scored ({why}).")
        else:
            info.append("[note] Language signals below not scored (no structural "
                        "signal to corroborate them).")

    return findings, context, info, decoded, pp, pp_flagged


def _hdr(title):
    return c(f"=== {title} ===", BRAND, BOLD)


def _color_info(line):
    """Tint a few key header-summary fields. No-op when color is off."""
    if line.startswith('Sender authentication:'):
        col = GREEN if ' PASS ' in line else RED if ' FAIL ' in line else YELLOW
        return c(line, col, BOLD)
    if line.startswith('[note]'):
        return c(line, DIM)
    if line.startswith('[WARN]'):
        return c(line, YELLOW)
    if line.startswith('Known-bad list:') and 'stale' in line:
        return c(line, YELLOW)
    for label, col in (('Proofpoint in path:', None),
                       ('Originating sender:', YELLOW)):
        if line.startswith(label):
            val = line[len(label):]
            if col is None:  # Proofpoint: YES stands out, no stays quiet
                col = CYAN if 'YES' in val else DIM
            return label + c(val, col, BOLD)
    return line


def verdict_for(score):
    if score >= 6:
        return "HIGH - strong phishing indicators", RED
    if score >= 3:
        return "MEDIUM - suspicious, investigate further", YELLOW
    if score >= 1:
        return "LOW - minor signals, likely benign but verify", CYAN
    return "MINIMAL - no scored signals", GREEN


# Headings the SIGNALS/CONTEXT sections are grouped under, in print order.
_SIGNAL_GROUPS = ('Authentication', 'Sender / headers', 'Links',
                  'Attachments', 'Content')


def _signal_group(desc):
    """Bucket a finding by its text. Display only; the finding tuples are
    untouched, so a wrong guess just files a line under a different heading."""
    d = desc.lower()
    if any(k in d for k in ('spf ', 'dkim', 'dmarc', 'proofpoint itself flagged',
                            'authentication-results')):
        return 'Authentication'
    if 'attachment' in d or 'extension' in d:
        return 'Attachments'
    if any(k in d for k in ('reply-to', 'return-path', 'message-id',
                            'display name', 'sender domain', 'from freemail',
                            'homograph) sender', 'homograph) subject',
                            'in the from header', 'in the subject', 'date header',
                            'originating relay')):
        return 'Sender / headers'
    if any(k in d for k in ('link', 'redirect', 'brand domain', 'form ',
                            'punycode', "'@'", 'ip address', 'shorten', 'tld',
                            'port', 'subdomain', 'body mentions', ' uri ')):
        return 'Links'
    return 'Content'


def _print_grouped(items, scored):
    by_group = {}
    for w, desc in items:
        by_group.setdefault(_signal_group(desc), []).append((w, desc))
    for group in _SIGNAL_GROUPS:
        rows = by_group.get(group)
        if not rows:
            continue
        rows.sort(key=lambda r: -r[0])
        print(c(f"  {group} ({len(rows)})", BRAND, BOLD))
        for w, desc in rows:
            tag = c(f'[+{w}]', weight_color(w), BOLD) if scored else c('[ ]', DIM)
            print(f"    {tag} {sanitize(desc)}")


def report(findings, context, info, decoded, pp, pp_flagged,
           quiet=False, verbose=False, raw=False):
    score = sum(w for w, _ in findings)
    verdict, vcolor = verdict_for(score)
    meter = risk_meter(score, vcolor)
    verdict_line = f"RISK SCORE {score}  {meter}  {c(verdict, vcolor, BOLD)}"

    if quiet:
        print(verdict_line)
        return

    # Lead with the answer: verdict, the spoof check, counts, heaviest signals.
    print("\n" + _hdr("VERDICT"))
    print("  " + verdict_line)
    auth_line = next((l for l in info if l.startswith('Sender authentication:')), '')
    if auth_line:
        print("  " + _color_info(sanitize(auth_line)))
    print(c(f"  {len(findings)} scored signal(s), {len(context)} context item(s)", DIM))
    for w, desc in sorted(findings, key=lambda f: -f[0])[:3]:
        print(f"    {c(f'[+{w}]', weight_color(w), BOLD)} {sanitize(desc)}")

    print("\n" + _hdr("HEADER SUMMARY"))
    for line in info:
        if line.startswith('Sender authentication:'):
            continue  # shown in the VERDICT block above
        print("  " + _color_info(sanitize(line)))

    print("\n" + _hdr("LINKS (decoded)"))
    if decoded:
        # Domains named in any link-related signal, so we can flag the implicated
        # link inline and let benign trackers fade into the background.
        flagged = set()
        for _w, desc in list(findings) + list(context):
            if _signal_group(desc) == 'Links':
                flagged.update(t.lower() for t in re.findall(r"'([^']+)'", desc))
        shown = decoded if verbose else decoded[:25]
        for d in shown:
            host = dest_domain(d)
            reg = registrable_domain(host)
            safe = sanitize(d if raw else defang(d))
            show_reg = reg if raw else defang(reg)
            if show_reg and show_reg in safe:  # make the registrable domain stand out
                safe = safe.replace(show_reg, c(show_reg, YELLOW, BOLD), 1)
            implicated = bool(host) and (host in flagged or reg in flagged
                or any(t in host for t in flagged if len(t) >= 4))
            marker = c("(!)", RED, BOLD) if implicated else c(" - ", DIM)
            line = f"  {marker} " + safe
            if 'xn--' in host:
                reads = decode_idna_host(host)
                line += sanitize("   [reads as: " + (reads if raw else defang(reads)) + "]")
            print(line)
        if not verbose and len(decoded) > 25:
            print(c(f"  ... +{len(decoded) - 25} more (use --verbose to show all)", DIM))
    else:
        print("  (no links found)")

    print("\n" + _hdr("SIGNALS"))
    if findings:
        _print_grouped(findings, scored=True)
    else:
        print("  (no scored signals fired)")

    if context:
        print("\n" + _hdr("CONTEXT (not scored)"))
        _print_grouped(context, scored=False)

    if pp:
        print("\nProofpoint detected: raw SPF/DKIM/DMARC fails scored LOW (they")
        print("break on clean mail here). " + (
            "PPS flagged this - weight heavily." if pp_flagged
            else "PPS did not flag it (context)."))
    print(c("\nNote: language signals (greetings, urgency, phrasing) count toward", DIM))
    print(c("the score only when a structural signal also fired and the sender is", DIM))
    print(c("not authenticated or allowlisted; otherwise they are listed as context.", DIM))
    print(c("The strongest evidence is the decoded link destinations, link-text/href", DIM))
    print(c("mismatches, known-bad hits, and Proofpoint's own verdict.", DIM))


USAGE = ("Usage: python phish-analyzer.py [-q|--quiet] [-v|--verbose] [--raw] "
         "<email.eml | folder> [more...]\n"
         "  --raw  show links live/clickable (default: defanged)")


def _gather_targets(args):
    """Expand the given files and folders into a list of .eml paths."""
    targets = []
    for a in args:
        if os.path.isdir(a):
            for name in sorted(os.listdir(a)):
                if name.lower().endswith('.eml'):
                    targets.append(os.path.join(a, name))
        else:
            targets.append(a)
    return targets


def _analyze_capture(path):
    """Run analyze() but turn any failure into an error string for batch runs."""
    try:
        return analyze(path), None
    except FileNotFoundError:
        return None, "file not found"
    except (OSError, ValueError) as exc:
        return None, sanitize(str(exc))
    except Exception as exc:
        return None, f"{type(exc).__name__}: {sanitize(str(exc))}"


def _summary_row(path, result, error):
    name = sanitize(os.path.basename(path))
    if error:
        return f"  {c('ERROR   ', RED, BOLD)} {name}  ({error})"
    score = sum(w for w, _ in result[0])
    verdict, vcolor = verdict_for(score)
    tier = verdict.split(' ', 1)[0]
    return f"  {c(f'{tier:<8}', vcolor, BOLD)} score {score:<3}  {name}"


def main():
    quiet = verbose = raw = False
    args = []
    for arg in sys.argv[1:]:
        if arg in ('-q', '--quiet'):
            quiet = True
        elif arg in ('-v', '--verbose'):
            verbose = True
        elif arg == '--raw':
            raw = True
        else:
            args.append(arg)

    if quiet and verbose:
        print("[ERROR] --quiet and --verbose are mutually exclusive.")
        sys.exit(1)
    if not args:
        print(USAGE)
        sys.exit(1)

    targets = _gather_targets(args)
    if not targets:
        print("[ERROR] No .eml files found in the given path(s).")
        sys.exit(1)

    # One file gets the full report; several get a one-line-per-file table.
    if len(targets) == 1:
        path = targets[0]
        if not quiet:
            print_banner()
            print(f"Analyzing {sanitize(os.path.basename(path))}...")
        result, error = _analyze_capture(path)
        if error:
            print(f"[ERROR] Could not analyze {sanitize(path)}: {error}")
            sys.exit(1)
        report(*result, quiet=quiet, verbose=verbose, raw=raw)
        return

    if not quiet:
        print_banner()
        print(f"Scanning {len(targets)} files...\n")
    print(_hdr("BATCH SUMMARY"))
    for path in targets:
        result, error = _analyze_capture(path)
        print(_summary_row(path, result, error))
    if not quiet:
        print(c("\nRun a single file for the full report.", DIM))


if __name__ == '__main__':
    main()
