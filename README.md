# phish-analyzer

A local, dependency-free triage tool that parses a saved `.eml` file and scores it for phishing signals. Designed for analysts who want a fast first-pass read on a suspicious email without uploading it to an external service.

---

## Why

Most email security tools either require cloud access, need API keys, or only tell you what their scanner already decided. This tool gives you the raw evidence: decoded links, auth failures in context, header mismatches, and content signals — so you can make the call yourself. It runs entirely offline and touches nothing outside your machine.

---

## Features

- **Proofpoint URL Defense decoding** — unwraps v2 and v3 redirect links to show the real destination
- **Auth header analysis** — reads all `Authentication-Results` headers and scores SPF, DKIM, and DMARC failures; adjusts confidence automatically when Proofpoint is in the mail path (where URL rewriting legitimately breaks DKIM)
- **Proofpoint verdict passthrough** — surfaces the `X-Proofpoint` verdict directly; a PPS flag is the single highest-weight signal
- **Header mismatch detection** — flags Reply-To and Return-Path domains that differ from the From domain
- **Display name impersonation** — catches display names claiming to be IT, security, Microsoft, PayPal, etc. when the actual sending domain doesn't match
- **Link text vs. href mismatch** — detects the classic trick of showing `paypal.com` in anchor text while the href goes elsewhere
- **Credential-harvesting phrase detection** — matches common lure phrases ("verify your account", "update your credentials", etc.)
- **Urgency and generic greeting detection** — soft signals for pressure language and impersonal salutations
- **Numeric risk score** with a four-tier verdict (MINIMAL / LOW / MEDIUM / HIGH)

---

## Requirements

- Python 3.6 or later
- No third-party packages — standard library only

---

## Installation

```
git clone https://github.com/RyanSecEng/phish-analyzer.git
cd phish-analyzer
```

No install step needed. Run directly with Python.

To save an email as `.eml`:
- **Outlook**: File → Save As → Outlook Message Format or `.eml`
- **Gmail**: Open message → three-dot menu → Download message
- **Thunderbird**: File → Save As → File

---

## Example Usage

```
python3 phish-analyzer.py suspicious.eml
```

---

## Example Output

```
Analyzing suspicious.eml...

=== HEADER SUMMARY ===
  Proofpoint in path: YES
  From:        IT Security <security-alerts@gmail.com>
  Reply-To:    (none)
  Return-Path: bounce@mailer-relay.ru
  Subject:     URGENT: Your account will be suspended
  [Auth-Results #1] spf=fail smtp.mailfrom=mailer-relay.ru; dkim=fail; dmarc=fail
  [PPS] X-Proofpoint-Spam-Details: rule=phish classifier=phish ...

=== LINKS (Proofpoint-decoded) ===
  -> https://login.microsoftonline.com.verify-account.ru/signin
  -> https://track.mailer-relay.ru/open?id=abc123

=== SIGNALS ===
  [+4] Proofpoint itself flagged this message (X-Proofpoint-Spam-Details)
  [+3] Authority/brand display name from freemail (gmail.com)
  [+3] Link DISPLAYS 'microsoftonline.com' but actually goes to 'verify-account.ru'
  [+2] Link goes to verify-account.ru, not sender domain gmail.com
  [+2] Credential-harvesting phrase: 'verify your account'
  [+1] SPF failed  (LOW conf — Proofpoint may have broken this)
  [+1] Urgency/lure keyword in SUBJECT: 'urgent'
  [+1] Generic greeting (no real name): 'dear user'

=== RISK SCORE: 17  ->  HIGH — strong phishing indicators ===

Proofpoint detected: raw SPF/DKIM/DMARC fails scored LOW (they
break on clean mail here). PPS flagged this — weight heavily.

Note: content signals (greetings, urgency, phrasing) are SOFT —
modern AI-written phishing has clean grammar and personalized
greetings. Your strongest evidence is the decoded link destinations,
link-text/href mismatches, and Proofpoint's own verdict. Triage aid
only — you make the call.
```

---

## How It Works

The analyzer assigns each signal a weight and sums them into a risk score.

| Tier | Score | Meaning |
|------|-------|---------|
| MINIMAL | 0 | No signals fired |
| LOW | 1–2 | Minor indicators, likely benign |
| MEDIUM | 3–5 | Suspicious, warrants investigation |
| HIGH | 6+ | Strong phishing indicators |

**Signal weights:**

| Weight | Signal |
|--------|--------|
| +4 | Proofpoint's own verdict flags the message as phish/malware/spam |
| +3 | Display name impersonation, or link text/href domain mismatch |
| +2 | Reply-To or Return-Path domain mismatch; external link destination; credential-harvesting phrase; DKIM/DMARC fail (no Proofpoint) |
| +1 | SPF fail; no auth headers; Message-ID domain mismatch; urgency keyword; generic greeting; body pressure language |

Proofpoint-aware mode automatically reduces SPF, DKIM, and DMARC weights to +1 when Proofpoint is detected in the mail path, since relay rewriting routinely breaks those checks on clean mail.

---

## Known Limitations

- **Proofpoint v2 hex heuristic** — the v2 decoder reverses Proofpoint's `%`→`-` substitution by turning any `-XX` (where `XX` are two hex digits, `0-9`/`a-f`) back into `%XX`. This preserves most literal hyphens, but a hyphen followed by two hex characters in a real link will be mis-decoded — e.g. `support-365.com` or `route-1a.example` get garbled because `-36`/`-1a` look like percent-encodings. This affects more than just rare domains; treat a v2-decoded destination containing a hyphen-plus-digits segment with suspicion and verify it manually. URLs without such sequences, and the common case of Proofpoint-wrapped links, decode correctly.
- **Content signals are noisy** — urgency words, generic greetings, and credential phrases fire on legitimate bulk mail (password reset emails, bank statements, IT notifications). Treat them as soft context, not verdicts.
- **Links are decoded, not fetched** — no DNS lookups, no page rendering, no sandbox. A convincing domain name (`login.microsoftonline.com.verify-account.ru`) requires human judgment to evaluate.
- **Basic HTML parser** — heavily obfuscated HTML (CSS-hidden text, zero-font-size tricks, Unicode lookalikes) may not be detected.
- **Attachments are not analyzed** — only the email body and headers are inspected. Malicious payloads in PDF or Office attachments are out of scope.
- **No public suffix awareness** — `same_domain_family()` uses suffix matching rather than a full public suffix list, so unusual registry structures (e.g., `co.uk` second-level domains) may produce occasional mismatches.
- **Single-file input only** — no batch mode; run once per email.

---

## Roadmap

- Batch mode: analyze a directory of `.eml` files and produce a summary table
- JSON output flag for piping results into a SIEM or ticketing system
- Optional VirusTotal / URLhaus reputation lookup for decoded link destinations
- Public suffix list (PSL) integration for accurate eTLD+1 domain comparison
- Attachment hashing (MD5/SHA256) for known-malware lookups
- Configurable weight overrides via a config file
- MIME attachment type inventory (flags unexpected executables or macros)

---

## License

MIT — see [LICENSE](LICENSE) for details.
