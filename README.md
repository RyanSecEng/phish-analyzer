# phish-analyzer

A local, dependency-free triage tool that parses a saved `.eml` file and scores it for phishing signals. Built for analysts who want a fast first-pass read on a suspicious email without uploading it to an external service.

---

## Why

Most email security tools require cloud access or API keys, or only tell you what their scanner already decided. This one gives you the raw evidence: decoded links, auth failures in context, header mismatches, and content signals, so you can make the call yourself. It runs entirely offline and touches nothing outside your machine.

---

## Features

- **Proofpoint URL Defense decoding** - unwraps v2 and v3 redirect links to show the real destination
- **Auth header analysis** - reads all `Authentication-Results` headers and scores SPF, DKIM, and DMARC failures; adjusts confidence automatically when Proofpoint is in the mail path (where URL rewriting legitimately breaks DKIM)
- **Proofpoint verdict passthrough** - surfaces the `X-Proofpoint` verdict directly; a PPS flag is the single highest-weight signal
- **Header mismatch detection** - flags Reply-To and Return-Path domains that differ from the From domain, compared at the registrable-domain level so legitimate subdomain splits (`mail.corp.com` vs `corp.com`) don't false-positive
- **Public Suffix List accuracy** - all domain comparisons use the registrable domain (eTLD+1) via a bundled PSL snapshot, so multi-label suffixes (`co.uk`, `com.au`) are handled correctly and cousin domains sharing a suffix (`servicea.gov.uk` vs `serviceb.gov.uk`) are recognised as different organisations
- **Display name impersonation** - catches display names claiming to be IT, security, Microsoft, PayPal, etc. when the actual sending domain doesn't match
- **Link text vs. href mismatch** - detects the classic trick of showing `paypal.com` in anchor text while the href goes elsewhere
- **Credential-harvesting phrase detection** - matches common lure phrases ("verify your account", "update your credentials", etc.)
- **Urgency and generic greeting detection** - soft signals for pressure language and impersonal salutations
- **Numeric risk score** with a four-tier verdict (MINIMAL / LOW / MEDIUM / HIGH)

---

## Requirements

- Python 3.6 or later
- No third-party packages, standard library only
- `public_suffix_list.dat` (bundled in this repo) must sit next to `phish-analyzer.py` for accurate eTLD+1 comparison. If it's missing, the tool still runs but falls back to a simpler last-two-labels heuristic and prints a one-line warning.

---

## Installation

```
git clone https://github.com/RyanSecEng/phish-analyzer.git
cd phish-analyzer
```

No install step needed. Run directly with Python. The bundled `public_suffix_list.dat` ships with the clone, so there's nothing else to fetch and no network access required at runtime.

To save an email as `.eml`:
- **Outlook**: File -> Save As -> Outlook Message Format or `.eml`
- **Gmail**: Open message -> three-dot menu -> Download message
- **Thunderbird**: File -> Save As -> File

---

## Example Usage

```
python phish-analyzer.py suspicious.eml
```

**Options:**

| Flag | Effect |
|------|--------|
| `-q`, `--quiet` | Print only the final risk-score line (banner, headers, and detail suppressed). Handy for scripting or scanning many files. |
| `-v`, `--verbose` | Show full detail, including every decoded link (the default view caps the list at 25). |

Output is **color-coded** by risk tier and includes a visual severity meter, e.g. `RISK SCORE: 25  [██████████]  HIGH`. Colors are emitted only to an interactive terminal and are automatically disabled when output is piped or redirected, or when the `NO_COLOR` environment variable is set.

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
  [+1] SPF failed  (LOW conf - Proofpoint may have broken this)
  [+1] Urgency/lure keyword in SUBJECT: 'urgent'
  [+1] Generic greeting (no real name): 'dear user'

=== RISK SCORE: 17  [██████████]  HIGH - strong phishing indicators ===

Proofpoint detected: raw SPF/DKIM/DMARC fails scored LOW (they
break on clean mail here). PPS flagged this - weight heavily.

Note: content signals (greetings, urgency, phrasing) are soft;
modern AI-written phishing has clean grammar and personalized
greetings. The strongest evidence is the decoded link destinations,
link-text/href mismatches, and Proofpoint's own verdict.
```

---

## How It Works

The analyzer assigns each signal a weight and sums them into a risk score.

| Tier | Score | Meaning |
|------|-------|---------|
| MINIMAL | 0 | No signals fired |
| LOW | 1-2 | Minor indicators, likely benign |
| MEDIUM | 3-5 | Suspicious, warrants investigation |
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

## Tests

A `unittest` suite (standard library, no extra packages) covers the core logic: Proofpoint v2/v3 link decoding, eTLD+1 registrable-domain comparison, terminal-escape sanitization, and an end-to-end run over crafted phishing and benign `.eml` fixtures.

```
python -m unittest discover -v
```

---

## Known Limitations

- **Proofpoint v2 hex heuristic** - the v2 decoder reverses Proofpoint's `%`->`-` substitution by turning any `-XX` (where `XX` are two hex digits, `0-9`/`a-f`) back into `%XX`. This preserves most literal hyphens, but a hyphen followed by two hex characters in a real link will be mis-decoded, e.g. `support-365.com` or `route-1a.example` get garbled because `-36`/`-1a` look like percent-encodings. Treat a v2-decoded destination containing a hyphen-plus-digits segment with suspicion and verify it manually. URLs without such sequences decode correctly.
- **Content signals are noisy** - urgency words, generic greetings, and credential phrases fire on legitimate bulk mail (password reset emails, bank statements, IT notifications). Treat them as soft context, not verdicts.
- **Links are decoded, not fetched** - no DNS lookups, no page rendering, no sandbox. A convincing domain name (`login.microsoftonline.com.verify-account.ru`) requires human judgment to evaluate.
- **Basic HTML parser** - heavily obfuscated HTML (CSS-hidden text, zero-font-size tricks, Unicode lookalikes) may not be detected.
- **Attachments are not analyzed** - only the email body and headers are inspected. Malicious payloads in PDF or Office attachments are out of scope.
- **PSL snapshot ages** - domain comparison uses a point-in-time copy of the Public Suffix List (`public_suffix_list.dat`). Newly delegated suffixes added after the snapshot won't be recognised until you refresh it (see *Maintenance* below).
- **Single-file input only** - no batch mode; run once per email.

---

## Roadmap

- Batch mode: analyze a directory of `.eml` files and produce a summary table
- JSON output flag for piping results into a SIEM or ticketing system
- Optional VirusTotal / URLhaus reputation lookup for decoded link destinations
- Attachment hashing (MD5/SHA256) for known-malware lookups
- `--no-color` and `--help`/`-h` flags
- Grouped, prioritized signals (sorted highest-weight first, under Auth / Links / Content subheadings)

---

## Maintenance

### Updating the Public Suffix List

The bundled `public_suffix_list.dat` is a snapshot from [publicsuffix.org](https://publicsuffix.org/list/). It changes slowly, but refresh it every few months so newly delegated suffixes are recognised. Re-download the official file, replacing the one in the repo:

```
# PowerShell
Invoke-WebRequest -Uri https://publicsuffix.org/list/public_suffix_list.dat -OutFile public_suffix_list.dat

# curl
curl -o public_suffix_list.dat https://publicsuffix.org/list/public_suffix_list.dat
```

The file's header records the `VERSION` date of the snapshot. No code changes are needed; the analyzer reads the new file on its next run. Only pull this list from the official URL above; mirrors are not guaranteed to be supported.

---

## License

MIT, see [LICENSE](LICENSE) for details.
