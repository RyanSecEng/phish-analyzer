# phish-analyzer

Parses a saved `.eml` file and scores it for phishing signals. It runs locally with no dependencies, so you can triage a suspicious email without uploading it anywhere.

---

## Why

Most email security tools need cloud access or an API key, or just hand you a verdict their scanner already reached. This one shows the evidence instead: decoded links, auth results in context, header mismatches, and content signals. The call is left to you, and nothing leaves your machine.

---

## Features

### Built to keep false positives down

The analyzer splits every signal into two classes:

- **Hard signals** - structural evidence of a disguise or attack: bad links, spoofed display names, dangerous attachments, auth failures. These always score.
- **Soft signals** - language and style cues (urgency, generic greetings, lure phrases). These are noisy on legitimate bulk mail, so they **only count toward the score when a hard signal also fired and the sender is not authenticated or allowlisted**. Otherwise they are listed under a separate `CONTEXT (not scored)` heading. This corroboration gate is the main false-positive reducer.

Trust is decided from the **top** `Authentication-Results` header only - the one your own mail boundary stamps - so an attacker cannot forge a `dmarc=pass` lower in the message to silence the language signals.

### Detections

- **Link unwrapping** - decodes Proofpoint URL Defense (v2/v3), Microsoft Safelinks, Mimecast, Barracuda, and Google AMP wrappers to show the real destination
- **Open-redirect / cloaking** - spots a link on one site whose query string forwards to a different domain ("a link hidden inside a link")
- **Sender spoofing** - real sending address is parsed from the angle-bracket address (an `@domain` planted in the display name can't fool it); flags a display name that embeds a different brand/domain, role-word impersonation (IT, security, PayPal...) from a mismatched or freemail domain, and a sender domain that is itself a typosquat or homograph of a brand
- **Auth header analysis** - scores SPF, DKIM, and DMARC failures; auto-lowers confidence when Proofpoint is in the mail path (where URL rewriting legitimately breaks DKIM)
- **Proofpoint verdict passthrough** - surfaces the `X-Proofpoint` verdict directly; a PPS flag carries the most weight
- **Header mismatch detection** - Reply-To to freemail/known-bad is a hard BEC tell; ordinary Reply-To/Return-Path splits are soft and skipped entirely for DMARC-passing mail or known ESP/bounce domains, compared at the registrable-domain level
- **Public Suffix List accuracy** - domain comparisons use the registrable domain (eTLD+1) via a bundled PSL snapshot, so multi-label suffixes (`co.uk`, `com.au`) and cousin domains (`servicea.gov.uk` vs `serviceb.gov.uk`) are handled correctly
- **Link text vs. href mismatch** - the classic trick of showing `paypal.com` in anchor text while the href goes elsewhere
- **Look-alike link domains** - mixed-script homographs (`pаypal.com` with a Cyrillic `а`), typosquats of the sender or a known brand (`paypa1.com`), brand names buried as a subdomain (`microsoft.com.verify.ru`), and punycode (`xn--`) domains shown as they actually read
- **Dangerous link mechanics** - raw-IP hosts, the `user@host` deception trick, `javascript:`/`data:` hrefs, `<form>` posting to an external domain, `<meta http-equiv="refresh">` auto-redirects, link shorteners, high-abuse TLDs, non-standard ports, and excessively deep subdomains
- **Known-bad lists** - link or sender domains matched against a local blocklist you can refresh from free public feeds (see *Reference lists*)
- **Attachment triage** - lists each attachment with size and SHA-256; flags dangerous executable/script types, macro-enabled Office files, **HTML/SVG attachments** (local phishing pages), archives, and misleading double extensions (`invoice.pdf.exe`). Files are never opened or detonated
- **Hidden-text and obfuscation checks** - CSS-hidden text carrying a lure phrase, and zero-width/bidi control characters
- **Readable report** - a verdict headline up top, decoded links, and signals grouped by category and sorted by weight, with a four-tier risk score (MINIMAL / LOW / MEDIUM / HIGH)
- **Batch mode** - point it at a folder or several files for a one-line-per-file summary table

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
python phish-analyzer.py suspicious.eml          # full report for one file
python phish-analyzer.py ./samples               # summary table for a folder
python phish-analyzer.py a.eml b.eml c.eml       # summary table for several files
```

A single file prints the full report. Point it at a folder (or pass several files) and it prints a one-line-per-file summary table instead, so you can triage a batch at a glance and then re-run the interesting ones on their own.

**Options:**

| Flag | Effect |
|------|--------|
| `-q`, `--quiet` | Print only the risk-score line per file (banner, headers, and detail suppressed). Handy for scripting or scanning many files. |
| `-v`, `--verbose` | Show full detail, including every decoded link (the default view caps the list at 25). |

The report leads with a `VERDICT` block (tier, score, and the heaviest few signals), then header summary, decoded links, and the full `SIGNALS` list grouped under Authentication / Sender / Links / Attachments / Content and sorted by weight. Output is **color-coded** by risk tier with a severity meter, e.g. `RISK SCORE 25  [██████████]  HIGH`. Colors are emitted only to an interactive terminal and are disabled when output is piped or redirected, or when `NO_COLOR` is set.

---

## Example Output

```
Analyzing suspicious.eml...

=== VERDICT ===
  RISK SCORE 17  [██████████]  HIGH - strong phishing indicators
    [+4] Proofpoint itself flagged this message (X-Proofpoint-Spam-Details)
    [+3] Authority/brand display name from freemail (gmail.com)
    [+3] Link DISPLAYS 'microsoftonline.com' but actually goes to 'verify-account.ru'

=== HEADER SUMMARY ===
  Known-bad list: 525445 hosts, feed 2 day(s) old
  Proofpoint in path: YES
  From:        IT Security <security-alerts@gmail.com>
  Reply-To:    (none)
  Return-Path: bounce@mailer-relay.ru
  Subject:     URGENT: Your account will be suspended
  [Auth-Results #1] spf=fail smtp.mailfrom=mailer-relay.ru; dkim=fail; dmarc=fail
  [PPS] X-Proofpoint-Spam-Details: rule=phish classifier=phish ...

=== LINKS (decoded) ===
  -> https://login.microsoftonline.com.verify-account.ru/signin
  -> https://track.mailer-relay.ru/open?id=abc123

=== SIGNALS ===
  Authentication
    [+4] Proofpoint itself flagged this message (X-Proofpoint-Spam-Details)
    [+1] SPF failed  (LOW conf - Proofpoint may have broken this)
  Sender / headers
    [+3] Authority/brand display name from freemail (gmail.com)
  Links
    [+3] Link DISPLAYS 'microsoftonline.com' but actually goes to 'verify-account.ru'
    [+3] Brand domain 'microsoftonline.com' appears inside link host but the real domain is 'verify-account.ru'
  Content
    [+2] Credential-harvesting phrase: 'verify your account'
    [+1] Urgency/lure keyword in SUBJECT: 'urgent'
    [+1] Generic greeting (no real name): 'dear user'

Proofpoint detected: raw SPF/DKIM/DMARC fails scored LOW (they
break on clean mail here). PPS flagged this - weight heavily.

Note: language signals (greetings, urgency, phrasing) count toward
the score only when a structural signal also fired and the sender is
not authenticated or allowlisted; otherwise they are listed as context.
```

Here the urgency and greeting cues **are** scored, because hard signals fired and the sender is not authenticated. On a DMARC-passing or allowlisted email those same lines would instead appear under a `=== CONTEXT (not scored) ===` heading and contribute 0 to the score.

A batch run (folder or several files) looks like:

```
=== BATCH SUMMARY ===
  HIGH     score 17   suspicious.eml
  MEDIUM   score 4    newsletter-with-shortener.eml
  MINIMAL  score 0    lunch-invite.eml
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

**Hard signals (always scored):**

| Weight | Signal |
|--------|--------|
| +4 | Proofpoint's own verdict flags the message as phish/malware/spam; link domain on the known-bad list |
| +3 | Display name embeds a different brand/domain; role-word impersonation; sender-domain typosquat; link text/href mismatch; homograph or typosquat link domain; brand buried in link subdomain; open-redirect cloaking; deceptive `user@host` link; external `<form>` post; dangerous attachment type; HTML/SVG attachment; misleading double extension |
| +2 | Reply-To to freemail/known-bad; DKIM/DMARC fail (no Proofpoint); raw-IP link host; `javascript:`/`data:` href; `meta refresh` auto-redirect; macro-enabled attachment; hidden text carrying a lure phrase |
| +1 | SPF fail; zero-width/bidi characters |

**Soft signals (scored only when corroborated - see below):**

| Weight | Signal |
|--------|--------|
| +2 | Credential-harvesting phrase |
| +1 | Reply-To/Return-Path split (non-ESP, no DMARC pass); Message-ID domain mismatch; urgency keyword; generic greeting; body pressure language; link shortener; high-abuse TLD; non-standard port; deep subdomain; punycode domain; body names a brand but no link goes to it; archive attachment |

**The corroboration gate:** soft signals contribute to the score **only when at least one hard signal also fired *and* the sender is not trusted** (did not pass DMARC on the top auth header and is not on your `allowlist.txt`). Otherwise they are displayed under `CONTEXT (not scored)` and add 0. This is what keeps ordinary newsletters, password-reset emails, and bank statements out of the MEDIUM/HIGH tiers.

Proofpoint-aware mode automatically reduces SPF, DKIM, and DMARC weights to +1 when Proofpoint is detected in the mail path, since relay rewriting routinely breaks those checks on clean mail. A missing `Authentication-Results` header is treated as context (it is usually just the save/export format), not scored.

---

## Reference lists

The analyzer reads several optional plain-text lists from the directory next to `phish-analyzer.py`. Each is one entry per line; `#` starts a comment and blank lines are ignored. A missing file simply disables that check, so the tool always runs. Edit them by hand and refresh on your own schedule, the same way you maintain the Public Suffix List.

| File | Purpose | Ships with |
|------|---------|-----------|
| `allowlist.txt` | Sender domains you trust. Quiets soft language signals for that sender (hard signals still score). | **Empty** - add your own org + trusted partners |
| `esp_domains.txt` | Email service providers / bulk-mail relays / trackers. Suppresses the noisy link and header-mismatch heuristics for legitimate bulk mail. The biggest false-positive reducer. | A curated default set |
| `brands.txt` | Extra brands to compare against for typosquat/homograph/brand-in-subdomain. **Add your own org's domains here** - look-alike detection is only as good as this list. | A curated default set (merged with the built-in brands) |
| `shorteners.txt` | URL shortening services. | A curated default set |
| `suspicious_tlds.txt` | High-abuse top-level domains. | A curated default set |
| `phish_domains.txt` | Hand-curated known-bad domains (e.g. from your own incident reports). | Header + your entries |
| `phish_domains.feed.txt` | **Auto-generated** known-bad domains from free public feeds. Unioned with `phish_domains.txt`. Gitignored (large, changes daily). | Created by `update_feeds.py` |
| `feed_exclude.txt` | Major legitimate domains that must never end up on the feed, so a bad feed entry can't flag `google.com`. Used by `update_feeds.py` only. | A curated guard list |

### Refreshing the known-bad feed

`update_feeds.py` pulls free public blocklists into `phish_domains.feed.txt`. It is the only part of the project that touches the network, and the analyzer itself never runs it - run it manually whenever you want fresh data:

```
python update_feeds.py
```

Sources (all free, no API key required):
- [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database) (active phishing domains)
- [Phishing.Army](https://phishing.army/) (community blocklist)
- [abuse.ch URLhaus](https://urlhaus.abuse.ch/) (online malware URLs)

If a source is down or changes format, the others still produce a usable file. Every host is checked against `feed_exclude.txt` first, so the resulting blocklist won't contain a major legitimate domain even if a feed lists one by mistake. The file is stamped with a UTC generation time, and the report shows the feed's age (and nags when it's over two weeks old). The result is ~500k hosts and loads in well under a second. To schedule it, use Task Scheduler (Windows) or cron (Linux/macOS).

---

## Tests

A `unittest` suite (standard library, no extra packages) covers the core logic: Proofpoint v2/v3 link decoding, eTLD+1 registrable-domain comparison, terminal-escape sanitization, typosquat and homograph detection, attachment triage, hidden-text and zero-width detection, the From-address spoof parse, sender/display-name impersonation, top-header auth trust (including the forged-lower-header case), the header-mismatch gate, HTML/SVG attachments, external forms, meta-refresh and `javascript:` links, a `report()` render smoke test, and end-to-end runs over crafted phishing and benign `.eml` fixtures (including false-positive guards for normal third-party links, DMARC-passing mail, and marketing preheaders).

```
python -m unittest discover -v
```

---

## Known Limitations

- **Proofpoint v2 hex heuristic** - the v2 decoder reverses Proofpoint's `%`->`-` substitution by turning any `-XX` (where `XX` are two hex digits, `0-9`/`a-f`) back into `%XX`. This preserves most literal hyphens, but a hyphen followed by two hex characters in a real link will be mis-decoded, e.g. `support-365.com` or `route-1a.example` get garbled because `-36`/`-1a` look like percent-encodings. Treat a v2-decoded destination containing a hyphen-plus-digits segment with suspicion and verify it manually. URLs without such sequences decode correctly.
- **Content signals are noisy by nature** - urgency words, generic greetings, and credential phrases fire on legitimate bulk mail (password resets, bank statements, IT notifications). That is exactly why they are soft and gated behind the corroboration rule; on their own they appear under `CONTEXT` and score 0. Tune `allowlist.txt` and `esp_domains.txt` to quiet them further for senders you trust.
- **Trust hinges on the top auth header** - the corroboration gate treats a `dmarc=pass` on the topmost `Authentication-Results` header as trusted. This is correct only if that header was added by *your* mail boundary. If you analyze a raw message captured before it reached your gateway (no trusted header on top), DMARC trust won't apply and more soft signals may score.
- **Known-bad feed ages fast** - `phish_domains.feed.txt` is a point-in-time snapshot of public feeds; a domain registered after your last `update_feeds.py` run won't be on it. Refresh regularly. The feeds also occasionally list a since-cleaned domain, so a known-bad hit is strong evidence but still worth a glance.
- **Links are decoded, not fetched** - no DNS lookups, no page rendering, no sandbox. A convincing domain name (`login.microsoftonline.com.verify-account.ru`) requires human judgment to evaluate.
- **HTML parser is best-effort** - it now catches CSS-hidden text and zero-width/bidi characters, but malformed markup or more exotic tricks (off-screen positioning, colour-on-colour text, image-only bodies) can still slip past.
- **Typosquat/homograph detection is conservative** - it catches mixed-script labels and common character swaps against the sender and a built-in brand list, so unusual look-alikes or brands not on the list won't be flagged. The decoded link list is still shown for manual review.
- **Attachments are flagged, not inspected** - each attachment is listed with its size and SHA-256, and risky types/extensions are scored, but files are never opened or detonated. Malicious payloads *inside* a PDF or Office document are out of scope; use the SHA-256 for an external lookup.
- **PSL snapshot ages** - domain comparison uses a point-in-time copy of the Public Suffix List (`public_suffix_list.dat`). Newly delegated suffixes added after the snapshot won't be recognised until you refresh it (see *Maintenance* below).
- **Batch mode is top-level only** - pointing at a folder picks up `.eml` files in that folder, not subfolders, and the table view omits the per-signal detail (re-run a single file for that).

---

## Roadmap

- JSON output flag for piping results into a SIEM or ticketing system
- `--no-color` and `--help`/`-h` flags, and exit codes by risk tier for scripting
- Recursive batch mode (walk subfolders) and an optional CSV summary
- Optional online enrichment (Safe Browsing, VirusTotal by hash/URL-ID) behind an explicit `--online` flag, off by default

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
