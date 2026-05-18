# Bug Bounty Methodology

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)
![PRs](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)

A practitioner-focused methodology and checklist for bug bounty hunting and web application penetration testing. Tight, tool-linked, and structured by attack surface.

For the condensed pre-flight checklist, see [`BB-Checklist.md`](BB-Checklist.md).

---

## Table of Contents

1. [Recon & Asset Discovery](#recon--asset-discovery)
   - [Large Scope (Org / Multi-Domain)](#large-scope-org--multi-domain)
   - [Medium Scope (Single Domain)](#medium-scope-single-domain)
   - [Small Scope (Single Host)](#small-scope-single-host)
2. [Network Recon](#network-recon)
3. [JavaScript & Client-Side Analysis](#javascript--client-side-analysis)
4. [API Testing](#api-testing)
   - [REST](#rest)
   - [GraphQL](#graphql)
5. [Authentication](#authentication)
6. [Session Management](#session-management)
7. [Authorization (IDOR / BAC)](#authorization-idor--bac)
8. [Input Handling](#input-handling)
   - [XSS](#xss)
   - [SQLi / NoSQLi](#sqli--nosqli)
   - [SSRF](#ssrf)
   - [SSTI](#ssti)
   - [XXE](#xxe)
   - [LFI / RFI / Path Traversal](#lfi--rfi--path-traversal)
   - [Command Injection](#command-injection)
   - [Prototype Pollution](#prototype-pollution)
9. [Business Logic](#business-logic)
10. [Race Conditions](#race-conditions)
11. [HTTP Request Smuggling](#http-request-smuggling)
12. [Cloud Misconfigurations](#cloud-misconfigurations)
13. [Mobile (Quick Reference)](#mobile-quick-reference)
14. [Misc Checks](#misc-checks)
15. [Reporting](#reporting)
16. [Contributing](#contributing)
17. [License](#license)

---

## Recon & Asset Discovery

### Large Scope (Org / Multi-Domain)

- ASN & IP ranges — [Amass](https://github.com/OWASP/Amass), [Asnlookup](https://github.com/yassineaboukir/Asnlookup), [Metabigor](https://github.com/j3ssie/metabigor), [bgp.he.net](https://bgp.he.net/)
- Acquisitions & subsidiaries — [Crunchbase](https://www.crunchbase.com/), SEC filings, Wikipedia
- Registrant pivots — [ViewDNS Reverse Whois](https://viewdns.info/reversewhois/), [WhoxyAPI](https://www.whoxy.com/)
- Trademark / favicon pivots — [Shodan favicon hash](https://github.com/devanshbatham/FavFreak), [FOFA](https://fofa.info/), [ZoomEye](https://www.zoomeye.org/)
- GitHub recon for org — [trufflehog](https://github.com/trufflesecurity/trufflehog), [github-search](https://github.com/gwen001/github-search), [gitleaks](https://github.com/gitleaks/gitleaks)
- For each in-scope domain, drop to **Medium Scope**

### Medium Scope (Single Domain)

- Passive subdomain enum — [Amass](https://github.com/OWASP/Amass), [Subfinder](https://github.com/projectdiscovery/subfinder), [Assetfinder](https://github.com/tomnomnom/assetfinder), [crt.sh](https://crt.sh/)
- Active bruteforce — [PureDNS](https://github.com/d3mondev/puredns), [shuffledns](https://github.com/projectdiscovery/shuffledns) + [six2dez wordlist](https://gist.github.com/six2dez/a307a04a222fab5a57466c51e1569acf)
- Permutations — [Gotator](https://github.com/Josue87/gotator), [Ripgen](https://github.com/resyncgg/ripgen), [alterx](https://github.com/projectdiscovery/alterx)
- Resolve & probe — [dnsx](https://github.com/projectdiscovery/dnsx), [httpx](https://github.com/projectdiscovery/httpx) (capture status, title, tech, CDN, CNAME)
- Subdomain takeover — [Nuclei takeover templates](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/takeovers), [subzy](https://github.com/PentestPad/subzy), [dnsReaper](https://github.com/punk-security/dnsReaper)
- Cloud asset discovery — [cloud_enum](https://github.com/initstring/cloud_enum), [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Visual recon — [gowitness](https://github.com/sensepost/gowitness), [Aquatone](https://github.com/michenriksen/aquatone), [eyeballer](https://github.com/BishopFox/eyeballer)
- Historical hostnames — [waybackurls](https://github.com/tomnomnom/waybackurls), [gau](https://github.com/lc/gau), Chaos
- Port-scan all live hosts — see [Network Recon](#network-recon)

### Small Scope (Single Host)

- Tech fingerprinting — [httpx](https://github.com/projectdiscovery/httpx), [whatweb](https://github.com/urbanadventurer/WhatWeb), [Wappalyzer](https://www.wappalyzer.com/)
- Common files — `/robots.txt`, `/sitemap.xml`, `/.well-known/`, `/.git/`, `/.env`, `/server-status`, `/crossdomain.xml`
- Crawl + passive URL harvest — [katana](https://github.com/projectdiscovery/katana), [hakrawler](https://github.com/hakluke/hakrawler), [gau](https://github.com/lc/gau), [waybackurls](https://github.com/tomnomnom/waybackurls)
- Content discovery — [feroxbuster](https://github.com/epi052/feroxbuster), [ffuf](https://github.com/ffuf/ffuf), [dirsearch](https://github.com/maurosoria/dirsearch) + [OneListForAll](https://github.com/six2dez/OneListForAll)
- Parameter discovery — [Arjun](https://github.com/s0md3v/Arjun), [ParamSpider](https://github.com/devanshbatham/ParamSpider), [x8](https://github.com/Sh1Yo/x8)
- CORS — [CORScanner](https://github.com/chenjj/CORScanner), [Corsy](https://github.com/s0md3v/Corsy); manually test `Origin: null`, wildcard with credentials, regex bypasses
- Nuclei sweep — [nuclei](https://github.com/projectdiscovery/nuclei) with `-severity medium,high,critical`

---

## Network Recon

- Full TCP — `nmap -p- --min-rate 5000 -T4 <target>` then `-sCV` on found ports
- UDP top ports — `nmap -sU --top-ports 200`
- Mass scan — [masscan](https://github.com/robertdavidgraham/masscan), [naabu](https://github.com/projectdiscovery/naabu)
- TLS/SSL — [testssl.sh](https://github.com/drwetter/testssl.sh), [sslyze](https://github.com/nabla-c0d3/sslyze)
- Email spoofing — [SpoofCheck](https://github.com/BishopFox/spoofcheck) (DMARC/SPF/DKIM)
- Service-specific — SMB, RDP, Redis, Memcached, MongoDB, Elasticsearch, Docker API exposure

---

## JavaScript & Client-Side Analysis

- Collect JS — [subjs](https://github.com/lc/subjs), [getJS](https://github.com/003random/getJS), katana with `-jc`
- Endpoint extraction — [LinkFinder](https://github.com/GerbenJavado/LinkFinder), [xnLinkFinder](https://github.com/xnl-h4ck3r/xnLinkFinder), [JSluice](https://github.com/BishopFox/jsluice)
- Secrets in JS — [trufflehog](https://github.com/trufflesecurity/trufflehog), [SecretFinder](https://github.com/m4ll0k/SecretFinder), [Nosey Parker](https://github.com/praetorian-inc/noseyparker)
- Source map review — pull `.map` files, reconstruct original source with [sourcemapper](https://github.com/denandz/sourcemapper)
- DOM sinks — Burp DOM Invader, manual review of `eval`, `innerHTML`, `document.write`, `postMessage`, `location.*`
- Webpack analysis — [webpack-exploder](https://github.com/spaceraccoon/webpack-exploder)

---

## API Testing

### REST

- Spec discovery — `/swagger`, `/swagger.json`, `/api-docs`, `/openapi.json`, `/v1/`, `/v2/`, `/graphql`
- Verb tampering — try `PUT`, `DELETE`, `PATCH`, `OPTIONS` on `GET` endpoints
- Content-type confusion — swap `application/json` ↔ `application/xml` ↔ `application/x-www-form-urlencoded`
- Mass assignment — add `isAdmin`, `role`, `verified`, `userId` to payloads
- Rate limit bypass — `X-Forwarded-For`, `X-Real-IP`, `X-Originating-IP`, casing changes, null bytes, path/param mutation
- Versioning — test old API versions (`/v1/` may lack fixes in `/v2/`)
- [Kiterunner](https://github.com/assetnote/kiterunner) for content discovery on APIs (uses HTTP verbs and routes wordlists)

### GraphQL

- Introspection — `{__schema{types{name fields{name}}}}`; if disabled, try [clairvoyance](https://github.com/nikitastupin/clairvoyance)
- IDE access — `/graphql`, `/graphiql`, `/playground`, `/console`
- Batching attacks — send array of queries to bypass rate limits / brute force
- Alias-based abuse — repeated aliased queries for brute force
- Field suggestion leak — typo in field name to leak schema
- Mutation enumeration — focus on `delete*`, `update*`, `create*Admin*`
- Tools — [InQL](https://github.com/doyensec/inql), [graphql-cop](https://github.com/dolevf/graphql-cop), [graphw00f](https://github.com/dolevf/graphw00f)

---

## Authentication

- Username enumeration via login, register, password reset, response timing
- Password policy (length, complexity, common-password rejection, breach check)
- Brute force resilience — account lockout, IP throttling, CAPTCHA after N attempts
- 2FA — bypass via response manipulation, backup code abuse, race conditions, missing rate limits on OTP, OTP reuse
- Password reset — token entropy/reuse, host header injection, `email[]=victim&email[]=attacker`, Unicode normalization
- OAuth — `redirect_uri` validation (path traversal, open redirect, subdomain), `state` parameter (CSRF), implicit flow leaks, scope upgrade
- SAML — XML signature wrapping, comment injection, `xmlns` confusion, [SAML Raider](https://github.com/CompassSecurity/SAMLRaider)
- JWT — `alg: none`, `alg: HS256` with public key as secret, `kid` injection (path traversal, SQLi), JWK injection, weak HMAC secret ([jwt_tool](https://github.com/ticarpi/jwt_tool), [hashcat](https://hashcat.net/))
- SSO — host header / session confusion between SP and IdP
- Magic links — predictable tokens, no expiry, reuse, login CSRF

---

## Session Management

- Session fixation — does login regenerate the session ID?
- CSRF — token presence, validation, reuse across users, `SameSite` cookie attribute
- Cookie flags — `HttpOnly`, `Secure`, `SameSite`, `__Host-`/`__Secure-` prefixes
- Logout — server-side invalidation? Token usable post-logout?
- Concurrent sessions — does login N+1 kill session N?
- Timeout — idle vs absolute
- Session token entropy and predictability

---

## Authorization (IDOR / BAC)

- Horizontal — swap IDs (numeric, UUID, base64, hashed) between two test accounts
- Vertical — low-priv user accessing admin endpoints; check direct URL, not just UI
- Method-based — endpoint hidden from UI but reachable via direct request
- Parameter pollution — `?user=victim&user=attacker`
- ID encoding — try wrapping ID in array, JSON object, different encoding
- Mass IDOR — [Autorize](https://github.com/Quitten/Autorize) (Burp), [AuthMatrix](https://github.com/SecurityInnovation/AuthMatrix)
- GUIDs / UUIDs — check for v1 (timestamp-predictable) vs v4 (random)
- Tenant isolation — multi-tenant apps: try IDs from tenant A while logged in as tenant B

---

## Input Handling

### XSS

- Reflected/stored — [Dalfox](https://github.com/hahwul/dalfox), [XSStrike](https://github.com/s0md3v/XSStrike), manual payload tuning
- DOM — Burp DOM Invader, manual sink analysis
- Blind XSS — [XSS Hunter Express](https://github.com/mandatoryprogrammer/xsshunter-express), [Interactsh](https://github.com/projectdiscovery/interactsh)
- CSP bypass — review `Content-Security-Policy`; look for `unsafe-inline`, `unsafe-eval`, overly broad CDNs, JSONP endpoints, [csp-evaluator](https://csp-evaluator.withgoogle.com/)
- Filter bypass — case, encoding, event handlers, SVG, `<details>`, `<dialog open ontoggle>`, mutation XSS

### SQLi / NoSQLi

- Manual probe — `'`, `''`, `"`, `--`, `OR 1=1`, time-based payloads
- Automation — [sqlmap](https://sqlmap.org/) with `--risk=3 --level=5` (in scope only)
- Blind boolean / time-based — when no output reflection
- NoSQL — `{"$ne": null}`, `{"$gt": ""}`, `{"$regex": ".*"}` (MongoDB)
- 2nd-order — payload stored then triggered elsewhere
- ORM-specific quirks — Hibernate HQL, Sequelize, Prisma

### SSRF

- Standard targets — `http://127.0.0.1`, `http://localhost`, `http://[::]`, `http://0.0.0.0`
- Cloud metadata — AWS `169.254.169.254`, GCP `metadata.google.internal`, Azure `169.254.169.254/metadata/instance`, IMDSv2 token flow
- DNS rebinding — [singularity](https://github.com/nccgroup/singularity)
- Bypasses — decimal/octal IPs, URL parsers, `@` confusion, redirect chains, gopher/file/dict schemes ([Gopherus](https://github.com/tarunkant/Gopherus))
- Blind SSRF — out-of-band via [interactsh](https://github.com/projectdiscovery/interactsh), Burp Collaborator

### SSTI

- Polyglot probe — `${{<%[%'"}}%\`
- Engine-specific payloads — Jinja2 `{{7*7}}`, Twig `{{7*'7'}}`, Freemarker `<#assign>`, ERB `<%= %>`
- [tplmap](https://github.com/epinna/tplmap) for automation
- PortSwigger SSTI labs map almost 1:1 to real targets

### XXE

- Classic — `<!ENTITY xxe SYSTEM "file:///etc/passwd">`
- Blind — OOB DTD via Burp Collaborator
- Parameter entities, SVG upload XXE, DOCX/XLSX/ODT XXE, SOAP XXE
- Billion laughs / quadratic blowup for DoS (only if in scope)

### LFI / RFI / Path Traversal

- `../`, encoded variants, `....//`, null byte (legacy), filter wrappers (`php://filter/convert.base64-encode/resource=`)
- Log poisoning → RCE
- Wordlists — [LFI-Payloads](https://github.com/payloadbox/rfi-lfi-payload-list)

### Command Injection

- Separators — `;`, `&&`, `|`, `` ` ``, `$()`, newline
- Blind — DNS/HTTP OOB callbacks
- [commix](https://github.com/commixproject/commix) for automation

### Prototype Pollution

- Client-side — pollute via URL/JSON, check sink in [PP-finder](https://github.com/dwisiswant0/ppfuzz) or DOM Invader
- Server-side (Node.js) — `__proto__`, `constructor.prototype` in JSON bodies
- Gadgets per framework (Express, Mongoose, Lodash)

---

## Business Logic

- Multi-step flow tampering — skip steps, replay, modify hidden state
- Price/quantity manipulation — negative numbers, decimal precision, currency confusion, integer overflow
- Coupon/voucher logic — stack multiple, reuse, race-apply
- Workflow bypass — KYC, age gates, terms acceptance
- Numeric edge cases — `0`, `-1`, `MAX_INT`, very large floats, scientific notation
- Client-side validation only — disable JS, intercept and modify
- File upload — extension/MIME/magic-byte mismatch, polyglots, double extension, SVG XSS, path traversal in filename, zip slip

---

## Race Conditions

- Burp Repeater "send group in parallel" / single-packet attack (HTTP/2)
- [Turbo Intruder](https://github.com/PortSwigger/turbo-intruder) `race.py` template
- High-value targets — coupon redemption, gift card claim, withdrawal, vote, like, follow, MFA verify
- Reference: PortSwigger's *Smashing the state machine*

---

## HTTP Request Smuggling

- CL.TE / TE.CL / TE.TE / CL.CL detection — [smuggler](https://github.com/defparam/smuggler), Burp HTTP Request Smuggler
- HTTP/2 downgrade smuggling (H2.CL, H2.TE)
- Browser-powered ("client-side") smuggling
- Validate impact — cache poisoning, auth bypass, request hijacking

---

## Cloud Misconfigurations

- S3 — public read/write, ACL misconfigs, bucket takeover ([S3Scanner](https://github.com/sa7mon/S3Scanner))
- GCP buckets — same idea, `storage.googleapis.com/<bucket>`
- Azure Blob — `<account>.blob.core.windows.net`
- Cloud metadata via SSRF — covered above
- IAM — overly permissive policies, leaked AWS keys ([trufflehog](https://github.com/trufflesecurity/trufflehog))
- Lambda/Functions — env vars, source via console
- Misconfigured CloudFront / CloudFlare — origin IP disclosure ([CloudFail](https://github.com/m0rtem/CloudFail))

---

## Mobile (Quick Reference)

- APK/IPA static — [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF), [apktool](https://github.com/iBotPeaches/Apktool), [jadx](https://github.com/skylot/jadx)
- iOS — [Frida](https://frida.re/), [Objection](https://github.com/sensepost/objection), Cycript
- SSL pinning bypass — Frida scripts ([frida-scripts](https://codeshare.frida.re/))
- Hardcoded secrets — same JS-style hunt against decompiled source
- Deep links / URL schemes — intent redirection, WebView abuse
- Backup analysis — `adb backup`, plist files on iOS

---

## Misc Checks

- Security headers — `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` (note: many of these are informational findings on most programs)
- CAPTCHA — OCR ([Tesseract](https://github.com/tesseract-ocr/tesseract)), reuse of solved token, removal of CAPTCHA parameter, automation of audio CAPTCHA
- Open redirect — useful as chain primitive (OAuth, SSRF filter bypass)
- Cache poisoning — unkeyed headers, parameter cloaking ([Param Miner](https://github.com/PortSwigger/param-miner))
- Web cache deception — `/account.php/nonexistent.css`
- Dependency confusion — internal package names published publicly on npm/PyPI
- Email injection — header injection in contact forms, SMTP smuggling

---

## Reporting

A solid report is often the gap between a bounty and a "won't fix":

- Clear, single-sentence title with impact
- Severity per program rules (avoid self-rating CVSS without justification)
- Steps to reproduce — numbered, copy-pasteable, no missing context
- Proof — screenshot or short video; redact your own creds
- Impact — *what could an attacker actually do?* Tie to the program's stated assets/data
- Remediation — short, suggestive, not prescriptive
- Don't include unrelated findings in one report — file separately

---

## Contributing

PRs welcome. Useful additions: new tools that meaningfully change a workflow, missing attack classes, real-world bypasses. Please keep entries tight and link to authoritative sources.

---

## License

[MIT](LICENSE) — use freely, attribution appreciated.

---

This is a living document. Methodology evolves; treat it as a scaffold, not a script.
