# Bug Bounty Methodology Checklist

This repository contains a comprehensive methodology and checklist for bug bounty hunting, covering recon, enumeration, and exploitation techniques. It is designed to assist security researchers and penetration testers in systematically identifying vulnerabilities in web applications, networks, and infrastructure.

## Table of Contents

1. [Recon Phase](#recon-phase)
   - [Large Scope](#large-scope-company-with-multiple-domains)
   - [Medium Scope](#medium-scope-single-domain)
   - [Small Scope](#small-scope-single-website)
2. [Network Recon](#network-recon)
3. [User Management](#user-management)
   - [Registration](#registration)
   - [Authentication](#authentication)
4. [Session Management](#session-management)
5. [Input Handling](#input-handling)
6. [Error Handling](#error-handling)
7. [Application Logic](#application-logic)
8. [Other Checks](#other-checks)
   - [CAPTCHA Bypass](#captcha-bypass)
   - [Security Headers](#security-headers)

---

## Recon Phase

### Large Scope: Company with Multiple Domains

- [ ] Get ASN for IP ranges using: 
  - [Amass](https://github.com/OWASP/Amass), [Asnlookup](https://github.com/yassineaboukir/Asnlookup), [Metabigor](https://github.com/j3ssie/metabigor), [BGP](https://bgp.he.net/)
- [ ] Review latest [acquisitions](https://www.crunchbase.com/)
- [ ] Get registrant relationships: 
  - [ViewDNS](https://viewdns.info/reversewhois/)
- [ ] Move to "Medium Scope" for each domain

### Medium Scope: Single Domain

- [ ] Enumerate subdomains:
  - [Amass](https://github.com/OWASP/Amass), [Subfinder](https://github.com/projectdiscovery/subfinder)
- [ ] Subdomain bruteforce:
  - [PureDNS](https://github.com/d3mondev/puredns), [Wordlist](https://gist.github.com/six2dez/a307a04a222fab5a57466c51e1569acf)
- [ ] Subdomain permutation:
  - [Gotator](https://github.com/Josue87/gotator), [Ripgen](https://github.com/resyncgg/ripgen)
- [ ] Identify live subdomains:
  - [Httpx](https://github.com/projectdiscovery/httpx)
- [ ] Subdomain takeover check:
  - [Nuclei Takeovers](https://github.com/projectdiscovery/nuclei-templates/tree/master/takeovers)
- [ ] Cloud asset discovery:
  - [CloudEnum](https://github.com/initstring/cloud_enum)
- [ ] Screenshot subdomains:
  - [Gowitness](https://github.com/sensepost/gowitness), [Aquatone](https://github.com/michenriksen/aquatone)

### Small Scope: Single Website

- [ ] Identify web server and tech stack:
  - [Httpx](https://github.com/projectdiscovery/httpx)
- [ ] Locate common files like `/robots.txt`, `/sitemap.xml`, etc.
- [ ] Source code review (using comments):
  - Burp Suite Engagement Tools
- [ ] Directory enumeration:
  - [FFUF](https://github.com/ffuf/ffuf), [OneListForAll Wordlist](https://github.com/six2dez/OneListForAll)
- [ ] Web fuzzing:
  - [FFUF](https://github.com/ffuf/ffuf)
- [ ] Discover URLs and APIs:
  - [Gau](https://github.com/lc/gau), [Waybackurls](https://github.com/tomnomnom/waybackurls)
- [ ] Test CORS vulnerabilities:
  - [CORScanner](https://github.com/chenjj/CORScanner), [Corsy](https://github.com/s0md3v/Corsy)

---

## Network Recon

- [ ] Check DMARC/SPF policies:
  - [SpoofCheck](https://github.com/BishopFox/spoofcheck)
- [ ] Port scanning (all ports):
  - [Nmap](https://nmap.org/)
- [ ] UDP port scanning:
  - [Udp-proto-scanner](https://github.com/CiscoCXSecurity/udp-proto-scanner)
- [ ] SSL/TLS testing:
  - [TestSSL](https://github.com/drwetter/testssl.sh)

---

## User Management

### Registration

- [ ] Test for duplicate registrations (e.g., `user+1@mail.com`)
- [ ] Check for weak password policies
- [ ] Rate-limiting on registration

### Authentication

- [ ] Test username enumeration
- [ ] Test for brute-force resilience
- [ ] Test multi-stage authentication (OAuth, SAML, JWT)

---

## Session Management

- [ ] Test session fixation
- [ ] Test CSRF tokens
- [ ] Validate secure cookies (`HTTPOnly`, `Secure`)
- [ ] Check session expiration on logout

---

## Input Handling

- [ ] Test for Reflected XSS:
  - [Dalfox](https://github.com/hahwul/dalfox)
- [ ] Test for SQL Injection:
  - [SQLmap](https://sqlmap.org/)
- [ ] Test for Server-Side Request Forgery (SSRF):
  - [Gopherus](https://github.com/tarunkant/Gopherus)
- [ ] Test for Local File Inclusion (LFI)

---

## Error Handling

- [ ] Generate and analyze custom error pages
- [ ] Test HTTP header injection
- [ ] Use fuzzing techniques to generate error codes:
  - [Burp Suite](https://portswigger.net/burp)

---

## Application Logic

- [ ] Test for multi-step process logic flaws (e.g., gift codes, payments)
- [ ] Test for client-side validation bypass
- [ ] IDOR checks (access control for sensitive resources)

---

## Other Checks

### CAPTCHA Bypass

- [ ] Bypass CAPTCHA using OCR tools:
  - [Tesseract OCR](https://github.com/tesseract-ocr/tesseract)

### Security Headers

- [ ] Check for missing headers like:
  - `X-XSS-Protection`, `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`

---

## Contributing

Feel free to submit a pull request if you find additional tools, techniques, or methodologies that should be included. We welcome all contributions from the bug bounty community!

---

This checklist provides a systematic approach to finding and exploiting vulnerabilities in bug bounty programs. It serves as a quick reference to ensure you cover all critical aspects during your testing process.

