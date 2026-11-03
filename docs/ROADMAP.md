# gravyard — Development Roadmap

Build order chosen to go from cryptography fundamentals to practical
security engineering. Each phase adds tool modules to its subpackage and
registers them in `crypto/__init__.py`.

## Phase 1 — Hashing fundamentals ✅

- [x] `crypto/hashing/hash_generator.py` — `hash-gen`: SHA-2/SHA-3/BLAKE2 + legacy MD5/SHA-1, files/text, `--check` verification
- [x] `crypto/hashing/hash_id.py` — `hash-id`: identify algorithms from format/length/prefix
- [x] `crypto/hashing/hash_cracker.py` — `hash-crack`: dictionary + brute-force (MD5/SHA1/SHA256/SHA512/NTLM), CTF labs only
- [x] `crypto/hashing/hmac_tool.py` — `hmac`: HMAC generate/verify (constant-time comparison)

## Phase 2 — Classical cryptography ✅

- [x] `crypto/ciphers/caesar.py` — `caesar`: encode/decode/brute (chi-squared ranking)
- [x] `crypto/ciphers/vigenere.py` — `vigenere`: keyword encode/decode
- [x] `crypto/ciphers/xor.py` — `xor`: repeating-key encode/decode + single-byte brute (Cryptopals-style)
- [x] `crypto/ciphers/substitution.py` — `substitution`: encode/decode/genkey
- [x] `crypto/ciphers/frequency.py` — `freq`: letter frequencies, index of coincidence, exact Caesar auto-solve, best-effort substitution hill-climbing

## Phase 3 — Modern symmetric cryptography ✅

- [x] `crypto/encryption/file_encryptor.py` — `fileenc`: AES-256-GCM / ChaCha20-Poly1305, PBKDF2/Argon2id, self-describing tamper-evident header (also `info` action)
- [x] `crypto/encryption/key_generator.py` — `keygen`: CSPRNG keys, hex/base64/raw, key files (mode 600)
- [x] `crypto/encryption/password_kdf.py` — `kdf`: PBKDF2/Argon2id derive + parameter benchmarking
- [x] `crypto/passwords/strength_checker.py` — `passcheck`: entropy, patterns, common lists, HIBP range API (k-anonymity), crack-time table, scripted exit codes
- [x] `crypto/passwords/generator.py` — `passgen`: passwords (per-class guarantee, ambiguous-char filter) + passphrases (~600-word built-in list or custom)
- [x] `crypto/passwords/vault.py` — `vault`: init/add/get/list/remove, AES-256-GCM entries under a PBKDF2-stretched master password, mode-600 file

## Phase 4 — Asymmetric cryptography ✅

- [x] `crypto/asymmetric/rsa.py` — `rsa`: playground keygen (p/q/n/e/d visible), textbook encrypt/decrypt (number + text), Pollard's-rho `factor` demo of why small moduli fall
- [x] `crypto/asymmetric/diffie_hellman.py` — `dh`: safe-prime exchange `demo`, manual `pub`/`secret`, and `attack` — BSGS discrete log that breaks toy parameters to show why 2048-bit primes exist
- [x] `crypto/asymmetric/ed25519.py` — `ed25519`: keygen (PEM files / raw hex), sign, verify (constant path through the production library), X25519 exchange demo
- [x] `crypto/asymmetric/keypair.py` — `keypair`: real PEM key files (rsa2048/3072/4096, ed25519, x25519), private keys mode 600

## Phase 5 — Authentication and integrity ✅

- [x] `crypto/authentication/jwt_inspector.py` — `jwt-inspect`: decode header/claims, expiry countdown, red flags (alg=none, symmetric confusion risk, missing exp)
- [x] `crypto/authentication/jwt_tester.py` — `jwt-test`: alg:none forge, token crafting, HS256 weak-secret dictionary attack, RSA key-confusion forgery — **LAB USE ONLY**
- [x] `crypto/signatures/digital_signature.py` — `sig`: RSA-PSS (SHA-256) detached signatures, sign + verify, signature files
- [x] `crypto/signatures/signature_verifier.py` — `verify-sig`: public-key-only verifier with key-type auto-detection (RSA-PSS / Ed25519 / ECDSA)
- [x] file integrity monitor — `crypto/signatures/integrity.py` (`integrity`): SHA-256 baselines, modified/added/removed/touched detection, scripted exit codes

## Phase 6 — Advanced cryptographic structures ✅

- [x] `crypto/blockchain/merkle_tree.py` — `merkle`: build, inclusion proofs, verification (SHA-256, Bitcoin-style odd-node duplication)
- [x] `crypto/blockchain/hash_explorer.py` — `chain`: toy proof-of-work chain — mine, show, tamper, verify (watch hash-chaining + PoW detect rewrites)

## Phase 7 — Security analysis ✅

- [x] `crypto/tls/certificate_inspector.py` — `tlsinfo`: live cert details (subject/issuer/SANs/expiry countdown/key type), TLS version probing
- [x] `crypto/analysis/entropy_analyzer.py` — `entropy`: Shannon entropy, chi-squared uniformity, sample-size-aware verdicts
- [x] `crypto/analysis/benchmark.py` — `cryptobench`: hash + AEAD throughput on this machine
- [x] `crypto/steganography/image_stego.py` — `stego`: LSB hide/extract/analyze with the three required workflows — message-to-image generation, hide-in-provided-image, or interactive ask

## Steganography (planned UX — user requirement) — ✅ delivered in phase 7

`crypto/steganography/image_stego.py` implements the three required
workflows: message-only → auto-generated noise cover; `--image` → hide in
the provided image; neither → interactive ask. Audio (WAV LSB) support
remains a stretch goal.

---

# webtest module — roadmap

Authorized-use note: the recon/audit tools send a handful of requests; the
active phases (3+) send more and belong strictly against lab apps you run
yourself or written-permission targets. See SCOPE.md.

## Phase 1 — reconnaissance ✅

- [x] `webtest/subdomain_enum.py` — `subdomain-enum`: crt.sh certificate-transparency + DNS candidate resolution with wildcard detection
- [x] `webtest/fingerprint.py` — `fingerprint`: server/framework/CMS from headers, cookie names, generator meta, HTML markers
- [x] `webtest/security_txt.py` — `security-txt`: RFC 9116 fields, Contact/Expires validation
- [x] `webtest/robots_analyzer.py` — `robots`: directives, sitemaps, interesting paths

## Phase 2 — HTTP hardening audits ✅

- [x] `webtest/header_auditor.py` — `headers`: CSP/HSTS/nosniff/framing/referrer/leaks, CI exit codes
- [x] `webtest/cookie_analyzer.py` — `cookies`: Secure/HttpOnly/SameSite/Domain scope/__Host- rules
- [x] `webtest/cors_tester.py` — `cors`: origin reflection, null origin, preflight probing
- [x] `webtest/clickjacking_tester.py` — `clickjacking`: X-Frame-Options / frame-ancestors verdict + local PoC file
- [x] `webtest/cache_analyzer.py` — `cache`: sensitive-response cacheability
- [x] `webtest/content_type_analyzer.py` — `content-type`: MIME mismatch + sniffing exposure

## Phase 3 — discovery (active, lab targets) ✅

- [x] `webtest/dir_bruteforcer.py` — `dirbrute`: wordlist + extension brute-force, soft-404 baseline filtering, threaded
- [x] `webtest/open_redirect.py` — `redirect`: Location/meta-refresh/JS detection across a bypass ladder (protocol-relative, backslash, encoded), reserved-domain canary never contacted
- [x] `webtest/path_traversal.py` — `traversal`: classic/filtered/encoded/absolute ladder (linux + windows), marker-confirmed or filesystem-error indicators
- [x] `webtest/vuln_mapper.py` — `vuln-map`: fingerprint versions → offline mini-CVE-database with range rules (curriculum-sized; cross-check NVD/OSV)

## Phase 4 — injection & fuzzing (active, lab targets) ✅

- [x] `webtest/form_fuzzer.py` — `fuzz`: HTML form discovery (stdlib parser), controlled OWASP-style payload list, reaction triage (raw echo / escaped / errors / status+length deltas)
- [x] `webtest/sqli_tester.py` — `sqli`: error-based (5 DB engines), boolean differentials (true-branch ≈ baseline, false-branch differs), time-based (SLEEP/WAITFOR/pg_sleep)
- [x] `webtest/xss_detector.py` — `xss`: nonce canary across tag/attribute/JS contexts — raw echo vs escaped; server-side reflection only (DOM XSS needs a browser)
- [x] `webtest/api_fuzzer.py` — `api-fuzz`: JSON mutation battery (empty/malformed/wrong-type/null/huge/extra/deep) + GraphQL introspection & field-suggestion probes
- [x] `webtest/smuggling_analyzer.py` — `smuggle`: self-contained raw-socket CL/TE probes (smuggled-GET, duplicate CL, TE obfuscation) — no connection poisoning

## Phase 5 — auth, sessions & abuse (active, lab targets) ✅

- [x] `webtest/auth_tester.py` — `auth`: username enumeration (message + timing), empty credentials, cleartext transport, password echo
- [x] `webtest/authz_tester.py` — `authz`: full credential×object matrix, hash-based IDOR detection, unauthenticated access checks (two controlled lab accounts)
- [x] `webtest/rate_limit.py` — `ratelimit`: bounded burst (max 200), 429/lockout/progressive-delay analysis with exit codes
- [x] `webtest/websocket_tester.py` — `ws`: minimal RFC 6455 client — CSWSH origin probe, pre-auth message handling, cleartext transport check

## Phase 6 — reporting ✅

- [x] `webtest/site_analyzer.py` — `site`: passive audit battery (~10 requests) aggregated into a self-contained HTML + JSON report
- [x] `webtest/screenshot.py` — `screenshot`: browser strategy evaluated in order (playwright → chromium binaries → headless firefox), no hidden downloads

---

# crawler module — roadmap

Authorized-use note: everything here collects **public source data only** —
polite rate-limited GETs, robots.txt honoured, scope-locked to the seed
host/domain, private addresses refused (SSRF guard). Breach checks use the
authorized HIBP API paths (verified domains / addresses you may query) and
never retrieve passwords. See SCOPE.md.

Shared infrastructure (`crawler/core/`): requests-based client with manual
redirect following + scope checks on every hop, per-host rate limiter,
HTML extraction (bs4 with stdlib fallback), JSON result store under
`gravyard-crawler/<target>/`.

## Phase 1 — crawl fundamentals ✅

- [x] `crawler/engine/crawler.py` — `crawl`: BFS/DFS site crawler with depth/page budgets, robots + Crawl-delay, scope lock, extraction pipeline (emails/social/params/assets/js)
- [x] `crawler/engine/bfs.py`, `dfs.py` — queue/stack traversal wrappers (also standalone)
- [x] `crawler/engine/robots.py` — RFC 9309-style matcher (longest path wins), Crawl-delay, sitemap discovery
- [x] `crawler/engine/sitemap.py` — `sitemap`: urlset + sitemapindex parsing, lastmod/priority, per-extension counts
- [x] `crawler/engine/url_manager.py` — URL normalization + BFS/DFS frontiers
- [x] `crawler/core/storage.py` — per-target JSON result store feeding `report`

## Phase 2 — information extraction ✅

- [x] `crawler/extraction/email_harvester.py` — `emails`: mailto + text addresses, `[at]/[dot]` deobfuscation, false-positive filtering
- [x] `crawler/extraction/social_harvester.py` — `social`: 17 platforms from page links, reserved-path filtering
- [x] `crawler/extraction/url_extractor.py` — `urls`: every referenced URL, categorized internal/external × page/document/asset/feed
- [x] `crawler/extraction/endpoint_collector.py` — `endpoints`: API endpoints from HTML + first-party JS (fetch/axios, /api/, graphql, wp-json)
- [x] `crawler/extraction/js_analyzer.py` — `js`: routes, URLs, bundler hints, source maps; potential credentials flagged but REDACTED
- [x] `crawler/extraction/metadata_extractor.py` — `metadata`: EXIF (Pillow, GPS → coordinates), PDF Info dict, OOXML core properties; files, directories or URLs
- [x] `crawler/extraction/document_collector.py` — `docs`: document link discovery + optional size-capped download with sha256
- [x] `crawler/extraction/document_extractor.py` — `doc-text`: text + properties from PDF (PyMuPDF) and DOCX/XLSX/PPTX (stdlib zipfile)

## Phase 3 — domain intelligence ✅

- [x] `crawler/domain/dns_intel.py` — `dns`: A/AAAA/MX/NS/TXT/SOA/CAA/PTR via a self-contained raw DNS client (UDP + TCP retry, no dnspython)
- [x] `crawler/domain/whois_lookup.py` — `whois`: RDAP via rdap.org (registrar, dates, statuses, abuse contact), python-whois fallback
- [x] `crawler/domain/ct_explorer.py` — `ct`: crt.sh log search → subdomains, issuers, expiring certificates
- [x] `crawler/domain/ip_intel.py` — `ip`: ip-api (geo/ASN/hosting flags) + RDAP netblock owner + reverse DNS
- [x] `crawler/domain/domain_mapper.py` — `domain-map`: CT subdomains → A records → ASNs/orgs → registrar as a nodes/edges graph (networkx GraphML optional)

## Phase 4 — external intelligence (keyed tools need your own accounts) ✅

- [x] `crawler/intelligence/breach_checker.py` — `breach`: HIBP v3 — account search (authorized addresses), verified-domain search, breach metadata; no password endpoints
- [x] `crawler/intelligence/shodan.py` — `shodan`: search / host / info via the official API
- [x] `crawler/intelligence/censys.py` — `censys`: v2 host search / view with basic auth
- [x] `crawler/intelligence/wayback.py` — `wayback`: CDX snapshot listing + `id_` raw snapshot fetch via availability API
- [x] `crawler/intelligence/search_dorker.py` — `dork`: duckduckgo (keyless) / Google CSE / Azure Bing backends
- [x] `crawler/intelligence/social_osint.py` — `social-osint`: profile existence across 12 platforms + keyless official APIs (github/reddit/gitlab)
- [x] `crawler/intelligence/github_intel.py` — `github`: repo/user/code search with scoped dork presets (token required for code)
- [x] `crawler/intelligence/rss_intel.py` — `rss`: feed autodiscovery + RSS2/Atom parsing (stdlib ElementTree)

## Phase 5 — analysis & reporting ✅

- [x] `crawler/analysis/wayback_diff.py` — `wayback-diff`: snapshot vs live (or two snapshots), text diff + similarity
- [x] `crawler/analysis/change_monitor.py` — `change-monitor`: sha256 baseline file, text diff, `--exit-changed` for cron
- [x] `crawler/analysis/technology_intel.py` — `tech`: CMS/framework/library/analytics fingerprints from headers + markup (published versions only)
- [x] `crawler/analysis/parameter_analyzer.py` — `params`: query parameter inventory with sink-name flagging (discovery only)
- [x] `crawler/analysis/resource_mapper.py` — `resources`: third-party origin map with SRI/crossorigin coverage
- [x] `crawler/reporting/aggregator.py` — `recon`: passive/keyless battery (dns → whois → ct → ip → crawl-lite → sitemap → wayback) + report
- [x] `crawler/reporting/osint_report.py` — `report`: markdown (+ HTML) OSINT report from the result store
- [x] `crawler/reporting/export.py` — `export`: stored JSON → CSV / markdown / XLSX

Tests: `tests/crawler_lab.py` (offline lab site) + `tests/test_crawler_core.py`
+ `tests/test_crawler_live.py` (66 tests).

