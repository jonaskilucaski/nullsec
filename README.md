# NullSec

**Current version:** v1.0.2

**NullSec** is a Bash-based bug bounty reconnaissance automation framework that organizes target discovery, validation, web probing, URL collection, prioritization, vulnerability scanning, JavaScript analysis, visual reconnaissance, fuzzing, and reporting into a checkpointed multi-phase workflow.

It is designed for **authorized security research only**. Use it exclusively on assets you own or on targets for which you have explicit permission to test.

> [!IMPORTANT]
> NullSec produces a mixture of confirmed findings, scanner matches, and investigation leads. Candidate files such as `xss-candidates.txt`, `sqli-candidates.txt`, `idor-candidates.txt`, and Nuclei output must be manually validated before submission to a bug bounty program.

## Features

- Three scan presets: `fast`, `normal`, and `deep`
- Passive and active subdomain discovery
- DNS resolution and wildcard filtering
- Subdomain takeover checks
- Ownership-aware cloud storage enumeration
- HTTP probing, technology detection, and status-code grouping
- Virtual-host discovery paused pending request-boundary enforcement
- Port scanning and alternate web-service detection
- Live, in-scope URL corpus generation
- Parameter discovery and endpoint categorization
- Local asset scoring and target prioritization
- Nuclei vulnerability and exposure scanning
- JavaScript download, secret detection, and endpoint extraction
- SSRF, redirect, XSS, SQLi, LFI, IDOR, CORS, and host-header lead generation
- Optional Dalfox and SQLMap validation
- Gowitness integration retained but disabled pending browser egress enforcement
- Opt-in ffuf directory and backup-file enumeration; virtual-host fuzzing is disabled
- Active Nuclei confirmation in deep mode
- Checkpoint-based resume support
- Safe interrupt handling and child-process cleanup
- Previous-result preservation under `prior-runs/`
- Optional Telegram notifications
- Final text report with an executive summary

## Responsible Use

Before running NullSec:

1. Read the program policy and safe-harbor terms.
2. Confirm the exact in-scope domains and excluded assets.
3. Check whether automated scanning, port scanning, fuzzing, OAST, or high request rates are permitted.
4. Adjust concurrency, rate limits, timeouts, and scan mode for the target.
5. Never submit raw automated output without manual reproduction and impact analysis.

NullSec enforces an apex-domain boundary for many downstream inputs, but **scope validation remains the operator's responsibility**. Wildcard program scope, third-party services, shared infrastructure, acquisitions, CDNs, and cloud resources can require additional ownership verification.

## Requirements

### Platform

NullSec is intended for Linux systems with Bash and GNU command-line utilities. Kali Linux or another Debian-based penetration-testing environment is recommended.

Basic system dependencies include:

```bash
sudo apt update
sudo apt install -y bash curl jq git python3 python3-pip golang-go dnsutils seclists
```

Package availability and names may differ by distribution.

### Required tools

The script now performs **mode-aware** dependency checks. A tool is treated as fatal only when the selected scan mode enables a phase that truly needs it. Missing optional tools are reported clearly and the related check is skipped or reduced.

| Tool | Purpose | Required when |
|---|---|---|
| Amass v4 or Amass fallback | Active relationship discovery | Requires `-E`; disabled with explicit host rules |
| Subfinder | Passive subdomain enumeration | All modes |
| Assetfinder | Passive subdomain enumeration | All modes |
| dnsx | DNS validation and wildcard detection | All modes |
| httpx-toolkit | HTTP probing and metadata collection | All modes |
| Katana | Integration disabled pending request-policy enforcement | Not required |
| Waybackurls | Historical URL collection | All modes |
| GAU | Historical and indexed URL collection | All modes |
| Unfurl | URL and parameter extraction | All modes |
| Nuclei | Template-based scanning and confirmation | All modes |
| jq | JSON processing | All modes |
| curl | HTTP requests with default configuration and redirects disabled | All modes |
| PureDNS | Generated DNS enumeration | Requires `-E`; disabled with explicit host rules |
| Naabu | Port scanning | Requires `-E` and `normal`/`deep` |
| ffuf | Non-recursive content enumeration | Requires `-E` and `deep`; virtual-host path disabled |
| Arjun | Active parameter discovery with redirects disabled | Requires `-E` and `deep` |

> [!NOTE]
> The expected ProjectDiscovery binary name is `httpx-toolkit`. This avoids conflicts with the unrelated Python package named `httpx`.

### Optional tools

NullSec continues when optional tools are unavailable, but the related checks are skipped or reduced.

| Tool | Enhancement |
|---|---|
| Gotator | Subdomain permutation generation |
| Gowitness | Screenshot capture |
| Dalfox | Automated XSS testing |
| SQLMap | SQL injection testing |
| gf | Higher-signal URL pattern filtering |
| anew | Efficient unique-result merging |
| qsreplace | Query-string manipulation support |
| Hakrawler | Response-based crawling and discovery |
| Cariddi | Endpoint and secret-oriented crawling |
| dig | DNS ownership evidence collection |
| cloud_enum | Detected but intentionally not used for ungated global-name mutation |
| S3Scanner | Optional cloud tooling |
| TruffleHog | Local JavaScript secret detection by default; live credential verification requires explicit `-V` authorization or its environment equivalent |

### Wordlists

The tool check also reports missing or unreadable wordlists/resolvers based on the selected mode. Missing wordlists do not crash the script; the related phase is skipped or reduced with a warning.

The default configuration expects:

```text
/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt
/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt
/usr/share/wordlists/resolvers.txt
```

Create a resolver file when it does not already exist:

```bash
sudo tee /usr/share/wordlists/resolvers.txt >/dev/null <<'RESOLVERS'
1.1.1.1
1.0.0.1
8.8.8.8
8.8.4.4
9.9.9.9
208.67.222.222
RESOLVERS
```

Modify the paths in the configuration section of `nullsec.sh` when your installation differs.

### Nuclei templates

NullSec detects Nuclei templates in this order:

1. `NUCLEI_TEMPLATES` when it is set and points to a valid directory
2. `$HOME/.local/nuclei-templates`
3. `$HOME/nuclei-templates`

Install or update templates manually:

```bash
nuclei -ut
```

If your templates are installed under the newer local path, you can also set:

```bash
export NUCLEI_TEMPLATES="$HOME/.local/nuclei-templates"
```

Missing templates show a warning only; normal mode does not fail only because the template directory is absent.
During authorized vulnerability scanning, `-u` requests a template update.

## Installation

```bash
git clone https://github.com/jonaskilucaski/nullsec.git
cd nullsec
chmod +x nullsec.sh
```

Confirm the script parses correctly:

```bash
bash -n nullsec.sh
```

Recommended quick smoke test before a real scan:

```bash
./nullsec.sh -h
./nullsec.sh -d your-owned-test-domain.com -m fast -s -o /tmp/nullsec-smoke
```

Use only safe targets you own or are explicitly allowed to test.

Display the built-in help:

```bash
./nullsec.sh -h
```

Display the current version:

```bash
./nullsec.sh --version
```

Expected output:

```text
NullSec Framework v1.0.2
Created by Jonaski
```

## Quick Start

Run the default `normal` scan:

```bash
./nullsec.sh -d example.com
```

Run with a custom Amass timeout:

```bash
NULLSEC_AMASS_TIMEOUT=1800 ./nullsec.sh -d example.com
```

Use the Nuclei templates environment variable:

```bash
export NUCLEI_TEMPLATES="$HOME/.local/nuclei-templates"
./nullsec.sh -d example.com
```

Run a lightweight scan:

```bash
./nullsec.sh -d example.com -m fast
```

Select deep-mode limits with polite inter-phase delays (authorization defaults remain conservative):

```bash
./nullsec.sh -d example.com -m deep -r
```

Write results to a specific new directory:

```bash
./nullsec.sh -d example.com -m normal -o ./results/example-normal
```

Resume an interrupted scan:

```bash
./nullsec.sh -d example.com -m normal -c ./recon-example.com-20260707-090000
```

## Command-Line Options

```text
Usage: ./nullsec.sh -d <target-domain> [options]

  -d <domain>   Target domain; required
  -o <dir>      New output directory
  -m <mode>     fast, normal, or deep; default: normal
  -s            Skip the dependency check
  -u            Update Nuclei templates before scanning
  -r            Add polite delays between phases
  -i <file>     Approved host scope (exact hosts or *.suffix patterns)
  -x <file>     Excluded host scope (exact hosts or *.suffix patterns)
  -C <file>     Approved cloud resources (provider:name; exact names only)
  -E            Explicitly authorize active enumeration
  -A            Explicitly authorize vulnerability validation
  -V            Explicitly authorize TruffleHog credential verification
  -c <dir>      Resume from an existing NullSec output directory
  --version     Show NullSec version and author
  -h            Show help
```

The target must be a plain DNS domain such as `example.com`. Do not pass a URL, path, wildcard, IP address, CIDR range, or labels with leading/trailing hyphens.

For programs with narrower authorization boundaries, provide an explicit include file with `-i` and an exclusion file with `-x`. Scope files accept plain DNS hostnames and leading-wildcard suffixes; exclusions override inclusions. `*.api.example.com` matches `a.api.example.com` and `b.a.api.example.com`, but does not include `api.example.com` itself unless that exact host is approved separately. Case and trailing dots are normalized; blank lines and `#` comments are ignored. URLs, ports, IPs, malformed labels, and other wildcard forms are rejected.

When `-i` is omitted, NullSec defaults to the target apex plus its descendants, subject to exclusions. An explicit include file is authoritative: zero-byte and comments-only files deny all. Missing, unreadable, non-regular, or malformed authorization files cause an error before target traffic. Files are re-read and checked against the startup fingerprint before phases and request launches; changed or disappearing files block further work.

Active enumeration requires `-E`; vulnerability validation requires `-A`; credential/API verification requires `-V`. Each has an explicit environment equivalent below. Enabling one class does not enable another, and scan modes still limit which stages run. Installing a tool never grants authorization.

`-o` and `-c` cannot be used together. A new `-o` directory must be empty. Resume requires identical target, mode, and normalized authorization policy; old scans without policy metadata must use a new directory.

## Scan Modes

| Mode | Intended use | Main behavior | Approximate runtime |
|---|---|---|---|
| `fast` | Frequent checks | Passive sources, scoped DNS/HTTP discovery and historical URLs. Nuclei additionally requires `-A`. | Target-dependent |
| `normal` | Daily reconnaissance | Adds local prioritization, JS analysis and candidate classification. Generated DNS/port enumeration requires `-E`; cloud probes require `-C`; vulnerability checks require `-A`. | Target-dependent |
| `deep` | Broader authorized coverage | Adds opt-in Arjun/content enumeration with `-E` and confirmation with `-A`; higher configured limits do not grant authorization. | Target-dependent |

Runtime depends on the number of discovered assets, target responsiveness, network conditions, WAF behavior, tool versions, and configured limits.

## Workflow

### Phase 1 — Subdomain discovery

Collects and merges passive results from Subfinder, Assetfinder and crt.sh. Amass active discovery, PureDNS brute force and Gotator resolution require `-E` and are disabled when host include/exclude files are supplied, because these paths generate requests before complete rule enforcement. Hakrawler discovery is disabled.

Primary outputs:

```text
phase1-subdomains/all-subdomains.txt
phase1-subdomains/amass-clean.txt
phase1-subdomains/amass-detailed.txt
```

`amass-detailed.txt` is diagnostic graph output only. NullSec merges only `amass-clean.txt` into the final subdomain corpus.

### Phase 2 — Validation and resolution

Scopes candidates before dnsx resolution. Wildcard filtering uses automatic mode when advertised, otherwise manual `-wd TARGET`; help failures or unrecognized contracts block resolution. With explicit host rules, only approved candidates are resolved and generated-name wildcard probes are disabled. Partial failed DNS output stays unvalidated. Nuclei takeover checks additionally require `-A`.

Primary outputs:

```text
phase2-validation/valid-subdomains.txt
phase2-validation/resolved.txt
phase2-validation/wildcards.txt
phase2-validation/takeover-findings.txt
```

### Phase 2.5 — Cloud storage enumeration

Builds possible S3, Google Cloud Storage, and Azure names and records provider-specific ownership evidence found in target-controlled DNS or web content.

**Cloud references are discovery evidence, not authorization.** Provider requests are disabled unless the operator supplies `-C <file>`. The approval file contains exact resources in `provider:name` form, for example:

```text
s3:example-assets
gcs:example-public
azure:examplestorage
```

Only names that are both corroborated by target-controlled evidence and present in this explicit approval file may be probed. Other candidates are retained as **not probed**. Public-write detection uses anonymous ACL, policy, or IAM inspection rather than uploading a test object.

Primary outputs:

```text
phase2.5-cloud/ownership-evidence.txt
phase2.5-cloud/exposed/unverified-candidates.txt
phase2.5-cloud/exposed/all-exposed-buckets.txt
phase2.5-cloud/exposed/critical-writable.txt
```

### Phase 3 — Live web probing

Uses httpx-toolkit on approved inputs to identify web services, collect titles and technologies, and group status codes. Cross-host redirects are disabled; designated metadata/JS validation probes may follow same-host redirects. Virtual-host discovery is disabled pending a request-boundary adapter for direct-IP and generated Host-header traffic.

Primary outputs:

```text
phase3-probing/live-hosts.txt
phase3-probing/live-hosts-detailed.txt
phase3-probing/status-200.txt
phase3-probing/status-401.txt
phase3-probing/status-403.txt
phase3-probing/status-500.txt
phase3-probing/discovered-vhosts.txt
```

### Phase 4 — Port scanning

Uses Naabu to scan common ports, then passes discovered endpoints to httpx-toolkit to identify web services on non-standard ports.

Primary outputs:

```text
phase4-portscan/open-ports.txt
phase4-portscan/services-on-ports.txt
```

### Phase 5 — URL discovery and crawling

Collects historical URLs from Waybackurls and GAU. Katana, both Hakrawler paths and Cariddi are disabled because their crawl/output scope is not a complete request authorization boundary. Provider cloud feeds are report-only and never become generic URL scan inputs. HTTPX launches reapply current host policy, with cross-host redirects disabled. curl ignores its default configuration and explicitly disables redirects.

The corpus is scope-filtered, deduplicated, parameter-collapsed, and checked for liveness. JS and active URL consumers require a complete validation marker bound to the current policy; previous GF output is intersected with current validated URLs. Scope or liveness failures are fail-closed: unvalidated candidates are retained separately instead of being promoted into trusted downstream inputs.

NullSec keeps two important URL sets:

- `all-urls.txt`: refined, live, in-scope, parameter-collapsed endpoints
- `scoped-injectable-candidates.txt`: all scoped parameterized candidate values, retained as evidence
- `all-urls-injectable.txt`: full-value candidates that passed current liveness validation; active consumers reapply scope
- `unvalidated-urls.txt` / `unvalidated-js-files.txt`: evidence that was not validated
- `validation-state.txt`: records completion and the authorization fingerprint

The phase also categorizes API endpoints, JavaScript files, sensitive paths, interesting files, and gf matches.

### Phase 6 — Parameter discovery

Extracts known parameter names locally with Unfurl. Arjun requires active-enumeration authorization (`-E`), deep mode, and an approved seed; redirects are explicitly disabled. An older Arjun that rejects this option fails the stage rather than falling back to redirect following.

Primary outputs:

```text
phase6-parameters/parameters.txt
phase6-parameters/arjun-params-*.txt
```

### Phase 6b — Asset scoring

Performs local scoring without additional network requests. Signals include response status, alternative ports, APIs, sensitive paths, interesting files, parameters, gf matches, and technology indicators.

Use the ranking to choose where to begin manual testing; it is not a vulnerability severity score.

Primary outputs:

```text
asset-scoring/scored-targets.txt
asset-scoring/top-targets.txt
asset-scoring/scoring-summary.txt
```

### Phase 7 — Nuclei scanning

Runs a consolidated severity-filtered scan and a dedicated exposure or misconfiguration scan. JSON exports are parsed into separate critical, high/medium, CVE, API, endpoint, JavaScript exposure, and general exposure files.

Primary outputs:

```text
phase7-vulns/all-findings.txt
phase7-vulns/all-findings.json
phase7-vulns/critical-findings.txt
phase7-vulns/high-medium-findings.txt
phase7-vulns/cve-findings.txt
phase7-vulns/exposure-findings.txt
```

### Phase 8 — JavaScript analysis

Downloads a bounded number of in-scope JavaScript responses with per-file and aggregate size limits. TruffleHog defaults to local `--no-verification` detection. `-V` or its explicit environment equivalent permits verification, with `--results=verified,unknown`. Raw JSON and summaries retain verified, unknown/error, and unverified states; targeted regex extraction still runs without TruffleHog. It also extracts possible in-scope API endpoints.

Primary outputs:

```text
phase8-javascript/js-files/
phase8-javascript/trufflehog-secrets.json
phase8-javascript/trufflehog-summary.txt
phase8-javascript/aws-access-keys.txt
phase8-javascript/google-api-keys.txt
phase8-javascript/github-tokens.txt
phase8-javascript/slack-tokens.txt
phase8-javascript/stripe-keys.txt
phase8-javascript/private-keys.txt
phase8-javascript/live-js-endpoints.txt
```

Treat regex-only secret matches as unverified until ownership, validity, exposure, and impact are safely established.

### Phase 9 — Vulnerability pattern hunting

Builds investigation lists for:

- SSRF
- Open redirect
- XSS
- SQL injection
- LFI
- IDOR
- CORS misconfiguration
- Host-header injection

Only with `-A`, available Dalfox and SQLMap receive deduplicated, capped, currently validated and re-scoped injection points. CORS and host-header checks include failure-window logic that stops early when throttling or network instability is detected.

Primary outputs:

```text
phase9-patterns/ssrf-candidates.txt
phase9-patterns/redirect-candidates.txt
phase9-patterns/xss-candidates.txt
phase9-patterns/dalfox-xss-confirmed.txt
phase9-patterns/sqli-candidates.txt
phase9-patterns/sqlmap-results/
phase9-patterns/lfi-candidates.txt
phase9-patterns/idor-candidates.txt
phase9-patterns/cors-findings.txt
phase9-patterns/host-injection-findings.txt
```

### Phase 10 — Screenshots

Gowitness initialization remains fixed, but screenshots are disabled: browser subresources can request third parties before any output filtering. Re-enabling this integration requires a request-policy-bound browser adapter.

Primary output:

```text
phase10-screenshots/
```

### Phase 11 — Directory and content fuzzing

Uses ffuf against a limited number of in-scope status-200 hosts. It requires `-E` and deep mode; redirects and recursion are explicitly disabled. A separate bounded pass inspects backup/configuration paths on the same approved host.

Primary outputs:

```text
phase11-fuzzing/dirs/all-found-paths.txt
phase11-fuzzing/dirs/all-found-backups.txt
phase11-fuzzing/dirs/*.json
```

### Phase 12 — Active confirmation

Deep mode with `-A` uses Nuclei to attempt bounded confirmation of selected SSRF, redirect, LFI, 403-bypass, and GraphQL leads.

Primary outputs:

```text
phase12-active-vulns/ssrf-confirmed.txt
phase12-active-vulns/redirect-confirmed.txt
phase12-active-vulns/lfi-confirmed.txt
phase12-active-vulns/403-bypass-confirmed.txt
phase12-active-vulns/graphql-findings.txt
```

## Parallel Execution

Phases 1 through 7 run sequentially. Phases 8 through 11 run in parallel with independent wall-clock watchdogs. Phase 12 starts only when the prerequisite pipeline completes successfully.

Parallel execution reduces overall runtime, but it can create a substantial combined request rate. Lower the configured worker counts and tool-specific rate limits for sensitive programs.

## Checkpoints, Resume, and Interrupt Handling

NullSec stores:

```text
.checkpoint
.scan-meta
```

The metadata binds the output directory to the target, scan mode and `AUTHORIZATION_SHA256`. The deterministic fingerprint covers the effective normalized include/exclude rules, approved cloud resources, and enumeration/validation/verification authorizations. Order, duplicate lines and comments do not change the policy. An explicit empty include differs from omitting an include. File paths and API secrets are not stored in this fingerprint metadata.

Resume refuses a missing/ambiguous fingerprint, narrower or broader rules, changed cloud approvals, changed execution authorization, or a changed mode. Use a new output directory for any policy change. Compatible resume reuses only artifacts from the same policy; revisited validations clear current outputs first.

When interrupted with `Ctrl+C`, NullSec attempts to:

- terminate registered scanner process trees;
- prevent orphaned background tools from continuing;
- clean temporary files;
- preserve partial evidence;
- archive prior outputs without restoring them as current validated inputs; and
- print a resume command.

When a resumed phase replaces an existing result, prior evidence is archived under a `prior-runs/` directory instead of being silently mixed into current findings.

## Output Structure

A typical result directory contains:

```text
recon-example.com-YYYYMMDD-HHMMSS/
├── .checkpoint
├── .scan-meta
├── phase1-subdomains/
├── phase2-validation/
├── phase2.5-cloud/
├── phase3-probing/
├── phase4-portscan/
├── phase5-urls/
├── phase6-parameters/
├── asset-scoring/
├── phase7-vulns/
├── phase8-javascript/
├── phase9-patterns/
├── phase10-screenshots/
├── phase11-fuzzing/
├── phase12-active-vulns/
└── reports/
    └── recon-report.txt
```

The final report summarizes discovery counts, live services, URL coverage, asset scores, Nuclei results, cloud checks, JavaScript secrets, pattern-hunting leads, fuzzing results, and active-confirmation output.

## Configuration

Edit the configuration section near the top of `nullsec.sh` before running large scans.

Important settings include:

```bash
HTTPX_THREADS=30
FFUF_THREADS=20
NUCLEI_RATE_LIMIT=50
NUCLEI_CONCURRENCY=25
GOWITNESS_THREADS=4

MAX_JS_FILES=50
MAX_ARJUN_HOSTS=5
MAX_SCREENSHOTS=50
MAX_CORS_HOSTS=100
MAX_SCORE_HOSTS=200
MAX_BUCKET_MUTATIONS=200
```

Phase 8 through 11 also have wall-clock timeouts, while Dalfox, SQLMap, and ffuf have dedicated execution limits and candidate caps.

### Authorization controls

The safest way to run NullSec against a bug-bounty program is to encode the program boundary instead of relying on the target domain alone:

```bash
./nullsec.sh -d example.com -m normal \
  -i approved-hosts.txt \
  -x excluded-hosts.txt
```

Environment-variable equivalents are also available:

```bash
export NULLSEC_SCOPE_INCLUDE_FILE=approved-hosts.txt
export NULLSEC_SCOPE_EXCLUDE_FILE=excluded-hosts.txt
export NULLSEC_CLOUD_APPROVAL_FILE=approved-cloud.txt
export NULLSEC_ALLOW_ACTIVE_ENUMERATION=false
export NULLSEC_ALLOW_ACTIVE_VALIDATION=false
export NULLSEC_ALLOW_SECRET_VERIFICATION=false
```

Use `-E` only for permitted active enumeration and `-A` only for permitted vulnerability validation. Use `-V` only when you are explicitly authorized to test whether discovered credentials are valid against their provider APIs.

### Amass selection

NullSec prefers a side-by-side Amass v4 binary called `amass-v4` and falls back to `amass`.

Override the behavior with environment variables:

```bash
export AMASS_PREFER_V4=true
export AMASS_V4_BIN=amass-v4
export AMASS_V4_CONFIG="$HOME/.config/amass/config.yaml"
```

Set a custom Amass timeout for larger domains:

```bash
NULLSEC_AMASS_TIMEOUT=1800 ./nullsec.sh -d example.com
```

Force the fallback binary:

```bash
export AMASS_PREFER_V4=false
```

## Telegram Notifications

Telegram is optional. Leave both values unset to run silently.

```bash
export TELEGRAM_TOKEN='your-bot-token'
export TELEGRAM_CHAT_ID='your-chat-id'
./nullsec.sh -d example.com -m normal
```

Never hardcode a real token into a public repository. If a token is exposed, revoke it immediately through BotFather.

Recommended `.gitignore` entries:

```gitignore
.env
recon-*/
results/
*.log
```

## Security and Data Handling

Reconnaissance output can contain credentials, tokens, private keys, internal endpoints, personal data, and sensitive evidence. NullSec sets `umask 077` so newly created files are restricted to the current user, but you should still:

- encrypt sensitive archives;
- avoid syncing raw results to public cloud storage;
- remove secrets before sharing logs or screenshots;
- never commit scan output to GitHub;
- follow the program's confidentiality requirements; and
- delete data when it is no longer needed.

## Troubleshooting

### A required tool is reported missing

Run:

```bash
command -v <tool-name>
```

Confirm the binary is on your `PATH`. Pay special attention to `httpx-toolkit`, `amass-v4`, and tools installed through Go.

### Wordlist or resolver errors

Verify the configured paths:

```bash
ls -lh /usr/share/wordlists/seclists/Discovery/DNS/
ls -lh /usr/share/wordlists/seclists/Discovery/Web-Content/
cat /usr/share/wordlists/resolvers.txt
```

### Amass returns no clean subdomains

Review:

```text
phase1-subdomains/amass-clean.txt
phase1-subdomains/amass-clean-export.log
phase1-subdomains/amass-detailed.txt
phase1-subdomains/amass-v4.log
phase1-subdomains/amass-error.log
phase1-subdomains/amass-version.txt
```

A zero result from one source does not necessarily mean the whole scan failed. Compare Subfinder, Assetfinder, crt.sh, PureDNS, and the merged Phase 1 output.

### A scan was interrupted

Resume with the same target, mode, policy contents and authorization flags:

```bash
./nullsec.sh -d example.com -m normal -c <existing-output-directory>
```

### Nuclei produces no findings

No output can mean no matching templates, inaccessible targets, filtering, rate limiting, WAF interference, stale templates, or a genuinely clean result. Review the Nuclei logs and statistics in `phase7-vulns/` before drawing conclusions.

### Candidate counts are very large

Candidate files are triage queues, not confirmed vulnerabilities. Start with:

```text
asset-scoring/top-targets.txt
phase7-vulns/critical-findings.txt
phase7-vulns/high-medium-findings.txt
phase9-patterns/dalfox-xss-confirmed.txt
phase9-patterns/cors-findings.txt
phase12-active-vulns/
```

Then reproduce each behavior manually with a controlled request and compare it against the program policy.

## Suggested Manual Triage Order

1. Verify scope and ownership.
2. Review critical and high Nuclei findings.
3. Inspect takeover and ownership-corroborated cloud results.
4. Review confirmed Dalfox or Phase 12 results.
5. Work through the highest-scored assets.
6. Validate CORS and host-header behavior manually.
7. Inspect JavaScript secrets and endpoints without using exposed credentials.
8. Test IDOR, authorization, business logic, and authenticated workflows manually.

## Changelog

### v1.0.2
- Fixed Nuclei templates path detection
- Added support for the NUCLEI_TEMPLATES environment variable
- Added fallback detection for $HOME/.local/nuclei-templates
- Made Amass timeout configurable
- Added NULLSEC_AMASS_TIMEOUT override
- Improved Amass timeout warning message
- Preserved Amass detailed graph output for diagnostics
- Prevented raw Amass graph data from polluting merged subdomain results
- Improved Amass zero-result terminal output

### v1.0.1
- Fixed Nuclei templates path detection
- Added support for NUCLEI_TEMPLATES environment variable
- Added fallback detection for $HOME/.local/nuclei-templates
- Improved Nuclei warning message

### v1.0.0
- Added official NullSec branding
- Added author name: Jonaski
- Added version display
- Added --version option

## Contributing

Contributions that improve reliability, scope enforcement, evidence quality, portability, rate control, or false-positive reduction are welcome.

Before submitting a change:

```bash
bash -n nullsec.sh
```

Also test the affected phase against a domain you own or a purpose-built lab. Do not include real target data, credentials, program reports, or sensitive scan output in issues or pull requests.

## Disclaimer

NullSec is provided for educational purposes and authorized security testing. The author and contributors are not responsible for misuse, service disruption, data loss, account suspension, legal consequences, or violations of third-party policies.

By using NullSec, you agree that you are solely responsible for obtaining permission, defining scope, selecting safe scan settings, validating results, and complying with all applicable laws and program rules.

---

Created by Jonaski for bug bounty reconnaissance and security research.


## Execution authorization and current limits

| Class | Control | Activities |
|---|---|---|
| Baseline reconnaissance | Target and host policy | Passive sources, approved-host DNS resolution, ordinary HTTP service/liveness discovery, local analysis |
| Active enumeration | `-E` / `NULLSEC_ALLOW_ACTIVE_ENUMERATION=true` | Mode-permitted generated DNS enumeration, port scanning, Arjun, non-recursive directory/content fuzzing |
| Vulnerability validation | `-A` / `NULLSEC_ALLOW_ACTIVE_VALIDATION=true` | Nuclei/takeover checks, Dalfox, SQLMap, CORS/Host-header manipulation, Phase 12 |
| Credential verification | `-V` / `NULLSEC_ALLOW_SECRET_VERIFICATION=true` | TruffleHog provider/API verification |
| Cloud resource inspection | `-C` / `NULLSEC_CLOUD_APPROVAL_FILE` | Exact approved resources also corroborated by discovery evidence; no upload/write tests |

Scope never expands because a more intrusive class is enabled. Cloud files require exactly `provider:name`, with `s3`, `gcs`, or `azure`; unknown providers, missing/extra colons and empty/invalid names are errors. Surrounding whitespace and provider case are normalized; resource names must satisfy lowercase provider-specific syntax. This adapter supports S3 general-purpose bucket names, GCS bucket names, and Azure storage account names (3–24 lowercase alphanumeric characters). Unsupported legacy/special S3 resource forms are rejected. Empty cloud files approve nothing. Discovery evidence alone never authorizes provider requests.

The script rechecks approved seeds at tool launch. This is not a general network sandbox: arbitrary Nuclei templates, tool plugins/configuration and verification providers need independent egress review. External crawlers, virtual-host fuzzing and browser screenshots remain deliberately disabled pending suitable adapters. No new exploitation behavior is introduced by these safety changes.

Tool-specific limits and phase delays are not a shared/global traffic limiter. Phases 8–11 still have independent watchdogs and can overlap. A strict aggregate request budget remains unresolved; do not describe `-r` as providing one.

### dnsx compatibility contract

Compatibility targets are upstream dnsx v1.2.3 (manual `-wd`) and v1.3.0/v1.3.1 (automatic wildcard option), using default plain-text output. Runtime feature detection reads the complete successful help response before selecting a branch and requires recognizable list/output/silent flags. Failed or malformed help is an error. The offline fixtures cover these CLI shapes; real released binaries have not been executed by this change's tests. Older versions and modified output/configuration contracts are unsupported until independently verified. Wildcard counts are unavailable, and explicit host policies disable generated-name wildcard detection.

### Offline regression tests

Run from a full checkout (keep `lib/authorization.sh` alongside the script):

```bash
bash -n nullsec.sh
bash -n lib/authorization.sh
python3 -m unittest discover -s tests -v
```

The suite replaces all network/scanner executables with local stubs; it does not scan public targets. It covers scope, cloud parsing, resume fingerprints, authorization classes, launch boundaries, validation failures, stale feeds/JS, dnsx help branches, curl options and TruffleHog result labels. Python 3 and jq are required for these tests. An unprivileged reader tests permission denial when run as root with `runuser` available.
