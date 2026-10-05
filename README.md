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
- Exact provider/resource-approved cloud storage enumeration
- HTTP probing, technology detection, and status-code grouping
- Host-policy enforcement (the existing direct-IP virtual-host path is disabled)
- Port scanning and alternate web-service detection
- Live, in-scope URL corpus generation
- Parameter discovery and endpoint categorization
- Local asset scoring and target prioritization
- Nuclei vulnerability and exposure scanning
- JavaScript download, secret detection, and endpoint extraction
- SSRF, redirect, XSS, SQLi, LFI, IDOR, CORS, and host-header lead generation
- Optional Dalfox and SQLMap validation
- Gowitness screenshot capture
- ffuf directory, backup-file, and virtual-host fuzzing
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

NullSec requires an explicit host policy and separate action permissions. By default, only the exact `-d` host is approved for passive collection; target-facing enumeration, active validation, and secret verification are disabled. Exclusions override approvals. These controls authorize the inputs NullSec hands to tools; they do not sandbox requests generated inside an external tool. Operators must still check program permissions and tool behavior.

## Requirements

### Platform

NullSec is intended for Linux systems with Bash and GNU command-line utilities. Kali Linux or another Debian-based penetration-testing environment is recommended.

Output ownership requires `flock` (normally provided by Linux's `util-linux` package) and readable `/proc/self/fd` and `/proc/self/mountinfo`. If ownership or filesystem validation is unavailable or fails, NullSec refuses execution, including with `-s`.

Basic system dependencies include:

```bash
sudo apt update
sudo apt install -y bash curl jq git python3 python3-pip golang-go dnsutils seclists
```

Package availability and names may differ by distribution.

### Required tools

The script now performs **mode-aware** dependency checks. A tool is treated as fatal only when the selected scan mode and authorization policy enable a phase that needs it. Missing optional tools are reported clearly and the related check is skipped or reduced.

| Tool | Purpose | Required when |
|---|---|---|
| Amass v4 or Amass fallback | Subdomain and DNS relationship discovery | When target-facing enumeration is authorized |
| Subfinder | Passive subdomain enumeration | All modes |
| Assetfinder | Passive subdomain enumeration | All modes |
| dnsx | DNS validation and wildcard detection | When target-facing enumeration is authorized |
| httpx-toolkit | HTTP probing and metadata collection | When target-facing enumeration is authorized |
| Katana | Web crawling | When target-facing enumeration is authorized |
| Waybackurls | Historical URL collection | When target-facing enumeration is authorized |
| GAU | Historical and indexed URL collection | When target-facing enumeration is authorized |
| Unfurl | URL and parameter extraction | When target-facing enumeration is authorized |
| Nuclei | Template-based scanning and confirmation | When active validation is authorized |
| jq | JSON processing | All modes |
| curl | HTTP requests and connectivity checks | All modes |
| PureDNS | DNS brute force and permutation resolution | `normal` and `deep` with `-A` |
| Naabu | Port scanning | `normal` and `deep` with `-A` |
| ffuf | Content fuzzing | Authorized active validation in `deep`; direct-IP vhost discovery is disabled |
| Arjun | Active parameter discovery | `deep` with `-A -V` |

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
| TruffleHog | Secret verification requires `-K`; regex extraction remains local |

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

Missing templates produce a warning during discovery. Phase 2 skips unavailable takeover templates; the shared scan launcher refuses unavailable template paths with an error.
NullSec updates templates only with explicit `-u`, during an authorized Phase 7 run (`-A -V`) with live hosts. A missing or old update stamp never authorizes an update. Updates therefore occur after Phase 2 takeover checks. Without `-u`, every Nuclei scan disables automatic update checks and uses explicit installed template paths. Update failures remain visible in `phase7-vulns/template-update.log` and fail Phase 7. The update stamp is written only after a successful explicit update; stamp write failures also fail the phase.

Each target scan records a local template inventory beside its output as `*.templates.txt`, and the report includes current records. It records the template root, selected path, mode severity, and `CORPUS=nuclei-yaml-v1`: a deterministic SHA-256 digest of sorted relative paths and bytes of regular `.yaml`/`.yml` template descriptors. An optional, already installed Python 3/PyYAML parser validates a single YAML mapping with exactly one top-level `id` (a nonblank scalar string) and `info` (a nonempty mapping). It rejects duplicate keys in every mapping, aliases, merge keys, nonstring/complex mapping keys, and unsupported tags. Python uses isolated imports and disables bytecode writes; YAML is composed into nodes without constructing objects. No parser is installed or required for scanning: unavailable parsing, syntax errors, or inconclusive validation produce `CONTENT_SHA256=unknown`, with no grep fallback. Other file classes are excluded, including logs, generated identity records, lock files, and temporary/output files. Traversal prunes `.git`, `prior-runs`, `reports`, `.run-state`, `.phase-backups`, `logs`, `tmp`, `temp`, `cache`, `caches`, `.cache`, and `.tmp` directories, plus managed output trees identified by `.nullsec.lock` or `.scan-meta`. The entire owned NullSec output root is excluded when physically beneath the template root, even if it contains YAML files. Physical containment uses path boundaries and existing output ownership checks; directory symlinks are never followed.

The release version is honestly reported as `unknown`; this descriptor digest is a content identity, not a release version or a fingerprint of external payloads, helper scripts, or scanner configuration. An empty corpus, source symlinks, ambiguous YAML, source-read errors, or unvalidated output ownership produces an `unknown` digest. A template root inside managed output also produces `unknown`. Inspection is local and read-only and runs before each scan, so takeover records can differ from later records after explicit updates. Preserve the descriptors and any external dependencies for reproduction; the digest alone cannot restore them or capture concurrent edits. Identity records retain checked atomic persistence and current-generation report/history isolation.

## Installation

```bash
git clone <your-repository-url>
cd NullSec
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

Run passive collection with the default `normal` preset (the preset grants no permissions):

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

Select the lightweight preset (still passive-only without `-A`):

```bash
./nullsec.sh -d example.com -m fast
```

Select the deep preset with explicit action permissions and an externally prepared approved-host policy:

```bash
./nullsec.sh -d example.com -m deep -I /tmp/approved-hosts.txt -A -V -K -u -r
```

Write results to a specific new directory:

```bash
./nullsec.sh -d example.com -m normal -o ./results/example-normal
```

Resume an interrupted scan with the same policy files and action flags (this example assumes the default passive policy):

```bash
./nullsec.sh -d example.com -m normal -c ./recon-example.com-20260707-090000
```

## Command-Line Options

```text
Usage: ./nullsec.sh -d <target-domain> [options]

  -d <domain>   Target domain; required
  -o <dir>      New output directory
  -m <mode>     fast, normal, or deep; default: normal
  -I <file>     Approved hosts; replaces the default exact -d host
  -E <file>     Excluded hosts; exclusions override approvals
  -C <file>     Exact cloud approvals: s3:name, gcs:name, azure:name
  -A            Permit target-facing enumeration; disabled by default
  -V            Permit active validation; also requires -A
  -K            Permit secret verification; disabled by default
  -s            Skip the dependency check
  -u            Explicitly update templates in Phase 7 (requires -A -V)
  -r            Add polite delays between phases
  -c <dir>      Resume from an existing NullSec output directory
  --version     Show NullSec version and author
  -h            Show help
```

The target must be a plain DNS domain such as `example.com`. Do not pass a URL, path, wildcard, IP address, CIDR range, or labels with leading/trailing hyphens.

`-o` and `-c` cannot be used together. A new explicit `-o` directory must be empty. Resume verifies the stored target and authorization fingerprint before any network launch. Re-supply the policy options and permissions used for the original run.

## Authorization policy

Policy files must be prepared outside the repository. Host files contain one exact DNS hostname or `*.domain` rule per line. Empty lines and `#` comments are ignored; case, trailing dots, whitespace, line endings, ordering, and duplicate rules are normalized. Rules use dotted ASCII DNS names with an alphabetic-starting final label. URLs, ports, IP/CIDR ranges, userinfo, and wildcard forms other than `*.domain` are not policy rules.

Example approved-host file:

```text
example.com
*.example.com
```

`*.example.com` approves subdomains at any depth and does **not** approve the apex. Supply the apex separately when needed. `-I` replaces the default exact target approval; it does not silently add the target or all its subdomains.

Example exclusion file:

```text
excluded.example.com
*.restricted.example.com
```

Exact exclusions reject that exact host. Wildcard exclusions reject descendants, not their apex. Use both rules when excluding a host and its entire subtree. Exclusions always override matching approvals.

Permissions are independent of modes:

| Option | Permission |
|---|---|
| No action options | Passive Subfinder/Assetfinder/CT collection only; no target-facing activity |
| `-A` | Target-facing DNS/Amass enumeration, probing, crawling, port discovery, JS downloads, and screenshots |
| `-A -V` | Additionally permit Nuclei checks, Arjun, Dalfox, SQLMap, CORS/host-header checks, and content fuzzing when the preset enables them |
| `-K` | Permit TruffleHog secret verification; the normal pipeline also needs `-A` to download JS |
| `-C <file>` | Approve exact cloud identities; cloud probes additionally need `-A` and a cloud-enabled preset |

Approved hosts cover valid ports on those hosts. Final launch inputs preserve valid hostname ports and reject malformed/ambiguous authorities. IP seeds are not approved by hostname rules. Consequently the existing direct-IP vhost implementation is disabled; no IP authorization is inferred from DNS resolution.

Cloud approval files contain exact provider identities:

```text
s3:example-assets
gcs:example-assets
azure:exampleassets
```

Cloud references in DNS or web content are leads only. The current cloud phase probes the intersection of referenced resources and explicit exact approvals, then checks approval again in each worker/request. `s3:example-assets` grants nothing for GCS or Azure, and no naming similarity grants permission. Host exclusions also deny matching provider endpoint hosts, even when the resource is explicitly approved. Unapproved references never authorize provider requests. Cloud provider URLs are not exempted from the host policy in generic scan feeds.

Example operator-approved enumeration:

```bash
./nullsec.sh -d example.com -I /tmp/approved-hosts.txt -E /tmp/excluded-hosts.txt -A
```

Add `-V`, `-K`, or `-C` only when those actions/resources are expressly permitted. A mode may disable an action; it never authorizes one. `-s`, `-u`, cached results, and checkpoints do not override authorization.

Policy files are loaded as one snapshot per invocation; edits require a restart. The normalized host rules, exclusions, cloud approvals, action permissions, and target form a SHA-256 fingerprint stored in `.scan-meta`. Equivalent normalized policies have the same identity. Resume refuses changed rules/permissions and missing, duplicated, or malformed fingerprint state. Older output directories without that state cannot be resumed; choose a new output directory. A mode change may restart phases only after the current policy matches.

NullSec removes its explicit httpx redirect-following options and uses curl with configuration defaults disabled and no redirects for controlled requests. Every controlled list launch receives a fresh authorized snapshot; filtering errors stop the launch and empty authorized lists skip safely.

This is **seed authorization, not an external-tool sandbox**. Crawlers, scanners, browsers, resolvers, template updates, and secret verifiers can generate requests internally, including redirects, browser subresources, OAST traffic, or provider verification. NullSec does not promise to confine those internals. Decline the corresponding permission when the tool's behavior is incompatible with program scope, or apply independently verified network controls. SQLMap's existing target regex is not a guarantee that arbitrary exclusions constrain all internal requests.

Passive services remain external: certificate transparency, installed passive data providers, the fixed Cloudflare connectivity check, and Telegram when configured. Secret verification may contact services outside host scope only after `-K`; exact credential/provider authorization still requires operator review.

## Scan Modes

The table describes preset capabilities **after** the corresponding action permissions are supplied. Without `-A`, every mode is limited to passive collection. Vhost discovery remains disabled by the host-only policy.

| Mode | Intended use | Main behavior | Approximate runtime |
|---|---|---|---|
| `fast` | Frequent or scheduled checks | Passive discovery, live probing, URL collection, and critical-only Nuclei scanning; skips cloud enumeration, brute force, port scanning, JavaScript analysis, screenshots, pattern hunting, fuzzing, and active confirmation | 5–15 minutes |
| `normal` | Daily reconnaissance | Adds DNS brute force, cloud checks, port scanning, asset scoring, JavaScript analysis, pattern hunting, screenshots; skips permutations, Arjun, directory fuzzing, and Phase 12 confirmation | 30–60 minutes |
| `deep` | First-time onboarding or thorough periodic scans | Selects all otherwise supported phases subject to explicit permissions, increases selected limits, and includes permutations, Arjun, directory fuzzing, and active confirmation | 1–4+ hours |

Normal mode generates pattern candidates with `-A`; Dalfox and SQLMap can run only with separate explicit `-A -V` permission and installed tools. Normal mode skips Phase 12 confirmation, but that does not disable its permission-gated Phase 9 validators.

Every target-facing Nuclei scan, including takeover, exposure/configuration, and Phase 12 scans, uses the same severity policy: `critical` in fast, `critical,high,medium` in normal, and `critical,high,medium,low` in deep. Category tags remain separate filters and do not override severity. A preset never grants validation permission.

Runtime depends on the number of discovered assets, target responsiveness, network conditions, WAF behavior, tool versions, and configured limits.

## Workflow

### Phase 1 — Subdomain discovery

Collects and merges results from Subfinder, Amass, Assetfinder, crt.sh, Hakrawler, PureDNS, and optionally Gotator. Amass v4 is preferred for its live colored Open Asset Model relationship output.

Primary outputs:

```text
phase1-subdomains/all-subdomains.txt
phase1-subdomains/amass-clean.txt
phase1-subdomains/amass-detailed.txt
```

`amass-detailed.txt` is diagnostic graph output only. NullSec merges only `amass-clean.txt` into the final subdomain corpus.

### Phase 2 — Validation and resolution

Uses dnsx to resolve discovered names, records DNS responses, filters wildcard behavior, and runs Nuclei takeover templates.

Primary outputs:

```text
phase2-validation/valid-subdomains.txt
phase2-validation/resolved.txt
phase2-validation/wildcards.txt
phase2-validation/takeover-findings.txt
```

### Phase 2.5 — Cloud storage enumeration

Builds cloud leads from DNS/web references, but probes only exact provider resources also approved by `-C`, with target-facing enumeration authorized by `-A`. References do not establish ownership or permission.

Unapproved resources and global namespace guesses are **not probed**. Public-write detection is based on anonymous ACL, policy, or IAM inspection rather than uploading a test object.

Primary outputs:

```text
phase2.5-cloud/ownership-evidence.txt
phase2.5-cloud/exposed/unverified-candidates.txt
phase2.5-cloud/exposed/all-exposed-buckets.txt
phase2.5-cloud/exposed/critical-writable.txt
```

### Phase 3 — Live web probing

Uses httpx-toolkit to identify web services, collect titles and technologies, and group status codes. The previous direct-IP ffuf vhost launch is disabled by the current host policy.

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

Combines Katana, Hakrawler, Cariddi, Waybackurls, GAU, cloud URLs, and alternate-port services. The corpus is scope-filtered, deduplicated, parameter-collapsed, and checked for liveness.

NullSec keeps two important URL sets:

- `all-urls.txt`: refined, live, in-scope, parameter-collapsed endpoints
- `all-urls-injectable.txt`: full-value parameterized URLs used by injection-oriented phases

The phase also categorizes API endpoints, JavaScript files, sensitive paths, interesting files, and gf matches.

### Phase 6 — Parameter discovery

Extracts known parameter names with Unfurl and optionally runs Arjun against a limited number of status-200 hosts.

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

Runs a consolidated scan and a dedicated exposure or misconfiguration scan, both constrained by the mode severity policy and explicit `-A -V`. Exposure/config/misconfig tags remain intact. JSON exports are parsed into separate critical, high/medium, CVE, API, endpoint, JavaScript exposure, and general exposure files.

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

Downloads a bounded number of in-scope JavaScript responses with per-file and aggregate size limits. When TruffleHog is installed and `-K` is explicitly supplied, it runs in verified-only mode; targeted regex extraction still runs without TruffleHog. It also extracts possible in-scope API endpoints.

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

When `-A -V` is supplied and the tools are available, Dalfox and SQLMap receive deduplicated, capped, currently authorized injection points. CORS and host-header checks include failure-window logic that stops early when throttling or network instability is detected.

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

Uses Gowitness to capture visual evidence for live hosts, status-403 pages, admin-like paths, and sensitive endpoints.

Primary output:

```text
phase10-screenshots/
```

### Phase 11 — Directory and content fuzzing

Uses ffuf against a limited number of in-scope status-200 hosts. It performs recursive directory discovery and a separate pass for exposed backup or configuration files.

Primary outputs:

```text
phase11-fuzzing/dirs/all-found-paths.txt
phase11-fuzzing/dirs/all-found-backups.txt
phase11-fuzzing/dirs/*.json
```

### Phase 12 — Active confirmation

Deep mode uses Nuclei to attempt bounded confirmation of selected SSRF, redirect, LFI, 403-bypass, and GraphQL leads.

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
.run-state/
```

Round 3 metadata uses canonical `FORMAT=3` records and binds the target, scan mode, normalized authorization fingerprint, and a random 256-bit generation identity. `.run-state/progress` repeats the generation identity and checkpoint. Each phase record repeats its generation and phase identity, records its execution state, and stores a SHA-256 digest of active output filenames and contents when completion can be committed. Historical `prior-runs/` trees and legacy `.bak` files are excluded from these digests and current aggregation.

A new scan creates a new generation. `-c` continues an interrupted generation only after metadata, checkpoint, phase records, and the active evidence of committed phases all validate. A mode change or `-c` on a completed checkpoint `12` starts a new generation after the old generation validates; authorization must still match. There is no inference of completion from result files alone.

Checkpoints contain exactly one canonical value followed by one newline: `0`, `1`, `2`, `3`, `4`, `5`, `6`, `7`, `11`, or `12`. No whitespace, additional lines, decimals, or repaired text is accepted. The only advances are `0 → 1 → 2 → 3 → 4 → 5 → 6 → 7 → 11 → 12`. Phase 2.5 is proven by the Phase 3 commit; scoring is proven by the Phase 7 commit. Phases 8–11 have separate atomic records and commit checkpoint 11 only when every worker succeeds and all earlier prerequisites are proven. Phase 12 cannot commit without that group. Intentional policy/mode/tool skips are explicit states, not evidence of a tool having run.

A missing checkpoint is treated as `0` only when canonical generation metadata, all phase records, and generation progress explicitly prove checkpoint `0`. Empty or corrupt checkpoints are refused. A completion record ahead of its checkpoint is allowed only in the next legal commit window and is conservatively rerun; it never advances progress on its own. A mismatch between the two progress files, an incomplete generation transition, changed committed evidence, duplicate/malformed records, or impossible completion requires a new output directory. Validation and output preparation occur before connectivity checks or target-capable work.

**Legacy migration:** scan directories from earlier NullSec versions lack Round 3 generation integrity state and are refused, even if their authorization fingerprint or numeric checkpoint looks valid. Keep those directories for analyst reference and select a fresh output directory. NullSec does not upgrade legacy checkpoints by trusting old result files.

New scans atomically reserve a fresh output directory. An existing directory, including an empty one, is refused; choose a new child path or use `-c` for an existing scan. A default name collision fails safely. Absolute paths, relative paths, spaces, and symlinked ancestors outside the output tree are supported after resolving the physical parent. Output names containing newlines or carriage returns are refused.

The physical root must belong to the current user and have private permissions (normally `700`). Managed state rejects symlinks, hard-linked files, foreign-owned objects, special files, writable shared directories, and nested filesystem mounts. The root's device/inode identity and path boundaries are checked before managed operations. New state uses `umask 077`.

One process owns the output state through an exclusive nonblocking lock on `.nullsec.lock`, acquired before resume reads, snapshots, or state changes. The lock file remains in place after completion: do not delete or replace it. Ownership is released by closing the descriptor, including on handled termination. Children inherit the descriptor, so surviving children continue to prevent another run from taking ownership until they exit. There is no PID-based stale-lock takeover.

Checkpoints, metadata, and reports use private temporary files and checked renames. A failed checkpoint write leaves the previous checkpoint and in-memory resume position intact. Phase completion is persisted before progress advances. A generation-transition marker invalidates the old state before any mode-change reset; interruption during that transition fails closed. Failed persistence prevents final success announcements and produces a failing scan status.

When interrupted with `Ctrl+C`, NullSec attempts to:

- terminate registered scanner process trees;
- prevent orphaned background tools from continuing;
- retain evidence from unfinished state writes;
- preserve partial evidence;
- archive previous evidence without restoring it as current; and
- print a resume command.

Current outputs belong to one validated generation. Before rerunning an uncommitted phase, NullSec copies and verifies its active files, commits them under that phase's `prior-runs/`, then removes individually validated active files. It keeps directories and historical subtrees, does not clear upstream inputs, and stops on preservation/reset failure. All unproven downstream outputs and the old report are prepared before execution, so a skipped phase, absent prerequisite/tool/pattern, or successful zero-result rerun cannot inherit old findings. Existing histories remain accessible outside current counts.

Before recursive JavaScript verification, Phase 8 moves any `prior-runs/` subtree beneath `js-files/` into a unique `phase8-javascript/prior-runs/js-history.*` archive outside the verification corpus. Historical bytes remain preserved, but recursive verification receives only current JavaScript. A failed preparation or move refuses verification; zero-current-JavaScript runs never invoke verification on preserved history.

Phase records distinguish lifecycle states `pending` and `running` from execution outcomes `complete`, `zero-result`, `skipped`, `partial`, and `failed`. `complete` reports successful execution with current evidence; `zero-result` reports successful execution without selected evidence; `skipped` reports an intentional non-execution. `partial` means the caller explicitly reports useful current evidence with incomplete coverage, and `failed` reports failure. Partial and failed records always use `DIGEST=-` and never prove completion. Successful complete, zero-result, and intentional skipped outcomes carry an evidence digest; an unsuccessful prerequisite skip retains `DIGEST=-` and cannot authorize progress.

Phase functions may call `_set_phase_outcome complete|zero-result|skipped|partial|failed` with one canonical lowercase outcome. The runner returns nonzero for partial or failed coverage, and shell/persistence failures take precedence over an explicit success. Existing functions retain their return-code, skip-marker, and selected-evidence behavior unless they explicitly declare an outcome; this mechanism does not infer additional scanner failures.

Execution outcome and checkpoint eligibility are separate. An earlier incomplete phase freezes progress without relabeling later successful outcomes as partial. Successful records made behind that barrier retain their digest and append `BLOCKED_AT=<committed checkpoint>` to the existing four-line, generation-bound format. Resume validates that marker against the committed checkpoint, an earlier incomplete phase, and the recorded evidence; it cannot authorize a checkpoint. Ordinary four-line records retain the existing next-commit-window rules. Only phases protected by the committed checkpoint are retained as current completion: partial work and later uncommitted successes are archived under `prior-runs/` and rerun. Committed evidence, including scoring, remains unchanged. Phase 4's intentional addition of alternate-port hosts to Phase 3 is rebound before committing Phase 4; interruption before rebinding is conservatively refused.

Generic action records support `complete`, `zero-result`, `skipped`, `partial`, and `failed`, including existing generation-bound `.action-gf-*` records. Current records require canonical serialization, matching generation/phase/action identities, and a valid status; malformed or stale records are refused. Historical action records under `prior-runs/` are never current proof. Reports show the generation, checkpoint, each phase's state, and available GF action states. Counts use active files only. A report with a checkpoint below 12 or failed/partial/running work is incomplete; skipped work must not be interpreted as a successful scan with no vulnerabilities. History is never added to current totals.

Backups under `.phase-backups/` become active only after every copy succeeds and is compared with its source. Finalization checks archive copies before deleting the source backup; it never restores historical bytes into active paths. Failures retain the source and return an error; retrying completed finalization preserves archived evidence. Unfinished snapshots without `.active` are refused on retry and require manual review/recovery of the preserved files before their incomplete directory is removed. Failed temporary writes may also remain for inspection.

These checks protect cooperative NullSec runs and reject unsafe existing trees. Bash pathname checks and external tools' output paths cannot eliminate check-then-use races against a hostile process running as the same user, or privileged filesystem replacement. Keep the tree private, do not modify it during a scan, and treat scanner processes as trusted filesystem writers. Atomic renames provide process-level persistence; power-loss durability (`fsync`) is not guaranteed. Legacy `.bak` finalization prunes `prior-runs/` and archives active legacy backups under unique paths without overwriting earlier history; other legacy recovery semantics remain deferred. Digests establish consistency under exclusive cooperative ownership, not authenticity against a malicious process running as the same user. Output digests include the physical directory path, so moving or copying a scan to another path requires a fresh output directory. Atomic renames do not constitute a multi-file transaction: a crash between progress writes is conservatively refused, and a new output directory is required.

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

Resume with the same target and mode:

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
