# Guirdrail — CVE-aware package manager wrapper

## Vision
A CLI tool that wraps common package managers and warns or blocks on CVEs before installation.
Single Go binary, no runtime dependencies required on the user's machine.

---

## Commands

```
grail npm install <packages...>         # wrap install with CVE check
grail pip install <packages...>
grail cargo add <packages...>

grail sync                              # re-fetch CVE data for all cached packages
grail sync --ecosystem npm,pypi         # sync only specific ecosystems

grail check pkg:npm/lodash@4.17.21      # check a PURL directly, no install
grail ignore CVE-2023-1234 \
  --reason "not applicable" \
  --expires 2025-12-31                    # add an ignore rule

grail install --analyze npm install express  # force LLM impact analysis
```

---

## Core Install Flow

1. User runs: `grail npm install express lodash`
2. Tool parses package names and versions from the arguments
3. If no version specified, resolve latest from the package registry
4. Build PURLs: `pkg:npm/express@4.18.2`, `pkg:npm/lodash@4.17.21`
5. Check local cache for each PURL — if found and TTL is still valid, use cached result
6. For any cache misses, send a single `querybatch` request to OSV API
7. Save API results to local cache
8. Evaluate all results against config (severity threshold, ignores list)
9. If any package is blocked: print report and exit without installing
10. If warn-only or all clear: delegate to the real package manager and run the original command
11. Optional: run LLM impact analysis before the block/warn decision

---

## CVE Data Source

**Primary: OSV.dev API** (`https://api.osv.dev/v1`)
- No authentication required
- Batch endpoint: `POST /v1/querybatch`
- Hard limit: 1,000 queries per batch request (more than enough for any real use case)
- No rate limits currently enforced by OSV
- Supports PURL natively

**Pagination:** OSV paginates when a single query returns >1,000 vulnerabilities or the
entire batch returns >3,000 total. Handle `next_page_token` in responses. In practice
this will almost never trigger for normal packages.

**Use HTTP/2** for large responses — OSV recommends it and Go supports it out of the box
via `golang.org/x/net/http2`.

---

## Caching Strategy

### Design
- Cache is stored locally at `~/.guirdrail/cache/`
- Key: SHA256 of the PURL (e.g. `sha256("pkg:npm/express@4.18.2")`)
- Value: JSON result from OSV + timestamp
- Default TTL: 24 hours
- Cache is per-user by default, but `cache_path` in config can point to a shared NFS/network path for team sharing

### Cache is built by accumulation
There is no initial bulk download. The cache grows organically as packages are installed.
After a few days of normal use it naturally reflects the team's actual dependency footprint.

### sync command
`grail sync` refreshes CVE data for everything already in the cache:
1. Read all entries from `~/.guirdrail/cache/` → collect their PURLs
2. Chunk into batches of 1,000 (OSV batch limit)
3. Send batch request(s) to OSV API
4. Overwrite cache entries with fresh results + reset TTL

This means `sync` is efficient — it only re-fetches packages your team actually uses,
not the entire OSV database. Running it daily in CI keeps the shared cache fresh for everyone.

```
# example CI cronjob
0 8 * * * grail sync
```

### Fail-open behavior
If the OSV API is unreachable and cache is expired:
- Print a warning: `⚠ OSV API unreachable, CVE check skipped`
- Continue with the installation
- Use `--strict` flag to override this and block instead

---

## Configuration

### Config file locations (merged, project-level wins over global)
1. `~/.guirdrail/config.yaml` — global user config
2. `.guirdrail.yaml` — project-level config (checked into repo)

### Full config reference

```yaml
# Minimum severity level to act on.
# Options: NONE | LOW | MEDIUM | HIGH | CRITICAL
# Default: HIGH
severity_threshold: HIGH

# What to do when a CVE meets or exceeds the threshold.
# true  = block the installation entirely
# false = print a warning but continue
# Default: true
block: true

# If OSV API is unreachable and cache is expired, block the install.
# Default: false (fail-open)
strict: false

# Cache configuration
cache:
  # Path to local cache directory.
  # Can be a shared NFS path for team-wide cache sharing.
  # Default: ~/.guirdrail/cache
  path: ~/.guirdrail/cache

  # How long to trust a cached result before re-fetching.
  # Default: 24h
  ttl: 24h

# LLM impact analysis via Claude API.
# When enabled, guirdrail will check whether your code actually calls
# the vulnerable functionality before blocking/warning.
impact_analysis:
  enabled: false

  # API key for Anthropic. Can also be set via ANTHROPIC_API_KEY env var.
  anthropic_api_key: ""

  # Only run impact analysis for this severity and above.
  # Avoids spending tokens on LOW severity CVEs.
  # Default: HIGH
  min_severity: HIGH

# CVE ignore rules.
# Useful for CVEs your team has reviewed and accepted.
ignores:
  - cve: CVE-2023-1234
    reason: "Not exploitable — we don't use the affected endpoint"
    expires: 2025-12-31   # optional, ignore rule auto-expires on this date

  - cve: GHSA-xxxx-yyyy-zzzz
    reason: "Vendor confirmed not applicable to our platform"
    # no expiry = ignore forever (not recommended)

# Package manager configuration.
# guirdrail auto-detects which PM to use from the command.
# Override binary paths here if needed (e.g. custom installs, nvm, pyenv).
package_managers:
  npm:
    enabled: true
    binary: npm
  yarn:
    enabled: true
    binary: yarn
  pnpm:
    enabled: true
    binary: pnpm
  pip:
    enabled: true
    binary: pip
  poetry:
    enabled: true
    binary: poetry
  uv:
    enabled: true
    binary: uv
  cargo:
    enabled: true
    binary: cargo
  go:
    enabled: true
    binary: go
```

### Environment variable overrides
| Variable | Overrides |
|----------|-----------|
| `ANTHROPIC_API_KEY` | `impact_analysis.anthropic_api_key` |
| `GRAIL_SEVERITY` | `severity_threshold` |
| `GRAIL_BLOCK` | `block` |
| `GRAIL_STRICT` | `strict` |
| `GRAIL_CACHE_PATH` | `cache.path` |
| `GRAIL_CONFIG` | path to config file |

---

## PURL Format by Ecosystem

| Package Manager | PURL format |
|-----------------|-------------|
| npm | `pkg:npm/<name>@<version>` (scoped: `pkg:npm/%40scope%2Fname@version`) |
| yarn / pnpm | same as npm |
| pip | `pkg:pypi/<name>@<version>` (normalize: underscores→dashes, lowercase) |
| poetry / uv | same as pip |
| cargo | `pkg:cargo/<name>@<version>` |
| go modules | `pkg:golang/<module>@<version>` |
| maven | `pkg:maven/<group>/<artifact>@<version>` |

---

## Version Resolution

If the user does not specify a version (e.g. `npm install express` with no `@version`),
guirdrail must resolve the latest version before building the PURL.

| Ecosystem | Resolution endpoint |
|-----------|---------------------|
| npm | `https://registry.npmjs.org/<name>/latest` |
| PyPI | `https://pypi.org/pypi/<name>/json` |
| crates.io | `https://crates.io/api/v1/crates/<name>` |
| Go | `https://proxy.golang.org/<module>/@latest` |

---

## Severity Levels

OSV records may include CVSS scores or severity strings. Normalize everything to:

| Level | CVSS range |
|-------|------------|
| CRITICAL | 9.0 – 10.0 |
| HIGH | 7.0 – 8.9 |
| MEDIUM | 4.0 – 6.9 |
| LOW | 0.1 – 3.9 |

If severity is unknown or missing: treat as MEDIUM (conservative default).

---

## LLM Impact Analysis

Triggered when `impact_analysis.enabled: true` in config, or via `--analyze` flag.

### Flow
1. Identify all files in the project that import the flagged package
   - JS/TS: grep for `require('pkg')` or `import ... from 'pkg'`
   - Python: grep for `import pkg` or `from pkg import`
   - Rust: grep for `use pkg::` in `Cargo.toml` dependents
2. For each CVE, extract the affected function/component from the OSV description
3. Send to Claude API (`claude-sonnet-4-20250514`):
   - System prompt: "You are a security analyst. Determine if the following code actually calls the vulnerable functionality described in this CVE."
   - Include: CVE ID, CVE description, affected functions, relevant code snippets only (not entire files)
4. Return one of: `EXPLOITABLE` | `LIKELY_SAFE` | `UNCERTAIN` with a short explanation

### Cost control
- Only send files that import the package, not the entire codebase
- Only run analysis for CVEs at or above `impact_analysis.min_severity`
- Skip analysis if no importing files are found (treat as LIKELY_SAFE)

---

## Output Format

Always use colored terminal output. Machine-readable JSON output available via `--json` flag.

```
🔴 CRITICAL  CVE-2021-44228  pkg:npm/log4js@1.0.0
             Remote code execution via JNDI lookup
             https://osv.dev/vulnerability/GHSA-xxxx

🟠 HIGH      CVE-2023-1234   pkg:npm/express@4.17.0
             Ignored: "Not exploitable in our setup" (expires 2025-12-31)

✅ SAFE      pkg:npm/lodash@4.17.21  (no CVEs found)

❌ Installation blocked. Fix CVEs or add ignore rules to .guirdrail.yaml
```

---

## Project Structure

```
guirdrail/
├── cmd/
│   └── guirdrail/
│       └── main.go
├── internal/
│   ├── config/          # config loading, merging, validation
│   ├── osv/             # OSV API client, batch queries, pagination
│   ├── cache/           # local cache read/write, TTL, sync logic
│   ├── purl/            # PURL building per ecosystem
│   ├── resolver/        # version resolution per registry
│   ├── pm/              # package manager adapters
│   │   ├── npm.go
│   │   ├── pip.go
│   │   ├── cargo.go
│   │   ├── go.go
│   │   └── registry.go  # auto-detect PM from command
│   ├── severity/        # severity parsing and comparison
│   ├── analyze/         # LLM impact analysis via Claude API
│   └── ui/              # terminal output, colors, JSON mode
├── .guirdrail.yaml        # example project config
├── CLAUDE.md
└── README.md
```

---

## Key Design Decisions

- Config merges global + project level; project-level wins on conflict
- Unknown severity → treat as MEDIUM (fail safe)
- OSV API unreachable → warn and proceed, unless `--strict` flag is set
- Cache miss on a package that was never seen → always hits API, saves result
- `sync` only refreshes packages already in cache — never downloads everything
- Ignore rules with `expires` date are silently dropped after expiry (treated as active CVE again)
- `--json` flag outputs machine-readable JSON for CI integration

---

## Supported Package Managers (Phase 1: npm, pip, cargo)

Phase 1 focuses on these three ecosystems. Others (yarn, pnpm, poetry, uv, go) follow
the same pattern and can be added incrementally.

---

## Testing Strategy

- Unit tests for: PURL builders, severity parsing, config loading/merging, cache TTL logic
- Integration tests against real OSV API using known-vulnerable packages:
  - `pkg:npm/lodash@4.17.20` (prototype pollution CVEs)
  - `pkg:pypi/django@2.0.0` (multiple known CVEs)
  - `pkg:cargo/regex@0.1.0` (known CVEs)
- Mock OSV client for unit tests (interface-based, easy to swap)
- Test ignore rules: expired ignores should not suppress CVEs

---

## Out of Scope (v1)

- `uninstall` command
- Lock file scanning (use Grype or Trivy for that)
- Private registry authentication
- CI/CD `scan` command (future: `guirdrail scan` to audit existing lock file)
- Full offline mode via GCS dump download
