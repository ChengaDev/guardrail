# Guardrail

[![CI](https://github.com/ChengaDev/guardrail/actions/workflows/ci.yml/badge.svg)](https://github.com/ChengaDev/guardrail/actions/workflows/ci.yml)
[![Release](https://github.com/ChengaDev/guardrail/actions/workflows/release.yml/badge.svg)](https://github.com/ChengaDev/guardrail/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Shift-left security for your package manager.**

Guardrail wraps your package manager and checks every package you install against the [OSV](https://osv.dev) vulnerability database — before it touches your lockfile, before code review, before CI. When it finds a problem, it tells you exactly what to install instead.

```
$ grail npm install express

🔴 CRITICAL  CVE-2024-1234   pkg:npm/express@4.17.0
             Prototype pollution via crafted request header
             https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz
             ✦ Patch: upgrade to 4.18.2

❌ Installation blocked. Fix CVEs or add ignore rules to .guirdrail.yaml
```

One line tells you what's wrong and what version fixes it. No tab-switching, no searching NVD, no guessing.

Most security tools catch vulnerabilities after the fact — in CI, in code review, or worse, in production. Guardrail shifts that check as far left as it goes: the moment you type `install`.

---

## Install

**macOS (Homebrew)**
```sh
brew install chengazit/tap/grail
```

**Linux / macOS (binary)**
```sh
curl -sSL https://github.com/chengazit/guardrail/releases/latest/download/grail_$(uname -s)_$(uname -m).tar.gz | tar -xz
sudo mv grail /usr/local/bin/
```

**Windows**
Download the `.zip` from the [latest release](https://github.com/chengazit/guardrail/releases/latest), extract, and add to your `PATH`.

**Go**
```sh
go install github.com/chengazit/guardrail/cmd/grail@latest
```

---

## Quick start

Prefix any install command with `grail`:

```sh
grail npm install express lodash
grail pip install django
grail cargo add serde tokio
```

Guardrail resolves versions, checks OSV, and either blocks the install or passes through to the real package manager — with no change to your existing workflow.

Check a specific package without installing:
```sh
grail check pkg:npm/lodash@4.17.20
```

---

## How it works

1. Parse package names from your install command
2. Resolve any missing versions from the package registry
3. Check the [OSV batch API](https://osv.dev) for CVEs (results cached locally for 24h)
4. If a CVE meets your severity threshold: print a report and exit — the install never runs
5. Otherwise: hand off to the real package manager unchanged

No agent, no account, no API key required.

---

## Remediation suggestions

Guardrail doesn't just tell you what's broken — it tells you what to install instead.

**When a patched version exists**, Guardrail recommends the minimum version that fixes all reported CVEs:

```
🔴 CRITICAL  CVE-2021-44228   pkg:npm/log4js@1.0.0
             Remote code execution via JNDI lookup
             https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz
             ✦ Patch: upgrade to 2.0.0
```

**When no patch exists**, Guardrail finds the newest published version that predates the vulnerability introduction — so you can at least pin to something safe while waiting for a fix:

```
🔴 HIGH      CVE-2024-9999    pkg:npm/newlib@3.1.0
             Arbitrary file read via path traversal
             https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc
             ↩ No patch: last safe version is 2.9.4
```

In `--json` mode, remediation is included in the output for CI scripting:

```json
{
  "purl": "pkg:npm/log4js@1.0.0",
  "vulns": [...],
  "remediation": { "version": "2.0.0", "kind": "patch" }
}
```

---

## Integrating into your workflow

The goal is to make Guardrail invisible — so you never have to remember to use it.

### Shell alias (personal setup)

Add to your `~/.zshrc` or `~/.bashrc`:

```bash
alias npm="grail npm"
alias pip="grail pip"
alias cargo="grail cargo"
```

Reload your shell (`source ~/.zshrc`) and you're done. Every `npm install` is now protected.

If you want a graceful fallback for machines where Guardrail isn't installed:

```bash
npm()   { command -v grail &>/dev/null && grail npm   "$@" || command npm   "$@"; }
pip()   { command -v grail &>/dev/null && grail pip   "$@" || command pip   "$@"; }
cargo() { command -v grail &>/dev/null && grail cargo "$@" || command cargo "$@"; }
```

### direnv (project-level, team-wide)

[direnv](https://direnv.net) activates a local environment whenever you `cd` into a project directory. Check these two files into your repo and every team member with direnv installed gets the protection automatically.

```bash
# .envrc
PATH_add .grail/bin
```

```bash
# .grail/bin/npm  (make executable: chmod +x .grail/bin/npm)
#!/bin/sh
exec grail npm "$@"
```

Create equivalents for `pip` and `cargo` as needed. The wrappers only apply inside the project directory — nothing is changed globally.

### Makefile

If your project uses `make` for dev tasks:

```makefile
.PHONY: install
install:
	grail npm install $(pkg)

# usage: make install pkg=express
```

---

## Configuration

Guardrail merges two config files — project-level wins over global:

| File | Scope |
|------|-------|
| `~/.guirdrail/config.yaml` | Global (your machine) |
| `.guirdrail.yaml` | Project (check into repo) |

**Full reference:**

```yaml
# Minimum severity to act on: NONE | LOW | MEDIUM | HIGH | CRITICAL
severity_threshold: HIGH

# true = block the install, false = warn and continue
block: true

# Block if OSV is unreachable (default: fail-open)
strict: false

cache:
  path: ~/.guirdrail/cache   # can be a shared NFS path for team cache
  ttl: 24h

# LLM analysis: checks whether your code actually calls the vulnerable function
impact_analysis:
  enabled: false
  anthropic_api_key: ""      # or set ANTHROPIC_API_KEY env var
  min_severity: HIGH

# CVE ignore rules
ignores:
  - cve: CVE-2023-1234
    reason: "Not exploitable — we don't use the affected endpoint"
    expires: 2025-12-31
```

**Environment overrides:**

| Variable | Overrides |
|----------|-----------|
| `GRAIL_SEVERITY` | `severity_threshold` |
| `GRAIL_BLOCK` | `block` |
| `GRAIL_STRICT` | `strict` |
| `GRAIL_CACHE_PATH` | `cache.path` |
| `ANTHROPIC_API_KEY` | `impact_analysis.anthropic_api_key` |

---

## Ignoring a CVE

After reviewing a CVE and deciding it doesn't apply:

```sh
grail ignore CVE-2023-1234 --reason "not exploitable in our setup" --expires 2025-12-31
```

This appends an ignore rule to `.guirdrail.yaml`. Rules with an `expires` date are automatically re-enabled after that date.

---

## LLM impact analysis

Guardrail can use Claude to check whether your code actually calls the vulnerable functionality before deciding to block:

```sh
grail install --analyze npm install express
```

Or enable it permanently in config (`impact_analysis.enabled: true`). Guardrail scans files that import the flagged package, sends only the relevant snippets to the Claude API, and returns one of:

- `EXPLOITABLE` — your code calls the vulnerable function
- `LIKELY_SAFE` — the vulnerable code path isn't reachable from your usage
- `UNCERTAIN` — couldn't determine with confidence

`LIKELY_SAFE` verdicts are treated as ignored for that run.

---

## Keeping the cache fresh (team setup)

The local cache grows organically as your team installs packages. Run `grail sync` on a schedule to refresh CVE data for everything already cached:

```sh
grail sync                        # refresh all cached packages
grail sync --ecosystem npm,pypi   # specific ecosystems only
```

Example CI cronjob (GitHub Actions):

```yaml
on:
  schedule:
    - cron: "0 8 * * *"

jobs:
  sync:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.guirdrail/cache
          key: grail-cache-${{ runner.os }}
      - run: grail sync
```

This keeps your team's cache up to date overnight so installs during the day get instant results from cache rather than hitting OSV on every install.

---

## grail vs. lock file scanners

| | Guardrail | Grype / `npm audit` |
|---|---|---|
| **When it runs** | As you add a package | After the fact (lockfile / CI) |
| **What it checks** | The package you're about to install | Everything already in your dependencies |
| **Blocks install** | Yes | No |
| **Catches new packages** | Yes | Only after commit |

They're complementary. Guardrail keeps new vulnerable packages out; lock file scanners audit what's already there. For full coverage, use both.

---

## Supported package managers

| Manager | Command | Ecosystem |
|---------|---------|-----------|
| npm | `grail npm install` | npm |
| yarn | `grail yarn add` | npm |
| pnpm | `grail pnpm add` | npm |
| pip | `grail pip install` | PyPI |
| cargo | `grail cargo add` | crates.io |

---

## License

MIT — see [LICENSE](LICENSE).
