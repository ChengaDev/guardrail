// grail — CVE-aware package manager wrapper.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ChengaDev/guardrail/internal/analyze"
	"github.com/ChengaDev/guardrail/internal/cache"
	"github.com/ChengaDev/guardrail/internal/config"
	"github.com/ChengaDev/guardrail/internal/osv"
	"github.com/ChengaDev/guardrail/internal/pm"
	"github.com/ChengaDev/guardrail/internal/purl"
	"github.com/ChengaDev/guardrail/internal/remediation"
	"github.com/ChengaDev/guardrail/internal/resolver"
	"github.com/ChengaDev/guardrail/internal/severity"
	"github.com/ChengaDev/guardrail/internal/ui"
)

// Build-time variables injected by GoReleaser via -ldflags "-X main.version=...".
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var (
	jsonOutput  bool
	strictFlag  bool
	analyzeFlag bool
)

func main() {
	root := buildRoot()
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func buildRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "grail",
		Short: "CVE-aware package manager wrapper",
		Long: `grail wraps common package managers and warns or blocks on CVEs before installation.

Examples:
  grail npm install express lodash
  grail pip install django
  grail cargo add serde
  grail sync
  grail check pkg:npm/lodash@4.17.21
  grail ignore CVE-2023-1234 --reason "not applicable" --expires 2025-12-31`,
	}

	root.PersistentFlags().BoolVar(&jsonOutput, "json", false, "output machine-readable JSON")
	root.PersistentFlags().BoolVar(&strictFlag, "strict", false, "block if OSV API is unreachable (overrides config)")

	// Package manager passthrough commands
	for _, name := range []string{"npm", "yarn", "pnpm"} {
		n := name // capture
		cmd := &cobra.Command{
			Use:                n,
			Short:              fmt.Sprintf("Run %s with CVE checking", n),
			DisableFlagParsing: true,
			RunE: func(cmd *cobra.Command, args []string) error {
				return runPMCommand(n, args)
			},
		}
		root.AddCommand(cmd)
	}
	for _, name := range []string{"pip", "pip3"} {
		n := name
		cmd := &cobra.Command{
			Use:                n,
			Short:              fmt.Sprintf("Run %s with CVE checking", n),
			DisableFlagParsing: true,
			RunE: func(cmd *cobra.Command, args []string) error {
				return runPMCommand(n, args)
			},
		}
		root.AddCommand(cmd)
	}
	{
		cmd := &cobra.Command{
			Use:                "cargo",
			Short:              "Run cargo with CVE checking",
			DisableFlagParsing: true,
			RunE: func(cmd *cobra.Command, args []string) error {
				return runPMCommand("cargo", args)
			},
		}
		root.AddCommand(cmd)
	}

	// install — alias for PM wrapper with explicit --analyze support
	installCmd := &cobra.Command{
		Use:   "install [--analyze] <pm> <pm-args...>",
		Short: "Wrap a package manager install with optional LLM impact analysis",
		Args:  cobra.MinimumNArgs(1),
	}
	installCmd.Flags().BoolVar(&analyzeFlag, "analyze", false, "force LLM impact analysis")
	installCmd.RunE = func(cmd *cobra.Command, args []string) error {
		return runPMCommandWithAnalyze(args[0], args[1:], analyzeFlag)
	}
	root.AddCommand(installCmd)

	// sync
	var ecosystems string
	syncCmd := &cobra.Command{
		Use:   "sync",
		Short: "Re-fetch CVE data for all cached packages",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSync(ecosystems)
		},
	}
	syncCmd.Flags().StringVar(&ecosystems, "ecosystem", "", "comma-separated ecosystems to sync (e.g. npm,pypi)")
	root.AddCommand(syncCmd)

	// check
	checkCmd := &cobra.Command{
		Use:   "check <purl>",
		Short: "Check a PURL directly without installing",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCheck(args[0])
		},
	}
	root.AddCommand(checkCmd)

	// version
	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("grail %s (%s, built %s)\n", version, commit, date)
		},
	})

	// ignore
	var ignoreReason string
	var ignoreExpires string
	ignoreCmd := &cobra.Command{
		Use:   "ignore <cve-id>",
		Short: "Add a CVE ignore rule to .guardrail.yaml",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runIgnore(args[0], ignoreReason, ignoreExpires)
		},
	}
	ignoreCmd.Flags().StringVar(&ignoreReason, "reason", "", "reason for ignoring this CVE")
	ignoreCmd.Flags().StringVar(&ignoreExpires, "expires", "", "expiry date (YYYY-MM-DD)")
	root.AddCommand(ignoreCmd)

	return root
}

// runPMCommand handles `grail npm install express lodash` etc.
func runPMCommand(pmName string, args []string) error {
	return runPMCommandWithAnalyze(pmName, args, false)
}

func runPMCommandWithAnalyze(pmName string, args []string, forceAnalyze bool) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	cfg.ExpandCachePath()
	if strictFlag {
		cfg.Strict = true
	}

	mgr, ok := pm.Lookup(pmName)
	if !ok {
		// Unknown PM — just pass through
		return pm.Exec(pmName, args)
	}

	pkgNames, isInstall := mgr.ParseInstall(args)
	if !isInstall || len(pkgNames) == 0 {
		// Not an install operation — delegate directly
		return pm.Exec(mgr.Binary(), args)
	}

	printer := ui.New(jsonOutput)

	// Resolve versions for packages that don't have one specified
	ctx := context.Background()
	type pkgInfo struct {
		name    string
		version string
		purlStr string
	}
	var packages []pkgInfo

	for _, name := range pkgNames {
		// Check if version is embedded (e.g. "express@4.18.2")
		version := ""
		parts := strings.SplitN(name, "@", 2)
		if len(parts) == 2 {
			name = parts[0]
			version = parts[1]
		}
		if version == "" {
			var resolveErr error
			version, resolveErr = resolver.Latest(ctx, mgr.Ecosystem(), name)
			if resolveErr != nil {
				printer.PrintWarning(fmt.Sprintf("could not resolve version for %s: %v", name, resolveErr))
				version = "unknown"
			}
		}
		packages = append(packages, pkgInfo{
			name:    name,
			version: version,
			purlStr: purl.Build(mgr.Ecosystem(), name, version),
		})
	}

	// Check cache + query OSV
	cacheStore, err := cache.New(cfg.Cache.Path, cfg.Cache.TTL)
	if err != nil {
		return err
	}

	osvClient := osv.NewClient()
	var cacheMissPURLs []string
	cachedVulns := make(map[string][]osv.Vuln)

	for _, pkg := range packages {
		entry, cErr := cacheStore.Get(pkg.purlStr)
		if cErr != nil || entry == nil {
			cacheMissPURLs = append(cacheMissPURLs, pkg.purlStr)
		} else {
			cachedVulns[pkg.purlStr] = entry.Vulns
		}
	}

	// Batch query for cache misses
	if len(cacheMissPURLs) > 0 {
		results, osvErr := osvClient.QueryBatch(ctx, cacheMissPURLs)
		if osvErr != nil {
			msg := fmt.Sprintf("OSV API unreachable: %v. CVE check skipped.", osvErr)
			printer.PrintWarning(msg)
			if cfg.Strict {
				return fmt.Errorf("strict mode: %s", msg)
			}
			return pm.Exec(mgr.Binary(), args)
		}
		for i, p := range cacheMissPURLs {
			cachedVulns[p] = results[i].Vulns
			_ = cacheStore.Set(p, results[i].Vulns)
		}
	}

	// Evaluate results against config
	now := time.Now()
	var reports []ui.PackageReport
	blocked := false

	for _, pkg := range packages {
		vulns := cachedVulns[pkg.purlStr]
		report := ui.PackageReport{
			PURL:          pkg.purlStr,
			ImpactResults: make(map[string]*analyze.Result),
		}

		for _, v := range vulns {
			lvl := v.Level()
			if !severity.MeetsThreshold(lvl, cfg.SeverityThreshold) {
				report.BelowThresholdCount++
				continue
			}
			if ignored, reason := cfg.IsIgnored(v.CVE(), now); ignored {
				report.IgnoredVulns = append(report.IgnoredVulns, ui.IgnoredVuln{
					Vuln:   v,
					Reason: reason,
				})
				continue
			}

			// LLM impact analysis
			if (cfg.ImpactAnalysis.Enabled || forceAnalyze) &&
				severity.MeetsThreshold(lvl, cfg.ImpactAnalysis.MinSeverity) {
				analyzer := analyze.New(cfg.ImpactAnalysis.AnthropicAPIKey)
				snippets, _ := analyze.FindImportingFiles(".", pkg.name, mgr.Ecosystem(), 10)
				result, aErr := analyzer.Analyze(ctx, v.CVE(), v.Details, pkg.name, snippets)
				if aErr == nil {
					report.ImpactResults[v.CVE()] = result
					if result.Verdict == analyze.VerdictLikelySafe {
						// Downgrade to ignored for output
						report.IgnoredVulns = append(report.IgnoredVulns, ui.IgnoredVuln{
							Vuln:   v,
							Reason: fmt.Sprintf("LLM analysis: LIKELY_SAFE — %s", result.Explanation),
						})
						continue
					}
				}
			}

			report.Vulns = append(report.Vulns, v)
			if cfg.Block {
				blocked = true
			}
		}
		if len(report.Vulns) > 0 {
			sug, _ := remediation.Suggest(ctx, report.Vulns, mgr.Ecosystem(), pkg.name, pkg.version)
			report.Remediation = sug
		}
		reports = append(reports, report)
	}

	printer.PrintReport(reports, cfg.SeverityThreshold)

	if blocked {
		printer.PrintBlockedMessage()
		os.Exit(1)
	}

	// All clear — run the real package manager
	return pm.Exec(mgr.Binary(), args)
}

func runSync(ecosystems string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	cfg.ExpandCachePath()

	printer := ui.New(jsonOutput)
	cacheStore, err := cache.New(cfg.Cache.Path, cfg.Cache.TTL)
	if err != nil {
		return err
	}

	entries, err := cacheStore.AllEntries()
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		printer.PrintInfo("Cache is empty — nothing to sync.")
		return nil
	}

	// Filter by ecosystem if requested
	var filter map[string]bool
	if ecosystems != "" {
		filter = make(map[string]bool)
		for _, e := range strings.Split(ecosystems, ",") {
			filter[strings.TrimSpace(strings.ToLower(e))] = true
		}
	}

	var purls []string
	for _, e := range entries {
		if filter != nil {
			eco, _, _, _ := purl.Parse(e.PURL)
			if !filter[strings.ToLower(eco)] {
				continue
			}
		}
		purls = append(purls, e.PURL)
	}

	printer.PrintInfo(fmt.Sprintf("Syncing %d cached packages...", len(purls)))

	ctx := context.Background()
	osvClient := osv.NewClient()

	const chunkSize = 1000
	for start := 0; start < len(purls); start += chunkSize {
		end := start + chunkSize
		if end > len(purls) {
			end = len(purls)
		}
		chunk := purls[start:end]
		results, osvErr := osvClient.QueryBatch(ctx, chunk)
		if osvErr != nil {
			return fmt.Errorf("OSV API error during sync: %w", osvErr)
		}
		for i, p := range chunk {
			if setErr := cacheStore.Set(p, results[i].Vulns); setErr != nil {
				printer.PrintWarning(fmt.Sprintf("failed to update cache for %s: %v", p, setErr))
			}
		}
	}

	printer.PrintInfo("Sync complete.")
	return nil
}

func runCheck(purlStr string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	cfg.ExpandCachePath()

	printer := ui.New(jsonOutput)
	ctx := context.Background()
	osvClient := osv.NewClient()
	cacheStore, err := cache.New(cfg.Cache.Path, cfg.Cache.TTL)
	if err != nil {
		return err
	}

	results, err := osvClient.QueryBatch(ctx, []string{purlStr})
	if err != nil {
		return fmt.Errorf("OSV query failed: %w", err)
	}
	_ = cacheStore.Set(purlStr, results[0].Vulns)

	now := time.Now()
	report := ui.PackageReport{
		PURL:          purlStr,
		ImpactResults: make(map[string]*analyze.Result),
	}
	for _, v := range results[0].Vulns {
		if ignored, reason := cfg.IsIgnored(v.CVE(), now); ignored {
			report.IgnoredVulns = append(report.IgnoredVulns, ui.IgnoredVuln{
				Vuln:   v,
				Reason: reason,
			})
			continue
		}
		if !severity.MeetsThreshold(v.Level(), cfg.SeverityThreshold) {
			report.BelowThresholdCount++
			continue
		}
		report.Vulns = append(report.Vulns, v)
	}

	if len(report.Vulns) > 0 {
		eco, pkgName, pkgVer, _ := purl.Parse(purlStr)
		sug, _ := remediation.Suggest(ctx, report.Vulns, eco, pkgName, pkgVer)
		report.Remediation = sug
	}

	printer.PrintReport([]ui.PackageReport{report}, cfg.SeverityThreshold)
	return nil
}

func runIgnore(cveID, reason, expires string) error {
	const configFile = ".guardrail.yaml"

	data, err := os.ReadFile(configFile)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	// Append a new ignore entry. We do a simple text append to avoid
	// overwriting existing hand-crafted YAML formatting.
	entry := fmt.Sprintf("\nignores:\n  - cve: %s\n    reason: %q\n", cveID, reason)
	if expires != "" {
		entry += fmt.Sprintf("    expires: %s\n", expires)
	}

	f, err := os.OpenFile(configFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	// If file already has content, ensure we don't duplicate the ignores key
	if len(data) > 0 && strings.Contains(string(data), "ignores:") {
		entry = fmt.Sprintf("\n  - cve: %s\n    reason: %q\n", cveID, reason)
		if expires != "" {
			entry += fmt.Sprintf("    expires: %s\n", expires)
		}
	}

	_, err = f.WriteString(entry)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "Added ignore rule for %s to %s\n", cveID, configFile)
	return nil
}
