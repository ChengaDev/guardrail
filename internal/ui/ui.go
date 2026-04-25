// Package ui handles all terminal output for guirdrail.
// Use --json flag to switch to machine-readable output.
package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/chengazit/guardrail/internal/analyze"
	"github.com/chengazit/guardrail/internal/osv"
	"github.com/chengazit/guardrail/internal/remediation"
	"github.com/chengazit/guardrail/internal/severity"
)

// ANSI colour codes.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorGreen  = "\033[32m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
)

// PackageReport holds all findings for one package PURL.
type PackageReport struct {
	PURL                string
	Vulns               []osv.Vuln
	IgnoredVulns        []IgnoredVuln
	BelowThresholdCount int
	// ImpactResults maps CVE ID → LLM impact analysis result.
	ImpactResults map[string]*analyze.Result
	// Remediation is an optional safe-version suggestion when Vulns is non-empty.
	Remediation *remediation.Suggestion
}

// IgnoredVuln pairs a vuln with the reason it was suppressed.
type IgnoredVuln struct {
	Vuln    osv.Vuln
	Reason  string
	Expires time.Time
}

// Printer writes human-readable or JSON output to the configured writer.
type Printer struct {
	out      io.Writer
	jsonMode bool
}

// New creates a Printer. Set jsonMode=true for CI/machine output.
func New(jsonMode bool) *Printer {
	return &Printer{out: os.Stdout, jsonMode: jsonMode}
}

// PrintReport writes the full CVE report for a list of packages.
func (p *Printer) PrintReport(reports []PackageReport, threshold severity.Level) {
	if p.jsonMode {
		p.printJSON(reports)
		return
	}
	for _, r := range reports {
		p.printPackage(r, threshold)
	}
}

func (p *Printer) printPackage(r PackageReport, threshold severity.Level) {
	if len(r.Vulns) == 0 && len(r.IgnoredVulns) == 0 {
		note := "  (no CVEs found)"
		if r.BelowThresholdCount > 0 {
			note = fmt.Sprintf("  (%d CVE(s) below %s threshold)", r.BelowThresholdCount, threshold)
		}
		fmt.Fprintf(p.out, "%s✅ SAFE%s      %s%s\n", colorGreen, colorReset, r.PURL, note)
		return
	}

	printed := 0
	for _, v := range r.Vulns {
		lvl := v.Level()
		if !severity.MeetsThreshold(lvl, threshold) {
			continue
		}
		printed++
		impact := ""
		if ir, ok := r.ImpactResults[v.CVE()]; ok {
			impact = fmt.Sprintf(" [%s%s%s: %s]",
				impactColor(ir.Verdict), ir.Verdict, colorReset, ir.Explanation)
		}
		fmt.Fprintf(p.out, "%s%s%s  %s  %s\n             %s\n             %s%s\n",
			levelColor(lvl), lvl.Emoji(), colorReset,
			v.CVE(),
			r.PURL,
			v.Summary,
			v.OSVLink(),
			impact,
		)
	}

	if printed == 0 && len(r.IgnoredVulns) == 0 {
		note := ""
		if r.BelowThresholdCount > 0 {
			note = fmt.Sprintf("  (%d CVE(s) below %s threshold)", r.BelowThresholdCount, threshold)
		}
		fmt.Fprintf(p.out, "%s✅ SAFE%s      %s%s\n", colorGreen, colorReset, r.PURL, note)
		return
	}

	if printed > 0 && r.Remediation != nil {
		switch r.Remediation.Kind {
		case remediation.KindPatch:
			fmt.Fprintf(p.out, "             %s✦ Patch: upgrade to %s%s\n",
				colorGreen, r.Remediation.Version, colorReset)
		case remediation.KindLastSafe:
			fmt.Fprintf(p.out, "             %s↩ No patch: last safe version is %s%s\n",
				colorYellow, r.Remediation.Version, colorReset)
		}
	}

	for _, iv := range r.IgnoredVulns {
		lvl := iv.Vuln.Level()
		expires := ""
		if !iv.Expires.IsZero() {
			expires = fmt.Sprintf(" (expires %s)", iv.Expires.Format("2006-01-02"))
		}
		fmt.Fprintf(p.out, "%s%s%s  %s  %s\n             %sIgnored: %q%s%s\n",
			colorGray, lvl.Emoji(), colorReset,
			iv.Vuln.CVE(),
			r.PURL,
			colorGray, iv.Reason, expires, colorReset,
		)
	}
}

// PrintBlockedMessage prints the final "installation blocked" line.
func (p *Printer) PrintBlockedMessage() {
	if p.jsonMode {
		return
	}
	fmt.Fprintf(p.out, "\n%s%s❌ Installation blocked.%s Fix CVEs or add ignore rules to .guirdrail.yaml\n",
		colorBold, colorRed, colorReset)
}

// PrintWarning prints a non-fatal warning line.
func (p *Printer) PrintWarning(msg string) {
	if p.jsonMode {
		return
	}
	fmt.Fprintf(p.out, "%s⚠  %s%s\n", colorYellow, msg, colorReset)
}

// PrintInfo prints an informational line.
func (p *Printer) PrintInfo(msg string) {
	if p.jsonMode {
		return
	}
	fmt.Fprintf(p.out, "%s%s%s\n", colorCyan, msg, colorReset)
}

// jsonReport is the machine-readable form of the full report.
type jsonReport struct {
	Blocked  bool          `json:"blocked"`
	Packages []jsonPackage `json:"packages"`
}

type jsonPackage struct {
	PURL        string            `json:"purl"`
	Vulns       []jsonVuln        `json:"vulns"`
	Remediation *jsonRemediation  `json:"remediation,omitempty"`
}

type jsonRemediation struct {
	Version string `json:"version"`
	Kind    string `json:"kind"` // "patch" or "last_safe"
}

type jsonVuln struct {
	ID       string `json:"id"`
	CVE      string `json:"cve"`
	Severity string `json:"severity"`
	Summary  string `json:"summary"`
	Link     string `json:"link"`
	Ignored  bool   `json:"ignored"`
	Reason   string `json:"reason,omitempty"`
}

func (p *Printer) printJSON(reports []PackageReport) {
	out := jsonReport{}
	for _, r := range reports {
		jp := jsonPackage{PURL: r.PURL}
		for _, v := range r.Vulns {
			jp.Vulns = append(jp.Vulns, jsonVuln{
				ID:       v.ID,
				CVE:      v.CVE(),
				Severity: v.Level().String(),
				Summary:  v.Summary,
				Link:     v.OSVLink(),
			})
		}
		for _, iv := range r.IgnoredVulns {
			jp.Vulns = append(jp.Vulns, jsonVuln{
				ID:       iv.Vuln.ID,
				CVE:      iv.Vuln.CVE(),
				Severity: iv.Vuln.Level().String(),
				Summary:  iv.Vuln.Summary,
				Link:     iv.Vuln.OSVLink(),
				Ignored:  true,
				Reason:   iv.Reason,
			})
		}
		if r.Remediation != nil {
			jp.Remediation = &jsonRemediation{
				Version: r.Remediation.Version,
				Kind:    string(r.Remediation.Kind),
			}
		}
		out.Packages = append(out.Packages, jp)
	}
	_ = json.NewEncoder(p.out).Encode(out)
}

func levelColor(l severity.Level) string {
	switch l {
	case severity.LevelCritical:
		return colorRed
	case severity.LevelHigh:
		return "\033[38;5;208m" // orange
	case severity.LevelMedium:
		return colorYellow
	default:
		return colorCyan
	}
}

func impactColor(v analyze.Verdict) string {
	switch v {
	case analyze.VerdictExploitable:
		return colorRed
	case analyze.VerdictLikelySafe:
		return colorGreen
	default:
		return colorYellow
	}
}
