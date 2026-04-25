// Package analyze performs LLM-based impact analysis to determine whether
// the project's code actually invokes the vulnerable functionality in a CVE.
package analyze

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// Verdict is the outcome of an impact analysis.
type Verdict string

const (
	VerdictExploitable Verdict = "EXPLOITABLE"
	VerdictLikelySafe  Verdict = "LIKELY_SAFE"
	VerdictUncertain   Verdict = "UNCERTAIN"
)

// Result holds the analysis output for a single CVE.
type Result struct {
	Verdict     Verdict
	Explanation string
}

// system prompt is stable across all calls → ideal for prompt caching.
const systemPromptText = `You are a security analyst. Determine if the following code actually calls the vulnerable functionality described in a CVE.

Analyze the provided code snippets and CVE information, then return exactly one of these verdicts on the FIRST line of your response (the single word only, no punctuation):
EXPLOITABLE - the code directly invokes the vulnerable functionality
LIKELY_SAFE  - the code imports the package but does not appear to call the vulnerable function/path
UNCERTAIN    - insufficient information to determine exploitability

After the verdict line, provide a brief explanation in 2-3 sentences.`

// Analyzer calls the Anthropic API to assess CVE exploitability.
type Analyzer struct {
	client anthropic.Client
}

// New creates an Analyzer using the given API key.
// If apiKey is empty, NewClient falls back to the ANTHROPIC_API_KEY env var.
func New(apiKey string) *Analyzer {
	opts := []option.RequestOption{}
	if apiKey != "" {
		opts = append(opts, option.WithAPIKey(apiKey))
	}
	return &Analyzer{client: anthropic.NewClient(opts...)}
}

// Analyze assesses whether the codeSnippets call the functionality described
// by the CVE. Returns LIKELY_SAFE immediately if no snippets are provided.
func (a *Analyzer) Analyze(
	ctx context.Context,
	cveID, cveDescription, packageName string,
	codeSnippets []string,
) (*Result, error) {
	if len(codeSnippets) == 0 {
		return &Result{
			Verdict:     VerdictLikelySafe,
			Explanation: "No files importing this package were found in the project.",
		}, nil
	}

	userContent := fmt.Sprintf(
		"CVE ID: %s\n\nCVE Description:\n%s\n\nPackage: %s\n\nRelevant code snippets:\n\n%s",
		cveID,
		cveDescription,
		packageName,
		strings.Join(codeSnippets, "\n---\n"),
	)

	resp, err := a.client.Messages.New(ctx, anthropic.MessageNewParams{
		// Sonnet 4.6: fast, cost-effective, sufficient for security triage.
		Model:     anthropic.ModelClaudeSonnet4_6,
		MaxTokens: 1024,
		System: []anthropic.TextBlockParam{{
			Text: systemPromptText,
			// Cache the system prompt — it never changes between calls.
			CacheControl: anthropic.NewCacheControlEphemeralParam(),
		}},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(userContent)),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("impact analysis: %w", err)
	}

	var text string
	for _, block := range resp.Content {
		if tb, ok := block.AsAny().(anthropic.TextBlock); ok {
			text = tb.Text
			break
		}
	}

	return parseResult(text), nil
}

// parseResult extracts the verdict and explanation from the model's response.
func parseResult(text string) *Result {
	lines := strings.SplitN(strings.TrimSpace(text), "\n", 2)
	verdict := VerdictUncertain
	explanation := strings.TrimSpace(text)

	if len(lines) > 0 {
		first := strings.TrimSpace(strings.ToUpper(lines[0]))
		switch {
		case strings.HasPrefix(first, "EXPLOITABLE"):
			verdict = VerdictExploitable
		case strings.HasPrefix(first, "LIKELY_SAFE"):
			verdict = VerdictLikelySafe
		case strings.HasPrefix(first, "UNCERTAIN"):
			verdict = VerdictUncertain
		}
	}
	if len(lines) > 1 {
		explanation = strings.TrimSpace(lines[1])
	}

	return &Result{Verdict: verdict, Explanation: explanation}
}

// FindImportingFiles returns a list of source-file snippets (up to maxFiles)
// that import packageName in the project rooted at dir.
// ecosystem is one of "npm", "pypi", "cargo".
func FindImportingFiles(dir, packageName, ecosystem string, maxFiles int) ([]string, error) {
	var patterns []string
	switch strings.ToLower(ecosystem) {
	case "npm":
		// Four plain-substring patterns cover both quote styles.
		// matchesPattern does literal contains, not regex, so avoid regex syntax.
		patterns = []string{
			fmt.Sprintf("require('%s'", packageName),
			fmt.Sprintf(`require("%s"`, packageName),
			fmt.Sprintf("from '%s'", packageName),
			fmt.Sprintf(`from "%s"`, packageName),
		}
	case "pypi":
		norm := strings.ReplaceAll(packageName, "-", "_")
		patterns = []string{
			fmt.Sprintf(`^import %s`, norm),
			fmt.Sprintf(`^from %s import`, norm),
		}
	case "cargo":
		patterns = []string{
			fmt.Sprintf(`use %s::`, packageName),
			fmt.Sprintf(`extern crate %s`, packageName),
		}
	default:
		return nil, nil
	}

	var snippets []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if skipPath(path) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !isSourceFile(path, ecosystem) {
			return nil
		}
		if len(snippets) >= maxFiles {
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil // skip unreadable files
		}
		content := string(data)

		for _, pat := range patterns {
			if matchesPattern(content, pat) {
				// Truncate large files to first 3000 chars to control token cost.
				snippet := content
				if len(snippet) > 3000 {
					snippet = snippet[:3000] + "\n[...truncated]"
				}
				snippets = append(snippets, fmt.Sprintf("// File: %s\n%s", path, snippet))
				break
			}
		}
		return nil
	})
	return snippets, err
}

func matchesPattern(content, pattern string) bool {
	// Simple substring / prefix check without regex dependency.
	// For accurate results a proper grep would be used, but this is sufficient
	// for the common import patterns.
	lower := strings.ToLower(content)
	lowerPat := strings.ToLower(strings.TrimPrefix(pattern, "^"))
	return strings.Contains(lower, lowerPat)
}

func skipPath(path string) bool {
	for _, skip := range []string{"node_modules", ".git", "vendor", "dist", "build", "__pycache__"} {
		if strings.Contains(path, string(filepath.Separator)+skip+string(filepath.Separator)) ||
			strings.HasSuffix(path, string(filepath.Separator)+skip) {
			return true
		}
	}
	return false
}

func isSourceFile(path, ecosystem string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch strings.ToLower(ecosystem) {
	case "npm":
		return ext == ".js" || ext == ".ts" || ext == ".jsx" || ext == ".tsx" || ext == ".mjs"
	case "pypi":
		return ext == ".py"
	case "cargo":
		return ext == ".rs"
	}
	return false
}
