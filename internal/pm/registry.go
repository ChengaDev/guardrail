// Package pm provides package manager adapters and auto-detection.
package pm

import (
	"fmt"
	"os"
	"os/exec"
)

// Manager describes a supported package manager.
type Manager interface {
	// Name returns the display name (e.g. "npm").
	Name() string
	// Ecosystem returns the OSV/PURL ecosystem identifier (e.g. "npm", "pypi", "cargo").
	Ecosystem() string
	// ParseInstall extracts package names from the args passed after the PM name.
	// e.g. ["install", "express", "lodash"] → (["express", "lodash"], true)
	// Returns isInstall=false if the sub-command is not an install operation.
	ParseInstall(args []string) (packages []string, isInstall bool)
	// Binary returns the path/name of the real PM binary.
	Binary() string
}

// Exec runs the real package manager with the provided args, inheriting stdio.
func Exec(binary string, args []string) error {
	path, err := exec.LookPath(binary)
	if err != nil {
		return fmt.Errorf("package manager %q not found in PATH: %w", binary, err)
	}
	cmd := exec.Command(path, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// byCommand maps command-line names to Manager instances.
var byCommand = map[string]Manager{
	"npm":   &NPM{binary: "npm"},
	"yarn":  &NPM{binary: "yarn"},  // yarn uses the same install syntax
	"pnpm":  &NPM{binary: "pnpm"}, // pnpm uses the same install syntax
	"pip":   &Pip{binary: "pip"},
	"pip3":  &Pip{binary: "pip3"},
	"cargo": &Cargo{binary: "cargo"},
}

// Lookup returns the Manager for a command name, e.g. "npm".
func Lookup(cmd string) (Manager, bool) {
	m, ok := byCommand[cmd]
	return m, ok
}

// Register adds or replaces a Manager for a command name.
// Use this to override the binary path from config.
func Register(cmd string, m Manager) {
	byCommand[cmd] = m
}
