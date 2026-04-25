package pm

// NPM handles npm, yarn, and pnpm, all of which use `install` to add packages.
type NPM struct {
	binary string
}

func (n *NPM) Name() string      { return n.binary }
func (n *NPM) Ecosystem() string { return "npm" }
func (n *NPM) Binary() string    { return n.binary }

// installCmds are the sub-commands that add packages.
var npmInstallCmds = map[string]bool{
	"install": true,
	"i":       true,
	"add":     true,
}

// ParseInstall extracts package names from npm/yarn/pnpm install args.
// It skips flags (args starting with "-") and the sub-command itself.
//
// e.g. ["install", "--save-dev", "express", "lodash"] → (["express", "lodash"], true)
func (n *NPM) ParseInstall(args []string) ([]string, bool) {
	if len(args) == 0 {
		return nil, false
	}
	if !npmInstallCmds[args[0]] {
		return nil, false
	}
	var pkgs []string
	for _, a := range args[1:] {
		if len(a) > 0 && a[0] == '-' {
			continue // flag
		}
		pkgs = append(pkgs, a)
	}
	return pkgs, true
}
