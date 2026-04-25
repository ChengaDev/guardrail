package pm

// Pip handles pip and pip3.
type Pip struct {
	binary string
}

func (p *Pip) Name() string      { return p.binary }
func (p *Pip) Ecosystem() string { return "pypi" }
func (p *Pip) Binary() string    { return p.binary }

// ParseInstall extracts package names from pip install args.
// Skips flags and options (e.g. -r requirements.txt, --upgrade).
//
// e.g. ["install", "--upgrade", "django", "requests"] → (["django", "requests"], true)
func (p *Pip) ParseInstall(args []string) ([]string, bool) {
	if len(args) == 0 || args[0] != "install" {
		return nil, false
	}
	var pkgs []string
	skip := false
	for _, a := range args[1:] {
		if skip {
			skip = false
			continue
		}
		if len(a) > 0 && a[0] == '-' {
			// Some flags take a value argument: -r, -c, -t, --extra-index-url, etc.
			// We skip those values to avoid treating them as package names.
			switch a {
			case "-r", "--requirement",
				"-c", "--constraint",
				"-t", "--target",
				"-d", "--download",
				"--index-url", "-i",
				"--extra-index-url",
				"--find-links", "-f",
				"--root", "--prefix":
				skip = true
			}
			continue
		}
		// Skip version specifiers in "package==1.2.3" form — keep the name
		pkgs = append(pkgs, stripVersion(a))
	}
	return pkgs, true
}

// stripVersion removes version specifiers from a pip package argument.
// e.g. "django==3.2.0" → "django", "requests>=2.0" → "requests"
func stripVersion(pkg string) string {
	for i, c := range pkg {
		if c == '=' || c == '>' || c == '<' || c == '!' || c == '~' || c == '^' {
			return pkg[:i]
		}
	}
	return pkg
}
