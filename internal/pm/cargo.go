package pm

// Cargo handles cargo.
type Cargo struct {
	binary string
}

func (c *Cargo) Name() string      { return "cargo" }
func (c *Cargo) Ecosystem() string { return "cargo" }
func (c *Cargo) Binary() string    { return c.binary }

// ParseInstall extracts package names from cargo add args.
//
// e.g. ["add", "serde", "tokio"] → (["serde", "tokio"], true)
// e.g. ["add", "serde@1.0"] → (["serde"], true)  — version is stripped
func (c *Cargo) ParseInstall(args []string) ([]string, bool) {
	if len(args) == 0 || args[0] != "add" {
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
			// Flags that consume the next argument
			switch a {
			case "--features", "-F",
				"--manifest-path",
				"--target":
				skip = true
			}
			continue
		}
		// Preserve "crate@version" so the caller can extract the pinned version.
		pkgs = append(pkgs, a)
	}
	return pkgs, true
}
