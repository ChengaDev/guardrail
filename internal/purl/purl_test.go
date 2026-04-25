package purl

import (
	"testing"
)

func TestBuild(t *testing.T) {
	tests := []struct {
		ecosystem string
		name      string
		version   string
		want      string
	}{
		{"npm", "express", "4.18.2", "pkg:npm/express@4.18.2"},
		{"npm", "@scope/pkg", "1.0.0", "pkg:npm/%40scope%2Fpkg@1.0.0"},
		{"pypi", "Django", "4.2.0", "pkg:pypi/django@4.2.0"},
		{"pypi", "my_package", "1.0.0", "pkg:pypi/my-package@1.0.0"},
		{"cargo", "serde", "1.0.0", "pkg:cargo/serde@1.0.0"},
		{"golang", "github.com/gin-gonic/gin", "v1.9.0", "pkg:golang/github.com/gin-gonic/gin@v1.9.0"},
		{"maven", "org.example/mylib", "2.0.0", "pkg:maven/org.example/mylib@2.0.0"},
	}

	for _, tt := range tests {
		got := Build(tt.ecosystem, tt.name, tt.version)
		if got != tt.want {
			t.Errorf("Build(%q, %q, %q) = %q, want %q", tt.ecosystem, tt.name, tt.version, got, tt.want)
		}
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		input     string
		wantEco   string
		wantName  string
		wantVer   string
		wantErr   bool
	}{
		{"pkg:npm/express@4.18.2", "npm", "express", "4.18.2", false},
		{"pkg:npm/%40scope%2Fpkg@1.0.0", "npm", "@scope/pkg", "1.0.0", false},
		{"pkg:pypi/django@4.2.0", "pypi", "django", "4.2.0", false},
		{"pkg:cargo/serde@1.0.0", "cargo", "serde", "1.0.0", false},
		{"pkg:npm/express", "npm", "express", "", false}, // no version
		{"notapurl", "", "", "", true},
		{"pkg:missingslash", "", "", "", true},
	}

	for _, tt := range tests {
		eco, name, ver, err := Parse(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("Parse(%q): expected error, got none", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("Parse(%q): unexpected error: %v", tt.input, err)
			continue
		}
		if eco != tt.wantEco || name != tt.wantName || ver != tt.wantVer {
			t.Errorf("Parse(%q) = (%q, %q, %q), want (%q, %q, %q)",
				tt.input, eco, name, ver, tt.wantEco, tt.wantName, tt.wantVer)
		}
	}
}

// Round-trip: Build then Parse should recover the original values.
func TestBuildParseRoundTrip(t *testing.T) {
	cases := []struct{ eco, name, ver string }{
		{"npm", "lodash", "4.17.21"},
		{"npm", "@babel/core", "7.0.0"},
		{"pypi", "requests", "2.31.0"},
		{"cargo", "tokio", "1.35.0"},
	}
	for _, c := range cases {
		built := Build(c.eco, c.name, c.ver)
		eco, name, ver, err := Parse(built)
		if err != nil {
			t.Errorf("Parse(Build(%q,%q,%q)) error: %v", c.eco, c.name, c.ver, err)
			continue
		}
		// PyPI normalizes name; adjust expectation
		wantName := c.name
		if c.eco == "pypi" {
			wantName = normalizePyPI(c.name)
		}
		if eco != c.eco || name != wantName || ver != c.ver {
			t.Errorf("round-trip (%q,%q,%q): got (%q,%q,%q)", c.eco, c.name, c.ver, eco, name, ver)
		}
	}
}

// normalizePyPI mirrors the package-level normalization for test expectations.
func normalizePyPI(name string) string {
	result := ""
	for _, ch := range name {
		if ch == '_' {
			result += "-"
		} else if ch >= 'A' && ch <= 'Z' {
			result += string(ch + 32)
		} else {
			result += string(ch)
		}
	}
	return result
}
