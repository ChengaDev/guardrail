package severity

import (
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		input string
		want  Level
	}{
		{"CRITICAL", LevelCritical},
		{"critical", LevelCritical},
		{"HIGH", LevelHigh},
		{"high", LevelHigh},
		{"MEDIUM", LevelMedium},
		{"LOW", LevelLow},
		{"NONE", LevelNone},
		{"  HIGH  ", LevelHigh},   // whitespace trimmed
		{"unknown", LevelMedium},  // conservative default
		{"", LevelMedium},         // conservative default
		{"bogus", LevelMedium},
	}

	for _, tt := range tests {
		got := Parse(tt.input)
		if got != tt.want {
			t.Errorf("Parse(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestFromCVSS(t *testing.T) {
	tests := []struct {
		score float64
		want  Level
	}{
		{10.0, LevelCritical},
		{9.0, LevelCritical},
		{8.9, LevelHigh},
		{7.0, LevelHigh},
		{6.9, LevelMedium},
		{4.0, LevelMedium},
		{3.9, LevelLow},
		{0.1, LevelLow},
		{0.0, LevelNone},
		{-1.0, LevelNone},
	}

	for _, tt := range tests {
		got := FromCVSS(tt.score)
		if got != tt.want {
			t.Errorf("FromCVSS(%v) = %v, want %v", tt.score, got, tt.want)
		}
	}
}

func TestMeetsThreshold(t *testing.T) {
	tests := []struct {
		level     Level
		threshold Level
		want      bool
	}{
		{LevelCritical, LevelHigh, true},
		{LevelHigh, LevelHigh, true},
		{LevelMedium, LevelHigh, false},
		{LevelLow, LevelHigh, false},
		{LevelNone, LevelNone, true},
		{LevelLow, LevelNone, true},
		{LevelCritical, LevelCritical, true},
		{LevelHigh, LevelCritical, false},
	}

	for _, tt := range tests {
		got := MeetsThreshold(tt.level, tt.threshold)
		if got != tt.want {
			t.Errorf("MeetsThreshold(%v, %v) = %v, want %v", tt.level, tt.threshold, got, tt.want)
		}
	}
}

func TestLevelString(t *testing.T) {
	cases := []struct {
		level Level
		want  string
	}{
		{LevelNone, "NONE"},
		{LevelLow, "LOW"},
		{LevelMedium, "MEDIUM"},
		{LevelHigh, "HIGH"},
		{LevelCritical, "CRITICAL"},
		{Level(99), "UNKNOWN"},
	}
	for _, c := range cases {
		if got := c.level.String(); got != c.want {
			t.Errorf("Level(%d).String() = %q, want %q", c.level, got, c.want)
		}
	}
}
