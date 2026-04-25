package severity

import (
	"strings"
)

// Level represents a CVE severity level.
type Level int

const (
	LevelNone     Level = 0
	LevelLow      Level = 1
	LevelMedium   Level = 2
	LevelHigh     Level = 3
	LevelCritical Level = 4
)

// String returns the human-readable name of the severity level.
func (l Level) String() string {
	switch l {
	case LevelNone:
		return "NONE"
	case LevelLow:
		return "LOW"
	case LevelMedium:
		return "MEDIUM"
	case LevelHigh:
		return "HIGH"
	case LevelCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// Parse converts a string like "HIGH" or "CRITICAL" to a Level.
// Unrecognized values default to MEDIUM (conservative).
func Parse(s string) Level {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "NONE":
		return LevelNone
	case "LOW":
		return LevelLow
	case "MEDIUM":
		return LevelMedium
	case "HIGH":
		return LevelHigh
	case "CRITICAL":
		return LevelCritical
	default:
		return LevelMedium
	}
}

// FromCVSS converts a CVSS numeric score to a severity level.
func FromCVSS(score float64) Level {
	switch {
	case score >= 9.0:
		return LevelCritical
	case score >= 7.0:
		return LevelHigh
	case score >= 4.0:
		return LevelMedium
	case score > 0:
		return LevelLow
	default:
		return LevelNone
	}
}

// MeetsThreshold reports whether l is at or above threshold.
func MeetsThreshold(l, threshold Level) bool {
	return l >= threshold
}

// Emoji returns the colored emoji indicator for the level.
func (l Level) Emoji() string {
	switch l {
	case LevelCritical:
		return "🔴 CRITICAL"
	case LevelHigh:
		return "🟠 HIGH    "
	case LevelMedium:
		return "🟡 MEDIUM  "
	case LevelLow:
		return "🔵 LOW     "
	default:
		return "⚪ NONE    "
	}
}
