package analyze

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- parseResult ---

func TestParseResult_Verdicts(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		wantVerdict     Verdict
		wantExplanation string
	}{
		{
			name:            "exploitable with explanation",
			input:           "EXPLOITABLE\nThis code calls the vulnerable JNDI lookup directly.",
			wantVerdict:     VerdictExploitable,
			wantExplanation: "This code calls the vulnerable JNDI lookup directly.",
		},
		{
			name:            "likely_safe with explanation",
			input:           "LIKELY_SAFE\nThe package is imported but only the safe API is used.",
			wantVerdict:     VerdictLikelySafe,
			wantExplanation: "The package is imported but only the safe API is used.",
		},
		{
			name:            "uncertain with explanation",
			input:           "UNCERTAIN\nInsufficient context to determine exploitability.",
			wantVerdict:     VerdictUncertain,
			wantExplanation: "Insufficient context to determine exploitability.",
		},
		{
			name:        "case insensitive exploitable",
			input:       "exploitable\nsome explanation",
			wantVerdict: VerdictExploitable,
		},
		{
			name:        "case insensitive likely_safe",
			input:       "likely_safe\nsome explanation",
			wantVerdict: VerdictLikelySafe,
		},
		{
			name:        "verdict with trailing whitespace",
			input:       "  EXPLOITABLE  \nsome explanation",
			wantVerdict: VerdictExploitable,
		},
		{
			name:        "verdict with extra text on first line",
			input:       "EXPLOITABLE: additional context\nThe code is vulnerable.",
			wantVerdict: VerdictExploitable,
		},
		{
			name:            "empty input falls back to uncertain",
			input:           "",
			wantVerdict:     VerdictUncertain,
			wantExplanation: "",
		},
		{
			name:        "garbage input falls back to uncertain",
			input:       "I cannot determine this\nsome text",
			wantVerdict: VerdictUncertain,
		},
		{
			name:            "no explanation line",
			input:           "LIKELY_SAFE",
			wantVerdict:     VerdictLikelySafe,
			wantExplanation: "LIKELY_SAFE",
		},
		{
			name:            "multi-line explanation is preserved",
			input:           "EXPLOITABLE\nLine one of explanation.\nLine two of explanation.",
			wantVerdict:     VerdictExploitable,
			wantExplanation: "Line one of explanation.\nLine two of explanation.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseResult(tt.input)
			if got.Verdict != tt.wantVerdict {
				t.Errorf("verdict = %q, want %q", got.Verdict, tt.wantVerdict)
			}
			if tt.wantExplanation != "" && got.Explanation != tt.wantExplanation {
				t.Errorf("explanation = %q, want %q", got.Explanation, tt.wantExplanation)
			}
		})
	}
}

// --- FindImportingFiles ---

func TestFindImportingFiles_NPM(t *testing.T) {
	dir := t.TempDir()

	write(t, dir, "app.js", `const express = require('express');
const x = require("other");
express.get('/', handler);`)

	write(t, dir, "utils.js", `const lodash = require('lodash');
module.exports = lodash.cloneDeep;`)

	write(t, dir, "no_import.js", `console.log('hello world');`)

	write(t, dir, "esm.ts", `import express from 'express';
import { something } from 'other';`)

	snippets, err := FindImportingFiles(dir, "express", "npm", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(snippets) != 2 {
		t.Fatalf("expected 2 snippets (app.js + esm.ts), got %d: %v", len(snippets), snippets)
	}
	for _, s := range snippets {
		if !strings.Contains(s, "express") {
			t.Errorf("snippet does not mention express: %s", s)
		}
	}
}

func TestFindImportingFiles_PyPI(t *testing.T) {
	dir := t.TempDir()

	write(t, dir, "views.py", `import django
from django import http
`)
	write(t, dir, "models.py", `from django import models
`)
	write(t, dir, "unrelated.py", `import os
import sys
`)

	snippets, err := FindImportingFiles(dir, "django", "pypi", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(snippets) < 2 {
		t.Fatalf("expected at least 2 snippets, got %d", len(snippets))
	}
}

func TestFindImportingFiles_Cargo(t *testing.T) {
	dir := t.TempDir()

	write(t, dir, "main.rs", `use serde::Deserialize;
use serde::Serialize;

fn main() {}`)
	write(t, dir, "lib.rs", `extern crate serde;
use serde::de::Error;`)
	write(t, dir, "other.rs", `fn helper() -> u32 { 42 }`)

	snippets, err := FindImportingFiles(dir, "serde", "cargo", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(snippets) != 2 {
		t.Fatalf("expected 2 snippets, got %d", len(snippets))
	}
}

func TestFindImportingFiles_SkipsNodeModules(t *testing.T) {
	dir := t.TempDir()

	// This should be found
	write(t, dir, "index.js", `const express = require('express');`)

	// These should be skipped
	nm := filepath.Join(dir, "node_modules", "express")
	if err := os.MkdirAll(nm, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, nm, "index.js", `const express = require('express');`)

	snippets, err := FindImportingFiles(dir, "express", "npm", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(snippets) != 1 {
		t.Fatalf("expected 1 snippet (node_modules skipped), got %d", len(snippets))
	}
}

func TestFindImportingFiles_SkipsVendorAndGit(t *testing.T) {
	dir := t.TempDir()

	write(t, dir, "main.rs", `use serde::Deserialize;`)

	for _, skip := range []string{"vendor", ".git"} {
		d := filepath.Join(dir, skip)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		write(t, d, "lib.rs", `use serde::Serialize;`)
	}

	snippets, err := FindImportingFiles(dir, "serde", "cargo", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(snippets) != 1 {
		t.Fatalf("expected 1 snippet (vendor/.git skipped), got %d", len(snippets))
	}
}

func TestFindImportingFiles_RespectsMaxFiles(t *testing.T) {
	dir := t.TempDir()

	for i := 0; i < 5; i++ {
		write(t, dir, filepath.Join("sub", string(rune('a'+i))+".js"),
			`const express = require('express');`)
	}

	snippets, err := FindImportingFiles(dir, "express", "npm", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(snippets) != 3 {
		t.Fatalf("expected 3 snippets (maxFiles=3), got %d", len(snippets))
	}
}

func TestFindImportingFiles_TruncatesLargeFiles(t *testing.T) {
	dir := t.TempDir()

	// Build a file larger than 3000 chars that imports the package
	big := `const express = require('express');
` + strings.Repeat("x", 4000)
	write(t, dir, "big.js", big)

	snippets, err := FindImportingFiles(dir, "express", "npm", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(snippets) != 1 {
		t.Fatalf("expected 1 snippet, got %d", len(snippets))
	}
	if !strings.Contains(snippets[0], "[...truncated]") {
		t.Error("expected truncation marker in large file snippet")
	}
}

func TestFindImportingFiles_UnknownEcosystem(t *testing.T) {
	dir := t.TempDir()
	snippets, err := FindImportingFiles(dir, "pkg", "maven", 10)
	if err != nil {
		t.Fatal(err)
	}
	if snippets != nil {
		t.Errorf("expected nil for unknown ecosystem, got %v", snippets)
	}
}

// write is a test helper that creates a file with the given content.
func write(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
