package ui

import (
	"regexp"
	"strings"
	"testing"
)

var serverNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$`)

func TestSecretNameForMatchesServerPattern(t *testing.T) {
	for _, in := range []string{
		"/Users/me/.aws/credentials",
		"api.github.com",
		"héllo wörld: key=1",
		"",
		strings.Repeat("x/", 300),
	} {
		got := secretNameFor(in)
		if !serverNamePattern.MatchString(got) {
			t.Errorf("secretNameFor(%q) = %q does not match server pattern", in, got)
		}
	}
	if got := secretNameFor("/Users/me/.env"); got != "Extracted--Users-me-.env" {
		t.Fatalf("secretNameFor = %q", got)
	}
	if got := secretNameFor(strings.Repeat("a", 400)); len(got) != 255 {
		t.Fatalf("len = %d", len(got))
	}
}
