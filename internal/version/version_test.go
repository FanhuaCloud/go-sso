package version

import "testing"

func TestCurrentFallsBackToDev(t *testing.T) {
	original := Version
	t.Cleanup(func() { Version = original })

	Version = "  "
	if got := Current(); got != "dev" {
		t.Fatalf("Current() = %q, want dev", got)
	}
}

func TestCurrentTrimsVersion(t *testing.T) {
	original := Version
	t.Cleanup(func() { Version = original })

	Version = " v1.2.3 "
	if got := Current(); got != "v1.2.3" {
		t.Fatalf("Current() = %q, want v1.2.3", got)
	}
}
