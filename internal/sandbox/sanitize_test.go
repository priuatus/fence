package sandbox

import (
	"testing"
)

func TestIsDangerousEnvVar(t *testing.T) {
	tests := []struct {
		entry     string
		dangerous bool
	}{
		// Linux LD_* variables
		{"LD_PRELOAD=/tmp/evil.so", true},
		{"LD_LIBRARY_PATH=/tmp", true},
		{"LD_AUDIT=/tmp/audit.so", true},
		{"LD_DEBUG=all", true},

		// macOS DYLD_* variables
		{"DYLD_INSERT_LIBRARIES=/tmp/evil.dylib", true},
		{"DYLD_LIBRARY_PATH=/tmp", true},
		{"DYLD_FRAMEWORK_PATH=/tmp", true},
		{"DYLD_FORCE_FLAT_NAMESPACE=1", true},

		// Safe variables
		{"PATH=/usr/bin:/bin", false},
		{"HOME=/home/user", false},
		{"USER=user", false},
		{"SHELL=/bin/bash", false},
		{"HTTP_PROXY=http://localhost:8080", false},
		{"HTTPS_PROXY=http://localhost:8080", false},

		// Edge cases - variables that start with similar prefixes but aren't dangerous
		{"LDFLAGS=-L/usr/lib", false}, // Not LD_ prefix
		{"DISPLAY=:0", false},

		// Empty and malformed
		{"LD_PRELOAD", true}, // No value but still dangerous
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.entry, func(t *testing.T) {
			got := isDangerousEnvVar(tt.entry)
			if got != tt.dangerous {
				t.Errorf("isDangerousEnvVar(%q) = %v, want %v", tt.entry, got, tt.dangerous)
			}
		})
	}
}

func TestFilterDangerousEnv(t *testing.T) {
	env := []string{
		"PATH=/usr/bin:/bin",
		"LD_PRELOAD=/tmp/evil.so",
		"HOME=/home/user",
		"DYLD_INSERT_LIBRARIES=/tmp/evil.dylib",
		"HTTP_PROXY=http://localhost:8080",
		"LD_LIBRARY_PATH=/tmp",
	}

	filtered := FilterDangerousEnv(env)

	// Should have 3 safe vars
	if len(filtered) != 3 {
		t.Errorf("expected 3 safe vars, got %d: %v", len(filtered), filtered)
	}

	// Verify the safe vars are present
	expected := map[string]bool{
		"PATH=/usr/bin:/bin":               true,
		"HOME=/home/user":                  true,
		"HTTP_PROXY=http://localhost:8080": true,
	}

	for _, e := range filtered {
		if !expected[e] {
			t.Errorf("unexpected var in filtered env: %s", e)
		}
	}

	// Verify dangerous vars are gone
	for _, e := range filtered {
		if isDangerousEnvVar(e) {
			t.Errorf("dangerous var not filtered: %s", e)
		}
	}
}

func TestGetStrippedEnvVars(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"LD_PRELOAD=/tmp/evil.so",
		"DYLD_INSERT_LIBRARIES=/tmp/evil.dylib",
		"HOME=/home/user",
	}

	stripped := GetStrippedEnvVars(env)

	if len(stripped) != 2 {
		t.Errorf("expected 2 stripped vars, got %d: %v", len(stripped), stripped)
	}

	// Should contain just the keys, not values
	found := make(map[string]bool)
	for _, s := range stripped {
		found[s] = true
	}

	if !found["LD_PRELOAD"] {
		t.Error("expected LD_PRELOAD to be in stripped list")
	}
	if !found["DYLD_INSERT_LIBRARIES"] {
		t.Error("expected DYLD_INSERT_LIBRARIES to be in stripped list")
	}
}

func TestFilterDangerousEnv_EmptyInput(t *testing.T) {
	filtered := FilterDangerousEnv(nil)
	if filtered == nil {
		t.Error("expected non-nil slice for nil input")
	}
	if len(filtered) != 0 {
		t.Errorf("expected empty slice, got %v", filtered)
	}

	filtered = FilterDangerousEnv([]string{})
	if len(filtered) != 0 {
		t.Errorf("expected empty slice, got %v", filtered)
	}
}

func TestFilterDangerousEnv_AllDangerous(t *testing.T) {
	env := []string{
		"LD_PRELOAD=/tmp/evil.so",
		"LD_LIBRARY_PATH=/tmp",
		"DYLD_INSERT_LIBRARIES=/tmp/evil.dylib",
	}

	filtered := FilterDangerousEnv(env)
	if len(filtered) != 0 {
		t.Errorf("expected all vars to be filtered, got %v", filtered)
	}
}

func TestFilterDangerousEnv_AllSafe(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"HOME=/home/user",
		"USER=test",
	}

	filtered := FilterDangerousEnv(env)
	if len(filtered) != 3 {
		t.Errorf("expected all 3 vars to pass through, got %d", len(filtered))
	}
}
