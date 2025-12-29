package templates

import (
	"testing"
)

func TestList(t *testing.T) {
	templates := List()
	if len(templates) == 0 {
		t.Fatal("expected at least one template")
	}

	// Check that code template exists
	found := false
	for _, tmpl := range templates {
		if tmpl.Name == "code" {
			found = true
			if tmpl.Description == "" {
				t.Error("code template should have a description")
			}
			break
		}
	}
	if !found {
		t.Error("code template not found")
	}
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"code", false},
		{"disable-telemetry", false},
		{"git-readonly", false},
		{"local-dev-server", false},
		{"nonexistent", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Load(tt.name)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if cfg == nil {
					t.Error("expected config, got nil")
				}
			}
		})
	}
}

func TestLoadWithJsonExtension(t *testing.T) {
	// Should work with or without .json extension
	cfg1, err := Load("disable-telemetry")
	if err != nil {
		t.Fatalf("failed to load disable-telemetry: %v", err)
	}

	cfg2, err := Load("disable-telemetry.json")
	if err != nil {
		t.Fatalf("failed to load disable-telemetry.json: %v", err)
	}

	// Both should return valid configs
	if cfg1 == nil || cfg2 == nil {
		t.Error("expected both configs to be non-nil")
	}
}

func TestExists(t *testing.T) {
	if !Exists("code") {
		t.Error("code template should exist")
	}
	if Exists("nonexistent") {
		t.Error("nonexistent should not exist")
	}
}

func TestCodeTemplate(t *testing.T) {
	cfg, err := Load("code")
	if err != nil {
		t.Fatalf("failed to load code template: %v", err)
	}

	// Verify key settings
	if !cfg.AllowPty {
		t.Error("code template should have AllowPty=true")
	}

	if len(cfg.Network.AllowedDomains) == 0 {
		t.Error("code template should have allowed domains")
	}

	// Check that *.anthropic.com is in allowed domains
	found := false
	for _, domain := range cfg.Network.AllowedDomains {
		if domain == "*.anthropic.com" {
			found = true
			break
		}
	}
	if !found {
		t.Error("*.anthropic.com should be in allowed domains")
	}

	// Check that cloud metadata domains are denied
	if len(cfg.Network.DeniedDomains) == 0 {
		t.Error("code template should have denied domains")
	}

	// Check command deny list
	if len(cfg.Command.Deny) == 0 {
		t.Error("code template should have denied commands")
	}
}
