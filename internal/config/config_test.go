package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateDomainPattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		// Valid patterns
		{"valid domain", "example.com", false},
		{"valid subdomain", "api.example.com", false},
		{"valid wildcard", "*.example.com", false},
		{"valid wildcard subdomain", "*.api.example.com", false},
		{"localhost", "localhost", false},

		// Invalid patterns
		{"protocol included", "https://example.com", true},
		{"path included", "example.com/path", true},
		{"port included", "example.com:443", true},
		{"wildcard too broad", "*.com", true},
		{"invalid wildcard position", "example.*.com", true},
		{"trailing wildcard", "example.com.*", true},
		{"leading dot", ".example.com", true},
		{"trailing dot", "example.com.", true},
		{"no TLD", "example", true},
		{"empty wildcard domain part", "*.", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDomainPattern(tt.pattern)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateDomainPattern(%q) error = %v, wantErr %v", tt.pattern, err, tt.wantErr)
			}
		})
	}
}

func TestMatchesDomain(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		pattern  string
		want     bool
	}{
		// Exact matches
		{"exact match", "example.com", "example.com", true},
		{"exact match case insensitive", "Example.COM", "example.com", true},
		{"exact no match", "other.com", "example.com", false},

		// Wildcard matches
		{"wildcard match subdomain", "api.example.com", "*.example.com", true},
		{"wildcard match deep subdomain", "deep.api.example.com", "*.example.com", true},
		{"wildcard no match base domain", "example.com", "*.example.com", false},
		{"wildcard no match different domain", "api.other.com", "*.example.com", false},
		{"wildcard case insensitive", "API.Example.COM", "*.example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchesDomain(tt.hostname, tt.pattern)
			if got != tt.want {
				t.Errorf("MatchesDomain(%q, %q) = %v, want %v", tt.hostname, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name:    "valid empty config",
			config:  Config{},
			wantErr: false,
		},
		{
			name: "valid config with domains",
			config: Config{
				Network: NetworkConfig{
					AllowedDomains: []string{"example.com", "*.github.com"},
					DeniedDomains:  []string{"blocked.com"},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid allowed domain",
			config: Config{
				Network: NetworkConfig{
					AllowedDomains: []string{"https://example.com"},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid denied domain",
			config: Config{
				Network: NetworkConfig{
					DeniedDomains: []string{"*.com"},
				},
			},
			wantErr: true,
		},
		{
			name: "empty denyRead path",
			config: Config{
				Filesystem: FilesystemConfig{
					DenyRead: []string{""},
				},
			},
			wantErr: true,
		},
		{
			name: "empty allowWrite path",
			config: Config{
				Filesystem: FilesystemConfig{
					AllowWrite: []string{""},
				},
			},
			wantErr: true,
		},
		{
			name: "empty denyWrite path",
			config: Config{
				Filesystem: FilesystemConfig{
					DenyWrite: []string{""},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefault(t *testing.T) {
	cfg := Default()
	if cfg == nil {
		t.Fatal("Default() returned nil")
	}
	if cfg.Network.AllowedDomains == nil {
		t.Error("AllowedDomains should not be nil")
	}
	if cfg.Network.DeniedDomains == nil {
		t.Error("DeniedDomains should not be nil")
	}
	if cfg.Filesystem.DenyRead == nil {
		t.Error("DenyRead should not be nil")
	}
	if cfg.Filesystem.AllowWrite == nil {
		t.Error("AllowWrite should not be nil")
	}
	if cfg.Filesystem.DenyWrite == nil {
		t.Error("DenyWrite should not be nil")
	}
}

func TestLoad(t *testing.T) {
	// Create temp directory for test files
	tmpDir := t.TempDir()

	tests := []struct {
		name        string
		content     string
		setup       func(string) string // returns path
		wantNil     bool
		wantErr     bool
		checkConfig func(*testing.T, *Config)
	}{
		{
			name:    "nonexistent file",
			setup:   func(dir string) string { return filepath.Join(dir, "nonexistent.json") },
			wantNil: true,
			wantErr: false,
		},
		{
			name:    "empty file",
			content: "",
			setup: func(dir string) string {
				path := filepath.Join(dir, "empty.json")
				_ = os.WriteFile(path, []byte(""), 0o600)
				return path
			},
			wantNil: true,
			wantErr: false,
		},
		{
			name:    "whitespace only file",
			content: "   \n\t  ",
			setup: func(dir string) string {
				path := filepath.Join(dir, "whitespace.json")
				_ = os.WriteFile(path, []byte("   \n\t  "), 0o600)
				return path
			},
			wantNil: true,
			wantErr: false,
		},
		{
			name: "valid config",
			setup: func(dir string) string {
				path := filepath.Join(dir, "valid.json")
				content := `{"network":{"allowedDomains":["example.com"]}}`
				_ = os.WriteFile(path, []byte(content), 0o600)
				return path
			},
			wantNil: false,
			wantErr: false,
			checkConfig: func(t *testing.T, cfg *Config) {
				if len(cfg.Network.AllowedDomains) != 1 {
					t.Errorf("expected 1 allowed domain, got %d", len(cfg.Network.AllowedDomains))
				}
				if cfg.Network.AllowedDomains[0] != "example.com" {
					t.Errorf("expected example.com, got %s", cfg.Network.AllowedDomains[0])
				}
			},
		},
		{
			name: "invalid JSON",
			setup: func(dir string) string {
				path := filepath.Join(dir, "invalid.json")
				_ = os.WriteFile(path, []byte("{invalid json}"), 0o600)
				return path
			},
			wantNil: false,
			wantErr: true,
		},
		{
			name: "invalid domain in config",
			setup: func(dir string) string {
				path := filepath.Join(dir, "invalid_domain.json")
				content := `{"network":{"allowedDomains":["*.com"]}}`
				_ = os.WriteFile(path, []byte(content), 0o600)
				return path
			},
			wantNil: false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup(tmpDir)
			cfg, err := Load(path)

			if (err != nil) != tt.wantErr {
				t.Errorf("Load() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantNil && cfg != nil {
				t.Error("Load() expected nil config")
				return
			}

			if !tt.wantNil && !tt.wantErr && cfg == nil {
				t.Error("Load() returned nil config unexpectedly")
				return
			}

			if tt.checkConfig != nil && cfg != nil {
				tt.checkConfig(t, cfg)
			}
		})
	}
}

func TestDefaultConfigPath(t *testing.T) {
	path := DefaultConfigPath()
	if path == "" {
		t.Error("DefaultConfigPath() returned empty string")
	}
	// Should end with .fence.json
	if filepath.Base(path) != ".fence.json" {
		t.Errorf("DefaultConfigPath() = %q, expected to end with .fence.json", path)
	}
}
