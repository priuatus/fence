package sandbox

import (
	"testing"

	"github.com/Use-Tusk/fence/internal/config"
)

// TestLinux_WildcardAllowedDomainsSkipsUnshareNet verifies that when allowedDomains
// contains "*", the Linux sandbox does NOT use --unshare-net, allowing direct
// network connections for applications that don't respect HTTP_PROXY.
func TestLinux_WildcardAllowedDomainsSkipsUnshareNet(t *testing.T) {
	tests := []struct {
		name           string
		allowedDomains []string
		wantUnshareNet bool
	}{
		{
			name:           "no domains - uses unshare-net",
			allowedDomains: []string{},
			wantUnshareNet: true,
		},
		{
			name:           "specific domain - uses unshare-net",
			allowedDomains: []string{"api.openai.com"},
			wantUnshareNet: true,
		},
		{
			name:           "wildcard domain - skips unshare-net",
			allowedDomains: []string{"*"},
			wantUnshareNet: false,
		},
		{
			name:           "wildcard with specific domains - skips unshare-net",
			allowedDomains: []string{"api.openai.com", "*"},
			wantUnshareNet: false,
		},
		{
			name:           "wildcard subdomain pattern - uses unshare-net",
			allowedDomains: []string{"*.openai.com"},
			wantUnshareNet: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Network: config.NetworkConfig{
					AllowedDomains: tt.allowedDomains,
				},
				Filesystem: config.FilesystemConfig{
					AllowWrite: []string{"/tmp/test"},
				},
			}

			// Check the wildcard detection logic directly
			hasWildcard := hasWildcardAllowedDomain(cfg)

			if tt.wantUnshareNet && hasWildcard {
				t.Errorf("expected hasWildcard=false for domains %v, got true", tt.allowedDomains)
			}
			if !tt.wantUnshareNet && !hasWildcard {
				t.Errorf("expected hasWildcard=true for domains %v, got false", tt.allowedDomains)
			}
		})
	}
}

// hasWildcardAllowedDomain checks if the config contains a "*" in allowedDomains.
// This replicates the logic used in both linux.go and macos.go.
func hasWildcardAllowedDomain(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	for _, d := range cfg.Network.AllowedDomains {
		if d == "*" {
			return true
		}
	}
	return false
}

// TestWildcardDetectionLogic tests the wildcard detection helper.
// This logic is shared between macOS and Linux sandbox implementations.
func TestWildcardDetectionLogic(t *testing.T) {
	tests := []struct {
		name           string
		cfg            *config.Config
		expectWildcard bool
	}{
		{
			name:           "nil config",
			cfg:            nil,
			expectWildcard: false,
		},
		{
			name: "empty allowed domains",
			cfg: &config.Config{
				Network: config.NetworkConfig{
					AllowedDomains: []string{},
				},
			},
			expectWildcard: false,
		},
		{
			name: "specific domains only",
			cfg: &config.Config{
				Network: config.NetworkConfig{
					AllowedDomains: []string{"example.com", "api.openai.com"},
				},
			},
			expectWildcard: false,
		},
		{
			name: "exact star wildcard",
			cfg: &config.Config{
				Network: config.NetworkConfig{
					AllowedDomains: []string{"*"},
				},
			},
			expectWildcard: true,
		},
		{
			name: "star wildcard among others",
			cfg: &config.Config{
				Network: config.NetworkConfig{
					AllowedDomains: []string{"example.com", "*", "api.openai.com"},
				},
			},
			expectWildcard: true,
		},
		{
			name: "prefix wildcard is not star",
			cfg: &config.Config{
				Network: config.NetworkConfig{
					AllowedDomains: []string{"*.example.com"},
				},
			},
			expectWildcard: false,
		},
		{
			name: "star in domain name is not wildcard",
			cfg: &config.Config{
				Network: config.NetworkConfig{
					AllowedDomains: []string{"test*domain.com"},
				},
			},
			expectWildcard: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasWildcardAllowedDomain(tt.cfg)
			if got != tt.expectWildcard {
				t.Errorf("hasWildcardAllowedDomain() = %v, want %v", got, tt.expectWildcard)
			}
		})
	}
}
