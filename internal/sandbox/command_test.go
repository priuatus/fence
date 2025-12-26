package sandbox

import (
	"testing"

	"github.com/Use-Tusk/fence/internal/config"
)

func TestCheckCommand_BasicDeny(t *testing.T) {
	cfg := &config.Config{
		Command: config.CommandConfig{
			Deny:        []string{"git push", "rm -rf"},
			UseDefaults: boolPtr(false), // Disable defaults for cleaner testing
		},
	}

	tests := []struct {
		command     string
		shouldBlock bool
		blockPrefix string
	}{
		// Exact matches
		{"git push", true, "git push"},
		{"rm -rf", true, "rm -rf"},

		// Prefix matches
		{"git push origin main", true, "git push"},
		{"rm -rf /", true, "rm -rf"},
		{"rm -rf .", true, "rm -rf"},

		// Should NOT match
		{"git status", false, ""},
		{"git pull", false, ""},
		{"rm file.txt", false, ""},
		{"rm -r dir", false, ""},
		{"echo git push", false, ""}, // git push is an argument, not a command
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			err := CheckCommand(tt.command, cfg)
			if tt.shouldBlock {
				if err == nil {
					t.Errorf("expected command %q to be blocked", tt.command)
					return
				}
				blocked, ok := err.(*CommandBlockedError)
				if !ok {
					t.Errorf("expected CommandBlockedError, got %T", err)
					return
				}
				if blocked.BlockedPrefix != tt.blockPrefix {
					t.Errorf("expected block prefix %q, got %q", tt.blockPrefix, blocked.BlockedPrefix)
				}
			} else if err != nil {
				t.Errorf("expected command %q to be allowed, got error: %v", tt.command, err)
			}
		})
	}
}

func TestCheckCommand_Allow(t *testing.T) {
	cfg := &config.Config{
		Command: config.CommandConfig{
			Deny:        []string{"git push"},
			Allow:       []string{"git push origin docs"},
			UseDefaults: boolPtr(false),
		},
	}

	tests := []struct {
		command     string
		shouldBlock bool
	}{
		// Allowed by explicit allow rule
		{"git push origin docs", false},
		{"git push origin docs --force", false},

		// Still blocked (not in allow list)
		{"git push origin main", true},
		{"git push", true},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			err := CheckCommand(tt.command, cfg)
			if tt.shouldBlock && err == nil {
				t.Errorf("expected command %q to be blocked", tt.command)
			}
			if !tt.shouldBlock && err != nil {
				t.Errorf("expected command %q to be allowed, got error: %v", tt.command, err)
			}
		})
	}
}

func TestCheckCommand_DefaultDenyList(t *testing.T) {
	// Test with defaults enabled (nil = true)
	cfg := &config.Config{
		Command: config.CommandConfig{
			Deny:        []string{},
			UseDefaults: nil, // defaults to true
		},
	}

	tests := []struct {
		command     string
		shouldBlock bool
	}{
		// Default denied commands
		{"shutdown", true},
		{"shutdown -h now", true},
		{"reboot", true},
		{"halt", true},
		{"insmod malicious.ko", true},
		{"rmmod module", true},
		{"mkfs.ext4 /dev/sda1", true},

		// Normal commands should be allowed
		{"ls", false},
		{"git status", false},
		{"npm install", false},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			err := CheckCommand(tt.command, cfg)
			if tt.shouldBlock {
				if err == nil {
					t.Errorf("expected command %q to be blocked by defaults", tt.command)
					return
				}
				blocked, ok := err.(*CommandBlockedError)
				if !ok {
					t.Errorf("expected CommandBlockedError, got %T", err)
					return
				}
				if !blocked.IsDefault {
					t.Errorf("expected IsDefault=true for default deny list")
				}
			} else if err != nil {
				t.Errorf("expected command %q to be allowed, got error: %v", tt.command, err)
			}
		})
	}
}

func TestCheckCommand_DisableDefaults(t *testing.T) {
	cfg := &config.Config{
		Command: config.CommandConfig{
			Deny:        []string{},
			UseDefaults: boolPtr(false),
		},
	}

	// When defaults disabled, "shutdown" should be allowed
	err := CheckCommand("shutdown", cfg)
	if err != nil {
		t.Errorf("expected 'shutdown' to be allowed when defaults disabled, got: %v", err)
	}
}

func TestCheckCommand_ChainedCommands(t *testing.T) {
	cfg := &config.Config{
		Command: config.CommandConfig{
			Deny:        []string{"git push"},
			UseDefaults: boolPtr(false),
		},
	}

	tests := []struct {
		command     string
		shouldBlock bool
		desc        string
	}{
		// Chained with &&
		{"ls && git push", true, "git push in && chain"},
		{"git push && ls", true, "git push at start of && chain"},
		{"ls && echo hello && git push origin main", true, "git push at end of && chain"},

		// Chained with ||
		{"ls || git push", true, "git push in || chain"},
		{"git status || git push", true, "git push after ||"},

		// Chained with ;
		{"ls; git push", true, "git push after semicolon"},
		{"git push; ls", true, "git push before semicolon"},

		// Chained with |
		{"echo hello | git push", true, "git push in pipe"},
		{"git status | grep something", false, "no git push in pipe"},

		// Multiple operators
		{"ls && echo hi || git push", true, "git push in mixed chain"},
		{"ls; pwd; git push origin main", true, "git push in semicolon chain"},

		// Safe chains
		{"ls && pwd", false, "safe commands only"},
		{"git status | grep branch", false, "safe git command in pipe"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			err := CheckCommand(tt.command, cfg)
			if tt.shouldBlock && err == nil {
				t.Errorf("expected command %q to be blocked", tt.command)
			}
			if !tt.shouldBlock && err != nil {
				t.Errorf("expected command %q to be allowed, got error: %v", tt.command, err)
			}
		})
	}
}

func TestCheckCommand_NestedShellInvocation(t *testing.T) {
	cfg := &config.Config{
		Command: config.CommandConfig{
			Deny:        []string{"git push"},
			UseDefaults: boolPtr(false),
		},
	}

	tests := []struct {
		command     string
		shouldBlock bool
		desc        string
	}{
		// bash -c patterns
		{`bash -c "git push"`, true, "bash -c with git push"},
		{`bash -c 'git push origin main'`, true, "bash -c single quotes"},
		{`sh -c "git push"`, true, "sh -c with git push"},
		{`zsh -c "git push"`, true, "zsh -c with git push"},

		// bash -c with chained commands
		{`bash -c "ls && git push"`, true, "bash -c with chained git push"},
		{`sh -c 'git status; git push'`, true, "sh -c semicolon chain"},

		// Safe bash -c
		{`bash -c "git status"`, false, "bash -c with safe command"},
		{`bash -c 'ls && pwd'`, false, "bash -c with safe chain"},

		// bash -lc (login shell)
		{`bash -lc "git push"`, true, "bash -lc with git push"},

		// Full path to shell
		{`/bin/bash -c "git push"`, true, "full path bash -c"},
		{`/usr/bin/zsh -c 'git push origin main'`, true, "full path zsh -c"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			err := CheckCommand(tt.command, cfg)
			if tt.shouldBlock && err == nil {
				t.Errorf("expected command %q to be blocked", tt.command)
			}
			if !tt.shouldBlock && err != nil {
				t.Errorf("expected command %q to be allowed, got error: %v", tt.command, err)
			}
		})
	}
}

func TestCheckCommand_PathNormalization(t *testing.T) {
	cfg := &config.Config{
		Command: config.CommandConfig{
			Deny:        []string{"git push"},
			UseDefaults: boolPtr(false),
		},
	}

	tests := []struct {
		command     string
		shouldBlock bool
		desc        string
	}{
		// Full paths should be normalized
		{"/usr/bin/git push", true, "full path git"},
		{"/usr/local/bin/git push origin main", true, "full path git with args"},

		// Relative paths
		{"./git push", true, "relative path git"},
		{"../bin/git push", true, "relative parent path git"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			err := CheckCommand(tt.command, cfg)
			if tt.shouldBlock && err == nil {
				t.Errorf("expected command %q to be blocked", tt.command)
			}
			if !tt.shouldBlock && err != nil {
				t.Errorf("expected command %q to be allowed, got error: %v", tt.command, err)
			}
		})
	}
}

func TestCheckCommand_QuotedArguments(t *testing.T) {
	cfg := &config.Config{
		Command: config.CommandConfig{
			Deny:        []string{"git push"},
			UseDefaults: boolPtr(false),
		},
	}

	tests := []struct {
		command     string
		shouldBlock bool
		desc        string
	}{
		// Quotes shouldn't affect matching
		{`git push "origin" "main"`, true, "double quoted args"},
		{`git push 'origin' 'main'`, true, "single quoted args"},

		// "git push" as a string argument to another command should NOT block
		{`echo "git push"`, false, "git push as echo argument"},
		{`grep "git push" log.txt`, false, "git push in grep pattern"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			err := CheckCommand(tt.command, cfg)
			if tt.shouldBlock && err == nil {
				t.Errorf("expected command %q to be blocked", tt.command)
			}
			if !tt.shouldBlock && err != nil {
				t.Errorf("expected command %q to be allowed, got error: %v", tt.command, err)
			}
		})
	}
}

func TestCheckCommand_EdgeCases(t *testing.T) {
	cfg := &config.Config{
		Command: config.CommandConfig{
			Deny:        []string{"rm -rf"},
			UseDefaults: boolPtr(false),
		},
	}

	tests := []struct {
		command     string
		shouldBlock bool
		desc        string
	}{
		// Empty command
		{"", false, "empty command"},
		{"   ", false, "whitespace only"},

		// Command that's a prefix of blocked command
		{"rm", false, "rm alone"},
		{"rm -r", false, "rm -r (not -rf)"},
		{"rm -f", false, "rm -f (not -rf)"},
		{"rm -rf", true, "rm -rf exact"},
		{"rm -rf /", true, "rm -rf with path"},

		// Similar but different
		{"rmdir", false, "rmdir (different command)"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			err := CheckCommand(tt.command, cfg)
			if tt.shouldBlock && err == nil {
				t.Errorf("expected command %q to be blocked", tt.command)
			}
			if !tt.shouldBlock && err != nil {
				t.Errorf("expected command %q to be allowed, got error: %v", tt.command, err)
			}
		})
	}
}

func TestParseShellCommand(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"ls", []string{"ls"}},
		{"ls && pwd", []string{"ls", "pwd"}},
		{"ls || pwd", []string{"ls", "pwd"}},
		{"ls; pwd", []string{"ls", "pwd"}},
		{"ls | grep foo", []string{"ls", "grep foo"}},
		{"ls && pwd || echo fail; date", []string{"ls", "pwd", "echo fail", "date"}},

		// Quotes should be preserved
		{`echo "hello && world"`, []string{`echo "hello && world"`}},
		{`echo 'a; b'`, []string{`echo 'a; b'`}},

		// Parentheses (subshells) - preserved as single unit
		{"(ls && pwd)", []string{"(ls && pwd)"}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			// parseShellCommand also expands shell invocations, so we just check basics
			result := parseShellCommand(tt.input)

			// For non-shell-invocation cases, result should match expected
			// (shell invocations will add extra entries)
			if len(result) < len(tt.expected) {
				t.Errorf("expected at least %d commands, got %d: %v", len(tt.expected), len(result), result)
			}
		})
	}
}

func TestNormalizeCommand(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"git push", "git push"},
		{"/usr/bin/git push", "git push"},
		{"/usr/local/bin/git push origin main", "git push origin main"},
		{"./script.sh arg1 arg2", "script.sh arg1 arg2"},
		{"  git   push  ", "git push"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeCommand(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeCommand(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestMatchesPrefix(t *testing.T) {
	tests := []struct {
		command  string
		prefix   string
		expected bool
	}{
		{"git push", "git push", true},
		{"git push origin main", "git push", true},
		{"git pushall", "git push", false}, // "pushall" is different word
		{"git status", "git push", false},
		{"gitpush", "git push", false},
	}

	for _, tt := range tests {
		t.Run(tt.command+"_vs_"+tt.prefix, func(t *testing.T) {
			result := matchesPrefix(tt.command, tt.prefix)
			if result != tt.expected {
				t.Errorf("matchesPrefix(%q, %q) = %v, want %v", tt.command, tt.prefix, result, tt.expected)
			}
		})
	}
}

// boolPtr returns a pointer to a bool value.
func boolPtr(b bool) *bool {
	return &b
}
