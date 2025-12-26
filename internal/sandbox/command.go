// Package sandbox provides sandboxing functionality for macOS and Linux.
package sandbox

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Use-Tusk/fence/internal/config"
)

// CommandBlockedError is returned when a command is blocked by policy.
type CommandBlockedError struct {
	Command       string
	BlockedPrefix string
	IsDefault     bool
}

func (e *CommandBlockedError) Error() string {
	if e.IsDefault {
		return fmt.Sprintf("command blocked by default policy: %q matches %q", e.Command, e.BlockedPrefix)
	}
	return fmt.Sprintf("command blocked by policy: %q matches %q", e.Command, e.BlockedPrefix)
}

// CheckCommand checks if a command is allowed by the configuration.
// It parses shell command strings and checks each sub-command in pipelines/chains.
// Returns nil if allowed, or CommandBlockedError if blocked.
func CheckCommand(command string, cfg *config.Config) error {
	if cfg == nil {
		cfg = config.Default()
	}

	subCommands := parseShellCommand(command)

	for _, subCmd := range subCommands {
		if err := checkSingleCommand(subCmd, cfg); err != nil {
			return err
		}
	}

	return nil
}

// checkSingleCommand checks a single command (not a chain) against the policy.
func checkSingleCommand(command string, cfg *config.Config) error {
	command = strings.TrimSpace(command)
	if command == "" {
		return nil
	}

	// Normalize the command for matching
	normalized := normalizeCommand(command)

	// Check if explicitly allowed (takes precedence over deny)
	for _, allow := range cfg.Command.Allow {
		if matchesPrefix(normalized, allow) {
			return nil
		}
	}

	// Check user-defined deny list
	for _, deny := range cfg.Command.Deny {
		if matchesPrefix(normalized, deny) {
			return &CommandBlockedError{
				Command:       command,
				BlockedPrefix: deny,
				IsDefault:     false,
			}
		}
	}

	// Check default deny list (if enabled)
	if cfg.Command.UseDefaultDeniedCommands() {
		for _, deny := range config.DefaultDeniedCommands {
			if matchesPrefix(normalized, deny) {
				return &CommandBlockedError{
					Command:       command,
					BlockedPrefix: deny,
					IsDefault:     true,
				}
			}
		}
	}

	return nil
}

// parseShellCommand splits a shell command string into individual commands.
// Handles: pipes (|), logical operators (&&, ||), semicolons (;), and subshells.
func parseShellCommand(command string) []string {
	var commands []string
	var current strings.Builder
	var inSingleQuote, inDoubleQuote bool
	var parenDepth int

	runes := []rune(command)
	for i := 0; i < len(runes); i++ {
		c := runes[i]

		// Handle quotes
		if c == '\'' && !inDoubleQuote {
			inSingleQuote = !inSingleQuote
			current.WriteRune(c)
			continue
		}
		if c == '"' && !inSingleQuote {
			inDoubleQuote = !inDoubleQuote
			current.WriteRune(c)
			continue
		}

		// Skip splitting inside quotes
		if inSingleQuote || inDoubleQuote {
			current.WriteRune(c)
			continue
		}

		// Handle parentheses (subshells)
		if c == '(' {
			parenDepth++
			current.WriteRune(c)
			continue
		}
		if c == ')' {
			parenDepth--
			current.WriteRune(c)
			continue
		}

		// Skip splitting inside subshells
		if parenDepth > 0 {
			current.WriteRune(c)
			continue
		}

		// Handle shell operators
		switch c {
		case '|':
			// Check for || (or just |)
			if i+1 < len(runes) && runes[i+1] == '|' {
				// ||
				if s := strings.TrimSpace(current.String()); s != "" {
					commands = append(commands, s)
				}
				current.Reset()
				i++ // Skip second |
			} else {
				// Just a pipe
				if s := strings.TrimSpace(current.String()); s != "" {
					commands = append(commands, s)
				}
				current.Reset()
			}
		case '&':
			// Check for &&
			if i+1 < len(runes) && runes[i+1] == '&' {
				if s := strings.TrimSpace(current.String()); s != "" {
					commands = append(commands, s)
				}
				current.Reset()
				i++ // Skip second &
			} else {
				// Background operator - keep in current command
				current.WriteRune(c)
			}
		case ';':
			if s := strings.TrimSpace(current.String()); s != "" {
				commands = append(commands, s)
			}
			current.Reset()
		default:
			current.WriteRune(c)
		}
	}

	// Add remaining command
	if s := strings.TrimSpace(current.String()); s != "" {
		commands = append(commands, s)
	}

	// Handle nested shell invocations like "bash -c 'git push'"
	var expanded []string
	for _, cmd := range commands {
		expanded = append(expanded, expandShellInvocation(cmd)...)
	}

	return expanded
}

// expandShellInvocation detects patterns like "bash -c 'cmd'" or "sh -c 'cmd'"
// and extracts the inner command for checking.
func expandShellInvocation(command string) []string {
	command = strings.TrimSpace(command)
	if command == "" {
		return nil
	}

	tokens := tokenizeCommand(command)
	if len(tokens) < 3 {
		return []string{command}
	}

	// Check for shell -c pattern
	shell := filepath.Base(tokens[0])
	isShell := shell == "sh" || shell == "bash" || shell == "zsh" ||
		shell == "ksh" || shell == "dash" || shell == "fish"

	if !isShell {
		return []string{command}
	}

	// Look for -c flag (could be combined with other flags like -lc, -ic, etc.)
	for i := 1; i < len(tokens)-1; i++ {
		flag := tokens[i]
		// Check for -c, -lc, -ic, -ilc, etc. (any flag containing 'c')
		if strings.HasPrefix(flag, "-") && strings.Contains(flag, "c") {
			// Next token is the command string
			innerCmd := tokens[i+1]
			// Recursively parse the inner command
			innerCommands := parseShellCommand(innerCmd)
			// Return both the outer command and inner commands
			// (we check both for safety)
			result := []string{command}
			result = append(result, innerCommands...)
			return result
		}
	}

	return []string{command}
}

// tokenizeCommand splits a command string into tokens, respecting quotes.
func tokenizeCommand(command string) []string {
	var tokens []string
	var current strings.Builder
	var inSingleQuote, inDoubleQuote bool

	for _, c := range command {
		switch {
		case c == '\'' && !inDoubleQuote:
			inSingleQuote = !inSingleQuote
		case c == '"' && !inSingleQuote:
			inDoubleQuote = !inDoubleQuote
		case (c == ' ' || c == '\t') && !inSingleQuote && !inDoubleQuote:
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(c)
		}
	}

	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	return tokens
}

// normalizeCommand normalizes a command for matching.
// - Strips leading path from the command (e.g., /usr/bin/git -> git)
// - Collapses multiple spaces
func normalizeCommand(command string) string {
	command = strings.TrimSpace(command)
	if command == "" {
		return ""
	}

	tokens := tokenizeCommand(command)
	if len(tokens) == 0 {
		return command
	}

	tokens[0] = filepath.Base(tokens[0])

	return strings.Join(tokens, " ")
}

// matchesPrefix checks if a command matches a blocked prefix.
// The prefix matches if the command starts with the prefix followed by
// end of string, a space, or other argument.
func matchesPrefix(command, prefix string) bool {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return false
	}

	prefix = normalizeCommand(prefix)

	if command == prefix {
		return true
	}

	if strings.HasPrefix(command, prefix+" ") {
		return true
	}

	return false
}
