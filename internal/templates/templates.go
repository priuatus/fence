// Package templates provides embedded configuration templates for fence.
package templates

import (
	"embed"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Use-Tusk/fence/internal/config"
	"github.com/tidwall/jsonc"
)

//go:embed *.json
var templatesFS embed.FS

// Template represents a named configuration template.
type Template struct {
	Name        string
	Description string
}

// AvailableTemplates lists all embedded templates with descriptions.
var templateDescriptions = map[string]string{
	"default-deny":      "No network allowlist; no write access (most restrictive)",
	"disable-telemetry": "Block analytics/error reporting (Sentry, Posthog, Statsig, etc.)",
	"workspace-write":   "Allow writes in the current directory",
	"npm-install":       "Allow npm registry; allow writes to workspace/node_modules/tmp",
	"pip-install":       "Allow PyPI; allow writes to workspace/tmp",
	"local-dev-server":  "Allow binding and localhost outbound; allow writes to workspace/tmp",
	"git-readonly":      "Blocks destructive commands like git push, rm -rf, etc.",
	"code":              "Production-ready config for AI coding agents (Claude Code, Codex, Copilot, etc.)",
}

// List returns all available template names sorted alphabetically.
func List() []Template {
	entries, err := templatesFS.ReadDir(".")
	if err != nil {
		return nil
	}

	var templates []Template
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".json")
		desc := templateDescriptions[name]
		if desc == "" {
			desc = "No description available"
		}
		templates = append(templates, Template{Name: name, Description: desc})
	}

	sort.Slice(templates, func(i, j int) bool {
		return templates[i].Name < templates[j].Name
	})

	return templates
}

// Load loads a template by name and returns the parsed config.
func Load(name string) (*config.Config, error) {
	// Normalize name (remove .json if present)
	name = strings.TrimSuffix(name, ".json")
	filename := name + ".json"

	data, err := templatesFS.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("template %q not found", name)
	}

	var cfg config.Config
	if err := json.Unmarshal(jsonc.ToJSON(data), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse template %q: %w", name, err)
	}

	return &cfg, nil
}

// Exists checks if a template with the given name exists.
func Exists(name string) bool {
	name = strings.TrimSuffix(name, ".json")
	filename := name + ".json"

	_, err := templatesFS.ReadFile(filename)
	return err == nil
}

// GetPath returns the embedded path for a template (for display purposes).
func GetPath(name string) string {
	name = strings.TrimSuffix(name, ".json")
	return filepath.Join("internal/templates", name+".json")
}
