# Config Templates

Fence includes built-in config templates for common use cases. Templates are embedded in the binary, so you can use them directly without copying files.

## Using templates

Use the `-t` / `--template` flag to apply a template:

```bash
# Use a built-in template
fence -t npm-install npm install

# Wraps Claude Code
fence -t code -- claude

# List available templates
fence --list-templates
```

You can also copy and customize templates from [`internal/templates/`](/internal/templates/).

## Available Templates

| Template | Description |
|----------|-------------|
| `code` | Production-ready config for AI coding agents (Claude Code, Codex, Copilot, etc.) |
| `code-relaxed` | Like `code` but allows direct network for apps that ignore HTTP_PROXY |
| `git-readonly` | Blocks destructive commands like `git push`, `rm -rf`, etc. |
| `local-dev-server` | Allow binding and localhost outbound; allow writes to workspace/tmp |
