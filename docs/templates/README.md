# Config Templates

This directory contains Fence config templates. They are small and meant to be copied and customized.

## Templates

- `default-deny.json`: no network allowlist; no write access (most restrictive)
- `workspace-write.json`: allow writes in the current directory
- `npm-install.json`: allow npm registry; allow writes to workspace/node_modules/tmp
- `pip-install.json`: allow PyPI; allow writes to workspace/tmp
- `local-dev-server.json`: allow binding and localhost outbound; allow writes to workspace/tmp
- `agent-api-only.json`: allow common LLM API domains; allow writes to workspace
- `git-readonly.json`: blocks destructive commands like `git push`, `rm -rf`, etc.

## Using a template

```bash
fence --settings ./docs/templates/npm-install.json npm install
```
