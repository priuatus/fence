# Using Fence with AI Agents

Many popular coding agents already include sandboxing. Fence can still be useful when you want a tool-agnostic policy layer that works the same way across:

- local developer machines
- CI jobs
- custom/internal agents or automation scripts
- different agent products (as defense-in-depth)

## Recommended approach

Treat an agent as "semi-trusted automation":

- Restrict writes to the workspace (and maybe `/tmp`)
- Allowlist only the network destinations you actually need
- Use `-m` (monitor mode) to audit blocked attempts and tighten policy

Fence can also reduce the risk of running agents with fewer interactive permission prompts (e.g. "skip permissions"), as long as your Fence config tightly scopes writes and outbound destinations. It's defense-in-depth, not a substitute for the agent's own safeguards.

## Example: API-only agent

```json
{
  "network": {
    "allowedDomains": ["api.openai.com", "api.anthropic.com"]
  },
  "filesystem": {
    "allowWrite": ["."]
  }
}
```

Run:

```bash
fence --settings ./fence.json <agent-command>
```

## Real-world usage

Currently, we provide the `code.json` template. You can use it by running `fence -t code -- claude`.

However, not all coding agent CLIs work with Fence yet. We're actively investigating these issues.

| Agent | Works? | Notes |
|-------|--------| ----- |
| Claude Code | ✅ | Fully working with `code` template |
| Codex | ❌ | Missing unidentified sandbox permission for interactive mode |
| OpenCode | ❌ | Ignores proxy env vars; makes direct network connections |

## Protecting your environment

Fence includes additional "dangerous file protection (writes blocked regardless of config) to reduce persistence and environment-tampering vectors like:

- `.git/hooks/*`
- shell startup files (`.zshrc`, `.bashrc`, etc.)
- some editor/tool config directories

See [`ARCHITECTURE.md`](/ARCHITECTURE.md) for the full list and rationale.
