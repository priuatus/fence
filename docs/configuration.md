# Configuration

Fence reads settings from `~/.fence.json` by default (or pass `--settings ./fence.json`). Config files support JSONC.

Example config:

```json
{
  "network": {
    "allowedDomains": ["github.com", "*.npmjs.org", "registry.yarnpkg.com"],
    "deniedDomains": ["evil.com"]
  },
  "filesystem": {
    "denyRead": ["/etc/passwd"],
    "allowWrite": [".", "/tmp"],
    "denyWrite": [".git/hooks"]
  },
  "command": {
    "deny": ["git push", "npm publish"]
  }
}
```

## Network Configuration

| Field | Description |
|-------|-------------|
| `allowedDomains` | List of allowed domains. Supports wildcards like `*.example.com` |
| `deniedDomains` | List of denied domains (checked before allowed) |
| `allowUnixSockets` | List of allowed Unix socket paths (macOS) |
| `allowAllUnixSockets` | Allow all Unix sockets |
| `allowLocalBinding` | Allow binding to local ports |
| `allowLocalOutbound` | Allow outbound connections to localhost, e.g., local DBs (defaults to `allowLocalBinding` if not set) |
| `httpProxyPort` | Fixed port for HTTP proxy (default: random available port) |
| `socksProxyPort` | Fixed port for SOCKS5 proxy (default: random available port) |

## Filesystem Configuration

| Field | Description |
|-------|-------------|
| `denyRead` | Paths to deny reading (deny-only pattern) |
| `allowWrite` | Paths to allow writing |
| `denyWrite` | Paths to deny writing (takes precedence) |
| `allowGitConfig` | Allow writes to `.git/config` files |

## Command Configuration

Block specific commands from being executed, even within command chains.

| Field | Description |
|-------|-------------|
| `deny` | List of command prefixes to block (e.g., `["git push", "rm -rf"]`) |
| `allow` | List of command prefixes to allow, overriding `deny` |
| `useDefaults` | Enable default deny list of dangerous system commands (default: `true`) |

Example:

```json
{
  "command": {
    "deny": ["git push", "npm publish"],
    "allow": ["git push origin docs"]
  }
}
```

### Default Denied Commands

When `useDefaults` is `true` (the default), fence blocks these dangerous commands:

- System control: `shutdown`, `reboot`, `halt`, `poweroff`, `init 0/6`
- Kernel manipulation: `insmod`, `rmmod`, `modprobe`, `kexec`
- Disk operations: `mkfs*`, `fdisk`, `parted`, `dd if=`
- Container escape: `docker run -v /:/`, `docker run --privileged`
- Namespace escape: `chroot`, `unshare`, `nsenter`

To disable defaults: `"useDefaults": false`

### Command Detection

Fence detects blocked commands in:

- Direct commands: `git push origin main`
- Command chains: `ls && git push` or `ls; git push`
- Pipelines: `echo test | git push`
- Shell invocations: `bash -c "git push"` or `sh -lc "ls && git push"`

## Other Options

| Field | Description |
|-------|-------------|
| `allowPty` | Allow pseudo-terminal (PTY) allocation in the sandbox (for MacOS) |

## See Also

- Config templates: [`docs/templates/`](docs/templates/)
- Workflow guides: [`docs/recipes/`](docs/recipes/)
