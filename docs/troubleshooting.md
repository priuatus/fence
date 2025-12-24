# Troubleshooting

## "curl: (56) CONNECT tunnel failed, response 403"

This usually means:

- the process tried to reach a domain that is **not allowed**, and
- the request went through fence's HTTP proxy, which returned `403`.

Fix:

- Run with monitor mode to see what was blocked:
  - `fence -m <command>`
- Add the required destination(s) to `network.allowedDomains`.

## "It works outside fence but not inside"

Start with:

- `fence -m <command>` to see what's being denied
- `fence -d <command>` to see full proxy and sandbox detail

Common causes:

- Missing `allowedDomains`
- A tool attempting direct sockets that don't respect proxy environment variables
- Localhost outbound blocked (DB/cache on `127.0.0.1`)
- Writes blocked (you didn't include a directory in `filesystem.allowWrite`)

## Node.js HTTP(S) doesn't use proxy env vars by default

Node's built-in `http`/`https` modules ignore `HTTP_PROXY`/`HTTPS_PROXY`.

If your Node code makes outbound HTTP(S) requests, use a proxy-aware client.
For example with `undici`:

```javascript
import { ProxyAgent, fetch } from "undici";

const proxyUrl = process.env.HTTPS_PROXY;
const response = await fetch(url, {
  dispatcher: new ProxyAgent(proxyUrl),
});
```

Fence's OS-level sandbox should still block direct connections; the above makes your requests go through the filtering proxy so allowlisting works as intended.

## Local services (Redis/Postgres/etc.) fail inside the sandbox

If your process needs to connect to `localhost` services, set:

```json
{
  "network": { "allowLocalOutbound": true }
}
```

If you're running a server inside the sandbox that must accept connections:

- set `network.allowLocalBinding: true` (to bind)
- use `-p <port>` (to expose inbound port(s))

## "Permission denied" on file writes

Writes are denied by default.

- Add the minimum required writable directories to `filesystem.allowWrite`.
- Protect sensitive targets with `filesystem.denyWrite` (and note fence protects some targets regardless).

Example:

```json
{
  "filesystem": {
    "allowWrite": [".", "/tmp"],
    "denyWrite": [".env", "*.key"]
  }
}
```
