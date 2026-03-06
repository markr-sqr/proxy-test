# Future Development

Potential features and enhancements for the MITM web proxy and log viewer.

---

## Table of Contents

- [Proxy Engine](#proxy-engine)
- [Security & Analysis](#security--analysis)
- [UI Enhancements](#ui-enhancements)
- [Developer Workflow](#developer-workflow)

---

## Proxy Engine

- **Request/response modification** — rewrite headers, inject scripts, or modify bodies on the fly (useful for testing)
- **Throttling / latency injection** — simulate slow networks by adding configurable delays per host or pattern
- **Allowlist / blocklist** — block or allow traffic by domain, IP, or URL pattern
- **WebSocket interception** — log and inspect WebSocket frames (currently only HTTP/HTTPS)
- **HTTP/2 support** — proxy and log HTTP/2 traffic
- **Replay** — re-send a captured request from the log viewer
- **Upstream proxy chaining** — forward traffic through another proxy (corporate environments)

## Security & Analysis

- **Cookie analysis** — flag missing `Secure`, `HttpOnly`, `SameSite` attributes
- **CORS misconfiguration detection** — flag overly permissive `Access-Control-Allow-Origin`
- **TLS version/cipher logging** — record negotiated TLS version and cipher suite per MITM connection
- **Content-type mismatch detection** — flag when response body doesn't match declared Content-Type
- **Dependency/library detection** — identify known JS libraries and flag versions with known CVEs
- **Request diff** — compare two captured requests side-by-side

## UI Enhancements

- **Live streaming** — WebSocket-based real-time log tail instead of polling/manual refresh
- **Request timeline / waterfall** — visualise request timing like browser DevTools network tab
- **Export** — download filtered logs as HAR, CSV, or JSON
- **Search across bodies** — full-text search through request/response bodies, not just URLs
- **Tagging / bookmarking** — mark entries for later review
- **Dark mode** — theme toggle (the current UI is light only)
- **Diff view for repeated requests** — highlight what changed between repeated calls to the same endpoint
- **Map view** — GeoIP visualisation of upstream targets
- **Certificate viewer** — inspect MITM-generated certs from the UI

## Developer Workflow

- **Mock/stub responses** — define canned responses for specific URL patterns (local API mocking)
- **Breakpoints** — pause a request mid-flight, let the user edit it in the UI, then forward
- **HAR import** — load and replay a HAR file through the proxy
- **API contract validation** — compare proxied traffic against an OpenAPI spec and flag violations
- **Shareable sessions** — export/import a full proxy session for team collaboration
