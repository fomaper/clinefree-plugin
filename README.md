# clinefree — Cline free-tier provider for CLIProxyAPI

A [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) plugin that turns **Cline free-tier accounts** (`cline-free/*`) into a first-class CPA provider. It runs inside the CPA process — no sidecar container, no extra hop.

## Why this exists

Cline's free tier is usable from a plain HTTP client, but two things get in the way:

1. It is gated behind **product-surface headers**. Without `HTTP-Referer`, `X-Title` and `X-CLIENT-TYPE` the gateway answers `403 ... only available via Cline product surfaces`.
2. Its **native non-streaming** path intermittently returns `{"error":"empty response content","success":false}`.

A sidecar proxy can paper over both. Doing it inside CPA is simpler to run and gives the plugin the credential system, the scheduling and the error vocabulary for free.

## Features

- **Product-surface gate headers** injected on every upstream request.
- **Non-streaming = upstream SSE + local aggregation.** The native non-streaming path is never used, so its empty-content failure cannot occur. `content`, `reasoning` and **`tool_calls`** (id / name / assembled arguments) are all rebuilt from the stream.
- **Real SSE forwarding** for streaming clients, with pre-output frame buffering: a failure before the first content frame is reported as a structured HTTP error instead of a truncated stream.
- **Quota windows per credential.** Cline spells its daily cap out in prose — `Try again in 6h 41m`. That is parsed, the affected credential is parked for exactly that long, and exactly one recovery probe is admitted when the window expires. The other keys keep serving.
- **Honest error mapping.** Upstream failures keep their own status (`401` / `403` / `429` / `404`) and are classified even when Cline delivers the error object inside a `200` body. A permanent `403` is never turned into a retryable `429`.
- **Plugin-hosted key console.** A browser page served by the plugin itself, at `/v0/resource/plugins/clinefree/console`, for listing (masked), adding and removing Cline API keys.
- **YAML config-node support.** The plugin also reads `api_keys` / `models` from the host config node if you prefer editing CPA's `config.yaml`.

## Requirements

- CLIProxyAPI v7.3.12 or newer (tested on v8.0.13), with `plugins.enabled: true`.
- A Linux host — the plugin is a `c-shared` dynamic library.

## Install

```bash
# 1. Build (needs Docker; the build runs the unit tests first)
docker build -f Dockerfile.build -t clinefree .
id=$(docker create clinefree) && docker cp $id:/out/clinefree.so ./clinefree-v0.2.0.so && docker rm $id

# 2. Drop it into CPA's plugin directory, named <id>-v<version>.so
cp clinefree-v0.2.0.so /path/to/cpa/plugins/linux/amd64/

# 3. CPA picks it up by scanning the directory — no config entry required.
```

If you want an explicit config entry, add:

```yaml
plugins:
  configs:
    clinefree:
      enabled: true
```

Reloading a replaced `.so` needs no restart: toggle the plugin off and on through the management API.

## Configure

Open the plugin's own console:

```
http://<cpa-host>:8317/v0/resource/plugins/clinefree/console
```

Enter your CPA management key, then add one Cline API key per line — one key per Cline account. Each account has its own daily quota and its own reset clock, so adding several accounts multiplies the available daily capacity and gives CPA more credentials to rotate over.

Model mappings default to a single entry; add more through the config node's `models` array:

```yaml
models:
  - id: cline-deepseek-v4.1-flash              # the name your clients request
    upstream_id: cline-free/deepseek-v4.1-flash # the upstream model id
```

Then call it like any other CPA model:

```bash
curl http://<cpa-host>:8317/v1/chat/completions \
  -H "Authorization: Bearer <your-cpa-key>" \
  -H "Content-Type: application/json" \
  -d '{"model":"cline-deepseek-v4.1-flash","messages":[{"role":"user","content":"hello"}]}'
```

## Known limitations

- **The OAuth entry cannot be removed.** CPA derives `supports_oauth` from the plugin declaring the `auth_provider` capability (`internal/pluginhost/snapshot.go: SupportsOAuth: authProvider != nil`), and there is no separate flag. `auth_provider` is what lets the plugin publish credentials into CPA's credential store, so it cannot be dropped. Clicking the generated **Start login** button returns `failed to generate authorization url` — that entry is inert. Use the console page instead.
- **Free tier only.** `cline-pass/*` (subscription) models are not the target here; an account without a Cline Pass subscription receives `403 ENTITLEMENT_ERROR` for them.
- **No team-TPM handling.** Cline's free tier hits a *daily cap per account*, which arrives as a real HTTP `429` with a retry hint. The shared team/region tokens-per-minute limit that subscription accounts encounter was never observed on free-tier keys, so that branch is deliberately absent.
- **Reasoning passthrough.** The upstream reasoning channel is forwarded as-is. Cline's free tier frequently reasons in English, so clients that render reasoning will show English text — that is upstream behaviour, not a transformation performed here.

## Development

```bash
docker build -f Dockerfile.build -t clinefree .
```

The build fails if the unit tests fail. Tests cover the retry-hint parser, the error classifier, tool-call aggregation, the YAML config-node reader, the rate gate and the console routes.

## License

MIT. Portions are adapted from [ClinePassBridge](https://github.com/xiao-qiu-qiu/ClinePassBridge) (MIT) — see `LICENSE` for the exact scope of the attribution.
