# tlsident

![Project Status - Feature Complete](https://img.shields.io/badge/Project_Status-Feature_Complete-2ea44f)
![100% AI Code](https://img.shields.io/badge/AI_Code-100%25-blue)

Collects TLS, HTTP2 and HTTP fingerprints of certain AI agents, compatible with [TLS Fingerprint Collector](https://tls.sub2api.org/).

## Run

```bash
go run ./cmd/tlsident -outdir ./results
```

Then point Claude Code at the local endpoint:

```bash
ANTHROPIC_BASE_URL=https://localhost:8443 ANTHROPIC_API_KEY='' ANTHROPIC_AUTH_TOKEN=anything NODE_TLS_REJECT_UNAUTHORIZED=0 claude "test"
```

## Release

```bash
goreleaser release --snapshot --clean
```
