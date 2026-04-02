# Agent Notes

NO NEED to read README.md.

## Development

Building:

```shell
goreleaser build --snapshot --clean --single-target
```

Find the artifacts under `dist/tlsident_{{ .Target }}`.

Verification after code change:

```shell
# Format
go fmt ./...
# Lint
golangci-lint run
# Full build
goreleaser release --snapshot --clean
```
