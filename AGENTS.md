# Agent Notes

NO NEED to read `README.md`. DO NOT read inside `doc/prompts`.

## Development

Building:

```shell
goreleaser build --snapshot --clean --single-target
```

Run with:

```shell
./dist/tlsident_{{ .Target }}/tlsident -outdir ./results
```

Verification after code change:

```shell
# Format
go fmt ./...
# Lint
golangci-lint run
# Full build
goreleaser release --snapshot --clean
```

## Code Style

- DO NOT write unit tests
- GitHub workflow should use artifacts from the build workflow
