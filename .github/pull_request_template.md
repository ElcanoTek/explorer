## What

<!-- One or two sentences: what changes and why. -->

## Checklist

- [ ] `gofmt -l .` is empty, `go vet ./...` and `golangci-lint run` pass
- [ ] `go test -race ./...` passes, with no AWS account or network needed
- [ ] Fixtures stay synthetic (`.example` addresses; no real mail)
- [ ] Docs updated where behaviour changed
- [ ] New source files carry the SPDX header
- [ ] No secrets, real customer data, or internal hostnames in the diff

## Screenshots

<!-- For UI changes. -->
