binary := "ggrok"
pkg := "./cmd/ggrok"
dist := "dist"

export CGO_ENABLED := "0"

# list available recipes
default:
    @just --list

# build a static ggrok binary for the host platform
build:
    go build -trimpath -o {{binary}} {{pkg}}

# run ggrok with the given args
run *args:
    go run {{pkg}} {{args}}

# cross-compile static binaries for common platforms into dist/
build-all:
    mkdir -p {{dist}}
    GOOS=linux   GOARCH=amd64 go build -trimpath -o {{dist}}/{{binary}}-linux-amd64   {{pkg}}
    GOOS=linux   GOARCH=arm64 go build -trimpath -o {{dist}}/{{binary}}-linux-arm64   {{pkg}}
    GOOS=darwin  GOARCH=amd64 go build -trimpath -o {{dist}}/{{binary}}-darwin-amd64  {{pkg}}
    GOOS=darwin  GOARCH=arm64 go build -trimpath -o {{dist}}/{{binary}}-darwin-arm64  {{pkg}}
    GOOS=windows GOARCH=amd64 go build -trimpath -o {{dist}}/{{binary}}-windows-amd64.exe {{pkg}}
    GOOS=windows GOARCH=arm64 go build -trimpath -o {{dist}}/{{binary}}-windows-arm64.exe {{pkg}}

# build the scratch-based docker image
docker-build tag="ggrok:latest":
    docker build -t {{tag}} .

# format code with gofumpt (falls back to gofmt) and tidy imports
fmt:
    gofumpt -l -w .
    go vet ./...

# check formatting without writing changes; fails if anything is unformatted
fmt-check:
    test -z "$(gofumpt -l .)"

# lint with golangci-lint
lint:
    golangci-lint run ./...

# lint and auto-fix what can be fixed
lint-fix:
    golangci-lint run --fix ./...

# scan dependencies and stdlib for known vulnerabilities
vuln:
    go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# verify go.sum integrity and that go.mod is tidy
mod-check:
    go mod verify
    go mod tidy -diff

# run tests
test:
    go test ./...

# run tests with race detector and coverage
test-race:
    go test -race -cover ./...

# tidy go.mod/go.sum
tidy:
    go mod tidy

# run fmt-check, lint, test, module and vulnerability checks - use before committing
verify: fmt-check lint test mod-check vuln

# remove build artifacts
clean:
    rm -f {{binary}}
    rm -rf {{dist}}
