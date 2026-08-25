# Build a static ggrok, then ship it on scratch - the final image is the
# binary and nothing else. ggrok verifies peers against a private CA you pass
# in by file, never the system trust store, so there are no root certificates
# to install here.

FROM golang:1.27-alpine AS build

WORKDIR /src

# Module files first so the dependency layer survives source-only edits.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Matches the justfile: no cgo, trimmed paths. -s -w drops the symbol and DWARF
# tables, which is a large fraction of the image.
#
# The mkdir rides along here because share and listen resolve their default cert
# paths under $HOME, and scratch has no shell to create that directory with - so
# it gets staged in this layer and copied over.
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w" -o /ggrok ./cmd/ggrok \
    && mkdir -p /home/nonroot/.ggrok

FROM scratch

COPY --from=build /ggrok /ggrok
COPY --from=build --chown=65532:65532 /home/nonroot /home/nonroot

# Numeric on purpose: scratch has no /etc/passwd for a name to resolve against.
USER 65532:65532
ENV HOME=/home/nonroot

# relay's listener. share and listen expose nothing.
EXPOSE 4443

ENTRYPOINT ["/ggrok"]
