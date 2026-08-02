# Build the auth binary
FROM golang:1.26-alpine as builder

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY main.go main.go
COPY Makefile Makefile
COPY internal/ internal/
COPY api/ api/
COPY pkg/ pkg/

RUN apk add --no-cache make

RUN apkArch="$(apk --print-arch)"; \
      case "$apkArch" in \
        aarch64) export GOARCH='arm64' ;; \
        *) export GOARCH='amd64' ;; \
      esac; \
    export CGO_ENABLED=0; \
    export GOOS=linux; \
    make build-bin

###########
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/bin/authd .
USER 65532:65532

EXPOSE 8080/tcp

ENTRYPOINT ["/authd"]
