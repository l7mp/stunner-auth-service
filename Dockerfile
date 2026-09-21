# Build the auth binary
# The builder runs on the build platform and cross-compiles for the target: Go needs no
# emulation for that, an emulated compiler is an order of magnitude slower.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS builder
ARG TARGETOS TARGETARCH

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

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH make build-bin

###########
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/bin/authd .
USER 65532:65532

EXPOSE 8080/tcp

ENTRYPOINT ["/authd"]
