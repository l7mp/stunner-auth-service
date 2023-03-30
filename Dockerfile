###########
# BUILD
FROM golang:1.19-alpine as builder

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY main.go ./
COPY internal/ internal/
COPY api/ api/
COPY pkg/ pkg/

RUN apkArch="$(apk --print-arch)"; \
      case "$apkArch" in \
        aarch64) export GOARCH='arm64' ;; \
        *) export GOARCH='amd64' ;; \
      esac; \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o stunner-auth-server .

###########
# STUNNER-AUTH-SERVICE
FROM gcr.io/distroless/static

WORKDIR /
COPY --from=builder /app/stunner-auth-server .

EXPOSE 8080/tcp

CMD ["/stunner-auth-server"]
