###########
# BUILD
FROM golang:1.19-alpine as builder

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY *.go ./
COPY internal/ internal/
COPY api/ api/
COPY pkg/ pkg/

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o stunner-auth-server .

###########
# STUNNER-AUTH-SERVICE
FROM gcr.io/distroless/static

WORKDIR /
COPY --from=builder /app/stunner-auth-server .

EXPOSE 8080/tcp

CMD ["/stunner-auth-server"]
