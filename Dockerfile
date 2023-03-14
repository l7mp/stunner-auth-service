FROM golang:1.18-alpine
WORKDIR /go/src

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . .

RUN go build .

EXPOSE 8080/tcp
CMD [ "sleep", "999999999" ]
