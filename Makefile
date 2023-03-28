.PHONY: generate test clean

generate:
	oapi-codegen -package client -generate "client"       -o internal/client/client.go api/stunner.yaml
	oapi-codegen -package server -generate "gorilla,spec" -o pkg/server/server.go api/stunner.yaml
	oapi-codegen -package types -generate "types"         -o pkg/types/types.go api/stunner.yaml

test:
	go test ./... -v

# clean up generated files
clean:
	echo 'Use "make generate` to autogenerate server code' > pkg/server/server.go
	echo 'Use "make generate` to autogenerate client code' > pkg/client/client.go
	echo 'Use "make generate` to autogenerate client code' > pkg/types/types.go

