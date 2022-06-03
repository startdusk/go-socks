.PHONY: run fmt vet

fmt:
	@go fmt ./...

vet: fmt
	@go vet ./...

test: vet
	@go test ./...

fuzz: vet
	@go test -fuzz=FuzzNewClientRequestMsg -fuzztime 30s
	@go test -fuzz=FuzzNewClientAuthMsg -fuzztime 30s
	@go test -fuzz=FuzzNewServerAuthMsg -fuzztime 30s
	@go test -fuzz=FuzzWriteReqSuccessMsg -fuzztime 30s
	@go test -fuzz=FuzzNewClientPasswordMsg -fuzztime 30s
	@go test -fuzz=FuzzAuth -fuzztime 30s
	@go test -fuzz=FuzzRequest -fuzztime 30s

run: test
	@go run ./cmd/socks/main.go
