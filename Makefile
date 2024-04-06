build:
	@go build -o bin/go_api

run: build
	@./bin/go_api

test:
	@go test -v ./...