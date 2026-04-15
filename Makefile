.PHONY: build test lint clean

build:
	go build -o bin/fastscan ./cmd/scanner

test:
	go test ./... -race

lint:
	golangci-lint run

clean:
	rm -rf bin/
