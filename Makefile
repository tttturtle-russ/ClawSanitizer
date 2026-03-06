PROJECT     := clawsan
MODULE      := github.com/tttturtle-russ/clawsan
BUILD_FLAGS := -ldflags="-X $(MODULE)/cmd.Version=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)"

.PHONY: all build install test lint clean

all: build

build:
	go build $(BUILD_FLAGS) -o $(PROJECT) .

install:
	go install $(BUILD_FLAGS) .

test:
	go test -race ./...

lint:
	go vet ./...
	@which staticcheck >/dev/null 2>&1 && staticcheck ./... || echo "staticcheck not installed — run: go install honnef.co/go/tools/cmd/staticcheck@latest"

clean:
	rm -f $(PROJECT) coverage.out

coverage:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out
