#!/usr/bin/env bash
set -e

VERSION=${VERSION:-"0.1.0"}
BINARY_NAME="clawsanitizer"

mkdir -p dist

echo "Building for linux/amd64..."
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=${VERSION}" -o dist/clawsanitizer-linux-amd64 .

echo "Building for darwin/amd64..."
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=${VERSION}" -o dist/clawsanitizer-darwin-amd64 .

echo "Building for darwin/arm64..."
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=${VERSION}" -o dist/clawsanitizer-darwin-arm64 .

echo "Building for windows/amd64..."
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=${VERSION}" -o dist/clawsanitizer-windows-amd64.exe .

echo "Done! Binaries in dist/"
