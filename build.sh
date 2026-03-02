#!/usr/bin/env bash
set -e
VERSION="${VERSION:-dev}"
OUTPUT_DIR="dist"
BINARY="clawsanitizer"

mkdir -p "$OUTPUT_DIR"

build_target() {
  local GOOS=$1
  local GOARCH=$2
  local output_suffix=$3
  local output="$OUTPUT_DIR/$BINARY-$output_suffix"
  echo "Building $output..."
  GOOS="$GOOS" GOARCH="$GOARCH" go build -o "$output" -ldflags="-s -w -X main.version=$VERSION" .
}

build_target "linux" "amd64" "linux-amd64"
build_target "darwin" "amd64" "darwin-amd64"
build_target "darwin" "arm64" "darwin-arm64"
build_target "windows" "amd64" "windows-amd64.exe"

echo "Done. Binaries in $OUTPUT_DIR/"
ls -lh "$OUTPUT_DIR/"
