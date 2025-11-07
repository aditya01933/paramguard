.PHONY: build test test-unit test-e2e clean install lint

# Build the binary
build:
	go build -o paramguard

# Run all tests
test:
	go test ./... -v

# Run only unit tests (fast)
test-unit:
	go test ./scanner -v

# Run only e2e tests
test-e2e:
	go test -v -run TestE2E

# Run tests with coverage
test-coverage:
	go test ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Clean build artifacts
clean:
	rm -f paramguard paramguard-test coverage.out coverage.html

# Install dependencies
install:
	go mod download
	go mod tidy

# Run linter
lint:
	go fmt ./...
	go vet ./...

# Run quick test (unit tests only, no e2e)
test-quick:
	go test ./scanner -short

# Build for multiple platforms
build-all:
	GOOS=linux GOARCH=amd64 go build -o dist/paramguard-linux-amd64
	GOOS=darwin GOARCH=amd64 go build -o dist/paramguard-darwin-amd64
	GOOS=darwin GOARCH=arm64 go build -o dist/paramguard-darwin-arm64
	GOOS=windows GOARCH=amd64 go build -o dist/paramguard-windows-amd64.exe

# Demo - scan the test config
demo: build
	./paramguard scan test-config.json

# Help
help:
	@echo "ParamGuard - Makefile commands:"
	@echo "  make build         - Build the binary"
	@echo "  make test          - Run all tests"
	@echo "  make test-unit     - Run unit tests only"
	@echo "  make test-e2e      - Run e2e tests only"
	@echo "  make test-quick    - Run fast unit tests"
	@echo "  make test-coverage - Run tests with coverage report"
	@echo "  make clean         - Remove build artifacts"
	@echo "  make install       - Install dependencies"
	@echo "  make lint          - Run linters"
	@echo "  make build-all     - Build for all platforms"
	@echo "  make demo          - Run demo scan"
