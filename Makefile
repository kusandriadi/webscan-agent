.PHONY: build run clean docker test

BINARY=red-team-agent
GO=/home/kusa/go-sdk/bin/go

build:
	$(GO) build -ldflags="-s -w" -o $(BINARY) ./cmd/agent/

run: build
	./$(BINARY) --config config.json --data data

dev:
	$(GO) run ./cmd/agent/ --config config.json --data data

clean:
	rm -f $(BINARY)

test:
	$(GO) test ./...

docker:
	docker build -t red-team-agent:latest .

docker-run:
	docker-compose up -d

docker-stop:
	docker-compose down

# Cross compilation
build-linux:
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags="-s -w" -o $(BINARY)-linux-amd64 ./cmd/agent/

build-mac-intel:
	GOOS=darwin GOARCH=amd64 $(GO) build -ldflags="-s -w" -o $(BINARY)-darwin-amd64 ./cmd/agent/

build-mac-arm:
	GOOS=darwin GOARCH=arm64 $(GO) build -ldflags="-s -w" -o $(BINARY)-darwin-arm64 ./cmd/agent/

build-windows:
	GOOS=windows GOARCH=amd64 $(GO) build -ldflags="-s -w" -o $(BINARY)-windows-amd64.exe ./cmd/agent/

build-all: build-linux build-mac-intel build-mac-arm build-windows
	@echo "All platforms built:"
	@ls -lh $(BINARY)-*

# Install dependencies
deps:
	$(GO) mod tidy
	$(GO) mod download
