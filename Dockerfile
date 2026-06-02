# Build stage
FROM golang:1.22-bookworm AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o red-team-agent ./cmd/agent/

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium \
    ca-certificates \
    fonts-liberation \
    libnss3 \
    libxss1 \
    libasound2 \
    libatk-bridge2.0-0 \
    libgtk-3-0 \
    libgbm1 \
    && rm -rf /var/lib/apt/lists/*

ENV CHROME_BIN=/usr/bin/chromium
ENV CHROME_PATH=/usr/bin/chromium

RUN groupadd -r agent && useradd -r -g agent -s /sbin/nologin agent

WORKDIR /app

COPY --from=builder /build/red-team-agent .
COPY web/ ./web/

RUN mkdir -p /app/reports /app/data /app/config && \
    chown -R agent:agent /app

USER agent

EXPOSE 5555

VOLUME ["/app/config", "/app/data", "/app/reports"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD curl -f http://localhost:5555/api/config || exit 1

ENTRYPOINT ["./red-team-agent"]
CMD ["--config", "/app/config/config.json", "--data", "/app/data"]
