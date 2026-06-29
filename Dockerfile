# Multi-stage build for bumblebee API server.
# Go 1.25+ required (matches go.mod).

FROM golang:1.25-alpine AS builder

WORKDIR /src

# Cache deps first.
COPY go.mod ./
RUN go mod download

# Copy source and build.
COPY . .
RUN CGO_ENABLED=0 go build \
    -ldflags "-X main.version=$(cat VERSION)-api" \
    -o /bumblebee-api ./cmd/api

# Runtime image — minimal, no shell, no package manager.
FROM alpine:3.20

RUN apk add --no-cache ca-certificates && \
    adduser -D -u 1000 app

COPY --from=builder /bumblebee-api /usr/local/bin/bumblebee-api
COPY threat_intel/ /app/threat_intel/

WORKDIR /app
USER app

ENV ADDR=:8080
ENV CATALOG_DIR=/app/threat_intel
ENV RATE_LIMIT_PER_HOUR=60

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

ENTRYPOINT ["bumblebee-api"]
