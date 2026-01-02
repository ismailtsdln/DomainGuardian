# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o domainguardian ./cmd/domainguardian

# Run stage
FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/domainguardian .
COPY --from=builder /app/internal/fingerprints/data/fingerprints.yaml ./internal/fingerprints/data/fingerprints.yaml

ENTRYPOINT ["./domainguardian"]
CMD ["--help"]
