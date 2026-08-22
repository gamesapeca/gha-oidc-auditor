# Build stage
FROM golang:alpine AS builder


WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/bin/gha-oidc ./cmd/gha-oidc

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

RUN adduser -D -u 10001 appuser
USER appuser

COPY --from=builder /app/bin/gha-oidc /usr/local/bin/gha-oidc

ENTRYPOINT ["/usr/local/bin/gha-oidc"]
CMD ["--help"]
