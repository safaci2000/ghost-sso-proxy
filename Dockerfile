FROM golang:1.26-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o ghost-sso-proxy ./cmd/

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /app/ghost-sso-proxy /ghost-sso-proxy

ENTRYPOINT ["/ghost-sso-proxy"]
