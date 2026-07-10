# Stage 1: Build
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod ./
COPY vendor ./vendor
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -o gateway-proxy .

# Stage 2: Runtime
FROM alpine:3.18
WORKDIR /app
COPY --from=builder /app/gateway-proxy .
COPY dashboard ./dashboard
COPY policies ./policies
EXPOSE 1163
ENTRYPOINT ["./gateway-proxy"]
