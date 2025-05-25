# Stage 1: Build the Go binary using the latest Go version
FROM golang:latest AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -tags=lambda.norpc \
    -trimpath \
    -ldflags="-s -w -extldflags '-static' \
    -X main.buildVersion={{.Version}} \
    -X main.buildCommit={{.ShortCommit}} \
    -X main.buildDate={{.Date}}" \
    -o bootstrap ./main.go

# Stage 2: Create minimal Lambda-compatible image
FROM public.ecr.aws/lambda/provided:al2
COPY --from=builder /app/bootstrap /var/task/bootstrap
CMD ["/var/task/bootstrap"]
