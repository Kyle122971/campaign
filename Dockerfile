FROM golang:1.24-alpine AS builder
# 1. Install git (needed to pull the Ethereum source code)
RUN apk add --no-cache git gcc musl-dev linux-headers

WORKDIR /app

# 2. Copy ONLY the go.mod file
COPY go.mod ./

# 3. CRITICAL: Generate the missing go.sum entries inside the container
RUN go mod tidy

# 4. Copy the rest of your code (main.go, etc.)
COPY . .

# 5. Build the binary as a static, pure-Go executable
RUN CGO_ENABLED=0 GOOS=linux go build -o engine main.go

# 6. Final lightweight production image
FROM alpine:latest
RUN apk add --no-cache ca-certificates
WORKDIR /root/
COPY --from=builder /app/engine .
EXPOSE 4021
CMD ["./engine"]
