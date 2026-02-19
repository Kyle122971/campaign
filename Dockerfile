FROM golang:1.24-alpine AS builder
# Install build tools
RUN apk add --no-cache gcc musl-dev linux-headers git

WORKDIR /app

# 1. Copy the module file
COPY go.mod ./

# 2. Force download dependencies (ignoring the empty/missing go.sum)
RUN go mod download

# 3. Copy the actual code
COPY . .

# 4. Generate the sum file based on the actual main.go
RUN go mod tidy

# 5. Build with CGO disabled and all dependencies linked
RUN CGO_ENABLED=0 GOOS=linux go build -o engine .

FROM alpine:latest
RUN apk add --no-cache ca-certificates
WORKDIR /root/
COPY --from=builder /app/engine .
EXPOSE 4021
CMD ["./engine"]
