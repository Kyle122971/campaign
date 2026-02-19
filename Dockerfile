FROM golang:1.24-alpine AS builder
RUN apk add --no-cache gcc musl-dev linux-headers git
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o engine main.go

FROM alpine:latest
RUN apk add --no-cache ca-certificates
WORKDIR /root/
COPY --from=builder /app/engine .
EXPOSE 4021
CMD ["./engine"]
