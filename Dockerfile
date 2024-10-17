# Build
FROM golang:1.23.0-alpine AS builder
RUN apk add build-base
WORKDIR /app
COPY . /app
RUN go mod download
RUN go build cmd/riverPass/riverPass.go

FROM alpine:3.18.3
RUN apk add bind-tools ca-certificates
COPY --from=builder /app/riverPass /usr/local/bin/riverPass
RUN riverPass

ENTRYPOINT ["riverPass"]
