FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o tcprp tcprp.go

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/tcprp /usr/local/bin/tcprp
ENTRYPOINT ["tcprp"]
