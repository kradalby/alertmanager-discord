FROM golang:1.18.1 as builder
WORKDIR /app
ADD . .
RUN CGO_ENABLED=0 GOOS=linux make build

FROM alpine:3.15 as certs

RUN apk --no-cache add ca-certificates && update-ca-certificates

FROM scratch
WORKDIR /

EXPOSE 9094/tcp

COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/alertmanager-discord .

CMD ["./alertmanager-discord"]
