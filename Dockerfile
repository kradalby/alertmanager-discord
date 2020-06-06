FROM golang:1.14.3 as builder
WORKDIR /app
ADD . .
RUN CGO_ENABLED=0 GOOS=linux make build


FROM alpine:latest

RUN apk --no-cache add ca-certificates
WORKDIR /

EXPOSE 9094/tcp

COPY --from=builder /app/alertmanager-discord .
CMD ["./alertmanager-discord"]
