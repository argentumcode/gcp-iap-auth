FROM golang:latest as builder

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64
WORKDIR /gcp-iap-auth
COPY . .
RUN go build

# runtime image
FROM alpine
RUN apk add --no-cache ca-certificates
COPY --from=builder /gcp-iap-auth/gcp-iap-auth /app
EXPOSE 8888
ENV GCP_IAP_AUTH_LISTEN_PORT 8888
ENTRYPOINT ["/app"]