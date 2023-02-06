FROM gcr.io/distroless/static-debian11

COPY gcp-iap-auth /

EXPOSE 8888
ENV GCP_IAP_AUTH_LISTEN_PORT 8888

USER 1000:1000

ENTRYPOINT ["/gcp-iap-auth"]
