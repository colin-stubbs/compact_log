# Go builder
FROM golang:alpine AS builder

# build the custom certspotter binary
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest && \
  xcaddy build --with github.com/mholt/caddy-ratelimit

# Final image
FROM alpine:3

RUN mkdir -p /usr/share/caddy && \
  echo "OK" > /usr/share/caddy/status && \
  mkdir -p /etc/caddy && \
  mkdir -p /var/log/caddy && \
  chown -R nobody:nogroup /var/log/caddy

WORKDIR /

COPY --from=builder --chmod=755 /go/caddy /usr/bin/caddy

USER nobody:nogroup

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=5s CMD wget -q -O - "http://127.0.0.1:${CADDY_LISTEN_PORT:-80}/status" | grep -E "^OK$" 2>/dev/null || exit 1

ENTRYPOINT ["/usr/bin/caddy", "run", "--config", "/etc/caddy/Caddyfile"]

# EOF