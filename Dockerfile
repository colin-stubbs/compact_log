FROM rust:1-bullseye

COPY . /compactlog

WORKDIR /compactlog

RUN mkdir -p /tmp/ct-log-storage && \
  cargo build --locked --release

USER root:root

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=5s CMD curl -f http://127.0.0.1:${COMPACTLOG_BIND_PORT:-8080}/ct/v1/get-sth | grep '"tree_size":' || exit 1

ENTRYPOINT ["/compactlog/entrypoint.sh"]
