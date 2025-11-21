FROM rust:1-bullseye

RUN apt update && \
  apt install -y jq git && \
  apt clean all && \
  rm -rf /var/lib/apt/lists/* && \
  mkdir -p /tmp/ct-log-storage && \
  git clone https://github.com/Barre/compact_log.git /compactlog

WORKDIR /compactlog

RUN cargo build --locked --release

COPY ./entrypoint.sh /compactlog/entrypoint.sh
COPY ./post_start.sh /compactlog/post_start.sh

USER root:root

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=30s CMD curl -f http://127.0.0.1:${COMPACTLOG_BIND_PORT:-8080}/ct/v1/get-sth | grep '"tree_size":' || exit 1

ENTRYPOINT ["/compactlog/entrypoint.sh"]
