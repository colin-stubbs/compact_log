FROM rust:1-bullseye

COPY . /compactlog
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

WORKDIR /compactlog

RUN chmod +x /usr/local/bin/entrypoint.sh && \
  mkdir -p /tmp/ct-log-storage && \
  apt update && \
  apt install -y debian-keyring debian-archive-keyring apt-transport-https curl jq psmisc && \
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg && \
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list && \
  chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg && \
  chmod o+r /etc/apt/sources.list.d/caddy-stable.list && \
  apt update && \
  apt install -y caddy && \
  apt clean all && \
  rm -rf /var/lib/apt/lists/* && \
  cargo build --locked --release

USER root:root

EXPOSE 80

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
