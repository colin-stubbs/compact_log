#!/bin/bash

# if DEBUG is set to true, dump the environment and enable verbose curl output.
if [ "${DEBUG}x" == "truex" ]; then
  echo "#### Environment ####"
  env | sort
  echo "####################"
  export CURL_EXTRA_ARGS="${CURL_EXTRA_ARGS} --verbose"
  export RUST_LOG=debug
else
  export CURL_EXTRA_ARGS="${CURL_EXTRA_ARGS} --silent"
fi

# ensure all expected variables are set with sane defaults.
export COMPACTLOG_ROOT_DIRECTORY=${COMPACTLOG_ROOT_DIRECTORY:-/tmp/ct-log-storage}
export COMPACTLOG_TRUSTED_ROOTS_PATH=${COMPACTLOG_TRUSTED_ROOTS_PATH:-/compactlog/trusted_roots}
export COMPACTLOG_BIND_ADDRESS=${COMPACTLOG_BIND_ADDRESS:-0.0.0.0}
export COMPACTLOG_BIND_PORT=${COMPACTLOG_BIND_PORT:-8080}
export COMPACTLOG_LOG_NAME=${COMPACTLOG_LOG_NAME:-compactlog}
export COMPACTLOG_LOG_MONITORING_URL=${COMPACTLOG_LOG_MONITORING_URL:-http://localhost/}
export COMPACTLOG_LOG_SUBMISSION_URL=${COMPACTLOG_LOG_SUBMISSION_URL:-http://localhost/}

# ensure the root directory and trusted roots directory exists
mkdir -p "${COMPACTLOG_ROOT_DIRECTORY}"
mkdir -p "${COMPACTLOG_TRUSTED_ROOTS_PATH}"

# add test to conform to default caddy healthcheck
test -f "${COMPACTLOG_ROOT_DIRECTORY}/status" || echo 'OK' > "${COMPACTLOG_ROOT_DIRECTORY}/status"

# run post start script - this runs in the background and *should* perform a loop waiting until compactlog has started before doing *things*.
nohup /compactlog/post_start.sh 1>/var/log/compactlog_post_start_stdout.log 2>/var/log/compactlog_post_start_stderr.log &

# start compactlog
cargo run --release

# EOF
