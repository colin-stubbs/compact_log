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

# set to true to load test certs from testdata/
export LOAD_TEST_DATA=${LOAD_TEST_DATA:-false}
# set to 1+ to load generated certificates from testdata/generated/compact.chains.ndjson if it exists, requires LOAD_TEST_DATA to be true.
export LOAD_GENERATED_CERTS=${LOAD_GENERATED_CERTS:-}
# set to 1+ to auto-generate certificates, NOTE: this is dependent upon LOAD_TEST_DATA being true and will not occur if LOAD_TEST_DATA is false.
export GEN_TEST_CERTS=${GEN_TEST_CERTS:-}
# Location for generated certs are stored in an NDJSON file. Can be relative if the container will generate it itself using the generate.sh script and LOAD_TEST_DATA is true and GEN_TEST_CERTS is set to 1+.
# An NDJSON file is used to support very large numbers of certs/chains, e.g 1,000,000+ without the performance impact and inode related limitations that may be present for most file systems.
# If you've already generated it once (which is recommended as 1,000,000+ certs will take a long time), and want it in a non-default location (for example via volume file mount) simply adjust this variable
# NOTE: LOAD_TEST_DATA must still be true, and LOAD_GENERATED_CERTS must still be set to 1+ to add any cert chains from this file to the CT log.
# NOTE: You only need to load test data like this ONCE provided you establish persistent storage for ${ITKO_ROOT_DIRECTORY}. If you're dealing with a large number of certs/chains you will only want to load once.
export CERT_CHAINS_NDJSON=${CERT_CHAINS_NDJSON:-compact.chains.ndjson}

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
echo 'OK' > "${COMPACTLOG_ROOT_DIRECTORY}/status"

# add test ca certs to trusted roots if requested and the files exist
if [ ${LOAD_TEST_DATA} = "true" ]; then
  cd /compactlog/testdata
  # run generate.sh script to create extra test certs if it exists and is executable.
  # we need to do this here and now to ensure we can insert test-ca.pem before compactlog starts.
  # NOTE: we override GEN_TEST_CERTS to 1 to ensure we only generate a single cert/chain instead of, potentially, a very large number that will take a long time which should happen *AFTER* compactlog starts.
  test -x /compactlog/testdata/generate.sh && GEN_TEST_CERTS=1 /compactlog/testdata/generate.sh

  echo "### Adding test CA certificates to trusted roots..."
  for i in `find . -type f -name fake-ca\*.cert -o -type f -name test-ca.pem` ; do
    test -f "${i}" || continue
    DEST_NAME=`echo "${i}" | sed -r -e 's|^.*/||' -e 's/\.(cert|crt)$/.pem/'`
    cp -v "${i}" "${COMPACTLOG_TRUSTED_ROOTS_PATH}/${DEST_NAME}"
  done
fi

cd /compactlog

# run post start script - this runs in the background and *should* perform a loop waiting until compactlog has started before doing *things*.
nohup /compactlog/post_start.sh 1>/var/log/compactlog_post_start_stdout.log 2>/var/log/compactlog_post_start_stderr.log &

# start compactlog
cargo run --release

# EOF
