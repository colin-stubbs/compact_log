#!/bin/bash

# if DEBUG is set to true, dump the environment and enable verbose curl output.
if [ "${DEBUG}x" == "truex" ]; then
  echo "#### Environment ####"
  env | sort
  echo "####################"
  CURL_EXTRA_ARGS="${CURL_EXTRA_ARGS} --verbose"
else
  CURL_EXTRA_ARGS="${CURL_EXTRA_ARGS} --silent"
fi

LOAD_TEST_DATA=${LOAD_TEST_DATA:-false}
GEN_TEST_CERTS=${GEN_TEST_CERTS:-}

COMPACTLOG_TRUSTED_ROOTS_PATH=${COMPACTLOG_TRUSTED_ROOTS_PATH:-/compactlog/trusted_roots/}
COMPACTLOG_BIND_ADDRESS=${COMPACTLOG_BIND_ADDRESS:-0.0.0.0}
COMPACTLOG_BIND_PORT=${COMPACTLOG_BIND_PORT:-8080}
COMPACTLOG_LOG_NAME=${COMPACTLOG_LOG_NAME:-compactlog}
COMPACTLOG_LOG_MONITORING_URL=${COMPACTLOG_LOG_MONITORING_URL:-http://localhost/}
COMPACTLOG_LOG_SUBMISSION_URL=${COMPACTLOG_LOG_SUBMISSION_URL:-http://localhost/}

CADDY_LISTEN_PORT=${CADDY_LISTEN_PORT:-80}
CADDY_LISTEN_ADDRESS=${CADDY_LISTEN_ADDRESS:-0.0.0.0}
CADDY_CONFIG_FILE=${CADDY_CONFIG_FILE:-/compactlog/Caddyfile}
CADDY_CONFIG_ADAPTER=${CADDY_CONFIG_ADAPTER:-caddyfile}

if [ "${LOAD_TEST_DATA}x" == "truex" ] ; then
  # generate additional test certs if requested
  if [ "${GEN_TEST_CERTS}x" != "x" ] && [ ${GEN_TEST_CERTS} -ge 1 ]; then
    echo "### Creating ${GEN_TEST_CERTS} additional test leaf certificates..."
    # we use the generated sub-folder that can be a volume mounted store to speed up the process by avoiding re-generating keys and certificates all of the time.
    test -d /compactlog/testdata/generated || mkdir -p /compactlog/testdata/generated

    # ensure the intermediate cert and everthing else is created if necessary
    test -f /compactlog/testdata/generated/test-ca.privkey.pem || openssl ecparam -genkey -name prime256v1 -noout -out /compactlog/testdata/generated/test-ca.privkey.pem 1>/dev/null 2>&1
    test -f /compactlog/testdata/generated/test-ca.crt || openssl req -new -x509 -config /compactlog/testdata/fake-ca.cfg -set_serial 0x0406cafe -days 3650 -extensions v3_ca -inform pem -key /compactlog/testdata/generated/test-ca.privkey.pem -out /compactlog/testdata/generated/test-ca.crt 1>/dev/null 2>&1
    test -f /compactlog/testdata/generated/test-int-ca.privkey.pem || openssl ecparam -genkey -name prime256v1 -noout -out /compactlog/testdata/generated/test-int-ca.privkey.pem 1>/dev/null 2>&1
    test -f /compactlog/testdata/generated/test-int-ca.csr.pem || openssl req -new -sha256 -config /compactlog/testdata/int-ca.cfg -key /compactlog/testdata/generated/test-int-ca.privkey.pem -out /compactlog/testdata/generated/test-int-ca.csr.pem 1>/dev/null 2>&1
    test -f /compactlog/testdata/generated/test-int-ca.crt || openssl x509 -req -in /compactlog/testdata/generated/test-int-ca.csr.pem -sha256 -extfile /compactlog/testdata/fake-ca.cfg -extensions v3_int_ca -CA /compactlog/testdata/generated/test-ca.crt -CAkey /compactlog/testdata/generated/test-ca.privkey.pem -set_serial 0x53535353 -days 3600 -out /compactlog/testdata/generated/test-int-ca.crt 1>/dev/null 2>&1

    echo "### Adding test CA certificate to trusted roots..."
    test -d ${COMPACTLOG_TRUSTED_ROOTS_PATH} && cp -v /compactlog/testdata/generated/test-ca.crt ${COMPACTLOG_TRUSTED_ROOTS_PATH}/test-ca.pem

    for n in `seq 1 ${GEN_TEST_CERTS}`; do
      if [ ! -f /compactlog/testdata/generated/test-subleaf-${n}.crt ]; then
        echo "### Creating test subleaf ${n} certificate..."
        openssl ecparam -genkey -name prime256v1 -noout -out /compactlog/testdata/generated/test-subleaf-${n}.privkey.pem 1>/dev/null 2>&1
        openssl req -new -sha256 -key /compactlog/testdata/generated/test-subleaf-${n}.privkey.pem -subj "/C=AU/ST=Queensland/L=Brisbane/O=Good Roots Work/OU=Eng/CN=test-subleaf-${n}.example.com" -out /compactlog/testdata/generated/test-subleaf-${n}.csr.pem 1>/dev/null 2>&1
        openssl x509 -req -in /compactlog/testdata/generated/test-subleaf-${n}.csr.pem -sha256 -extfile /compactlog/testdata/int-ca.cfg -extensions v3_user -CA /compactlog/testdata/generated/test-int-ca.crt -CAkey /compactlog/testdata/generated/test-int-ca.privkey.pem -set_serial 0xdeadbeef -days 2600 -out /compactlog/testdata/generated/test-subleaf-${n}.crt 1>/dev/null 2>&1
      fi
    done
  fi
fi

nohup cargo run --release 1>/var/log/compact_log_stdout.log 2>/var/log/compact_log_stderr.log &

echo -n "### Waiting for compact_log to start and respond to HTTP requests..."
while ! curl -s http://127.0.0.1:${COMPACTLOG_BIND_PORT}/ >/dev/null 2>&1; do
  sleep 1
  echo -n "."
done
echo "OK!"

if [ ${LOAD_TEST_DATA} = "true" ]; then
  # generate additional test certs if requested
  if [ "${GEN_TEST_CERTS}x" != "x" ] && [ ${GEN_TEST_CERTS} -ge 1 ]; then
    echo "### Adding ${GEN_TEST_CERTS} additional test leaf certificates..."

    for n in `seq 1 ${GEN_TEST_CERTS}`; do
      if [ ! -f /compactlog/testdata/generated/test-subleaf-${n}-chain.json ]; then
        echo "### Creating test subleaf ${n} certificate chain..."
        cat /compactlog/testdata/generated/test-subleaf-${n}.crt /compactlog/testdata/generated/test-int-ca.crt /compactlog/testdata/generated/test-ca.crt | tr  -d '\n' | sed -E -e 's/^/{"chain":[/' -e 's/$/]}/' -e 's/-+BEGIN\sCERTIFICATE-+/"/g' -e 's/-+END\sCERTIFICATE-+/"/g' -e 's/-+END\sCERTIFICATE/",/g' > /compactlog/testdata/generated/test-subleaf-${n}-chain.json
      fi
      echo -n "### Adding test subleaf ${n} certificate chain..."
      test -s /compactlog/testdata/generated/test-subleaf-${n}-chain.json && curl -o /dev/null ${CURL_EXTRA_ARGS} -H 'Content-Type: application/json' -d "@/compactlog/testdata/generated/test-subleaf-${n}-chain.json" "http://127.0.0.1:${COMPACTLOG_BIND_PORT}/ct/v1/add-chain" && echo "OK!"
    done
  fi
fi

# The current date/time in simple UTC zoned RFC3339 format, used in our generated monitor.json files if we're auto-generating them.
NOW=`date -u -Iseconds | sed -r 's/\+00:00/Z/'`
# Used in our generated monitor.json files if we're auto-generating them, e.g. a long time ago in a galaxy far, far away...
NOT_AFTER_START=`curl -s http://127.0.0.1:${COMPACTLOG_BIND_PORT}/inclusion_request.json | jq --raw-output '.temporal_interval.start_inclusive'`
# Used in our generated monitor.json files if we're auto-generating them, e.g. now + years in simple UTC zoned RFC3339 format.
NOT_AFTER_LIMIT=`curl -s http://127.0.0.1:${COMPACTLOG_BIND_PORT}/inclusion_request.json | jq --raw-output '.temporal_interval.start_inclusive'`

COMPACTLOG_LOG_ID=`curl -s http://127.0.0.1:${COMPACTLOG_BIND_PORT}/inclusion_request.json | jq --raw-output '.log_id'`
COMPACTLOG_LOG_PUBLIC_KEY=`curl -s http://127.0.0.1:${COMPACTLOG_BIND_PORT}/inclusion_request.json | jq --raw-output '.key'`

mkdir -p /compactlog/monitor_json

# generate monitor.json files, refer to:
#  1. https://googlechrome.github.io/CertificateTransparency/log_lists.html
#  2. https://www.gstatic.com/ct/log_list/v3/log_list_schema.json

MONITOR_RFC_JSON='{
  "is_all_logs": false,
  "version": "1.0.0",
  "log_list_timestamp": "'${NOW}'",
  "name": "testing",
  "operators": [
    {
      "name": "testing",
      "email": [
        "test@example.com"
      ],
      "logs": [
        {
          "description": "'${COMPACTLOG_LOG_NAME}'",
          "log_id": "'${COMPACTLOG_LOG_ID}'",
          "key": "'${COMPACTLOG_LOG_PUBLIC_KEY}'",
          "url": "'${COMPACTLOG_LOG_MONITORING_URL}'",
          "mmd": 86400,
          "state": {
            "usable": {
              "timestamp": "'${NOW}'"
            }
          },
          "temporal_interval": {
            "start_inclusive": "'${NOT_AFTER_START}'",
            "end_exclusive": "'${NOT_AFTER_LIMIT}'"
          }
        }
      ],
      "tiled_logs": []
    }
  ]
}'

MONITOR_STATIC_JSON='{
  "is_all_logs": false,
  "version": "1.0.0",
  "log_list_timestamp": "'${NOW}'",
  "name": "testing",
  "operators": [
    {
      "name": "testing",
      "email": [
        "test@example.com"
      ],
      "logs": [],
      "tiled_logs": [
        {
          "description": "'${COMPACTLOG_LOG_NAME}'",
          "log_id": "'${COMPACTLOG_LOG_ID}'",
          "key": "'${COMPACTLOG_LOG_PUBLIC_KEY}'",
          "monitoring_url": "'${COMPACTLOG_LOG_MONITORING_URL}'",
          "submission_url": "'${COMPACTLOG_LOG_SUBMISSION_URL}'",
          "mmd": 60,
          "state": {
            "usable": {
              "timestamp": "'${NOW}'"
            }
          },
          "temporal_interval": {
            "start_inclusive": "'${NOT_AFTER_START}'",
            "end_exclusive": "'${NOT_AFTER_LIMIT}'"
          }
        }
      ]
    }
  ]
}'

MONITOR_COMBINED_JSON='{
  "is_all_logs": false,
  "version": "1.0.0",
  "log_list_timestamp": "'${NOW}'",
  "name": "testing",
  "operators": [
    {
      "name": "testing",
      "email": [
        "test@example.com"
      ],
      "logs": [
        {
          "description": "'${COMPACTLOG_LOG_NAME}'",
          "log_id": "'${COMPACTLOG_LOG_ID}'",
          "key": "'${COMPACTLOG_LOG_PUBLIC_KEY}'",
          "url": "'${COMPACTLOG_LOG_MONITORING_URL}'",
          "mmd": 86400,
          "state": {
            "usable": {
              "timestamp": "'${NOW}'"
            }
          },
          "temporal_interval": {
            "start_inclusive": "'${NOT_AFTER_START}'",
            "end_exclusive": "'${NOT_AFTER_LIMIT}'"
          }
        }
      ],
      "tiled_logs": [
        {
          "description": "'${COMPACTLOG_LOG_NAME}'",
          "log_id": "'${COMPACTLOG_LOG_ID}'",
          "key": "'${COMPACTLOG_LOG_PUBLIC_KEY}'",
          "monitoring_url": "'${COMPACTLOG_LOG_MONITORING_URL}'",
          "submission_url": "'${COMPACTLOG_LOG_SUBMISSION_URL}'",
          "mmd": 60,
          "state": {
            "usable": {
              "timestamp": "'${NOW}'"
            }
          },
          "temporal_interval": {
            "start_inclusive": "'${NOT_AFTER_START}'",
            "end_exclusive": "'${NOT_AFTER_LIMIT}'"
          }
        }
      ]
    }
  ]
}'

test -f /compactlog/monitor_json/monitor-rfc6962.json || echo "${MONITOR_RFC_JSON}" > /compactlog/monitor_json/monitor-rfc6962.json
test -f /compactlog/monitor_json/monitor-static.json || echo "${MONITOR_STATIC_JSON}" > /compactlog/monitor_json/monitor-static.json
test -f /compactlog/monitor_json/monitor-combined.json || echo "${MONITOR_COMBINED_JSON}" > /compactlog/monitor_json/monitor-combined.json

test -f ${CADDY_CONFIG_FILE} || echo "{
  log default {
    output file /var/log/caddy.log
    format json
  }
  auto_https off

  servers :${CADDY_LISTEN_PORT} {
    name http
  }
  default_bind ${CADDY_LISTEN_ADDRESS}
}

:${CADDY_LISTEN_PORT} {
  @blocked {
    path /deny
  }
  handle @blocked {
    respond \"Access denied\" 403
  }
  reverse_proxy /ct/* http://127.0.0.1:${COMPACTLOG_BIND_PORT}
  reverse_proxy /checkpoint http://127.0.0.1:${COMPACTLOG_BIND_PORT}
  reverse_proxy /tile/* http://127.0.0.1:${COMPACTLOG_BIND_PORT}
  reverse_proxy /issuer/* http://127.0.0.1:${COMPACTLOG_BIND_PORT}

  route /monitor-*.json {
    header Content-Type application/json
  }
  root * /compactlog/monitor_json/
  file_server
  log {
    output file /var/log/access.log {
      roll_size 10mb
      roll_keep 5
      roll_keep_for 1h
    }
  }
}" > ${CADDY_CONFIG_FILE} && caddy fmt --overwrite --config ${CADDY_CONFIG_FILE}

caddy run --adapter ${CADDY_CONFIG_ADAPTER} --config ${CADDY_CONFIG_FILE} --watch

killall -9 target/release/compactlog 2>/dev/null || true

# EOF
