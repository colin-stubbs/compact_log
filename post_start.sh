#!/bin/sh

echo -n "### Waiting for compact_log to start and respond to HTTP requests..."
while ! curl -s http://127.0.0.1:${COMPACTLOG_BIND_PORT}/ >/dev/null 2>&1; do
  sleep 1
  echo -n "."
done
echo "OK!"

# The current date/time in simple UTC zoned RFC3339 format, used in our generated monitor.json files if we're auto-generating them.
NOW=`date -u -Iseconds | sed -r 's/\+00:00/Z/'`

# We need to grab the follow values *ONLY* after compactlog has started and is responding to HTTP requests...
# Used in our generated monitor.json files if we're auto-generating them, e.g. a long time ago in a galaxy far, far away...
NOT_AFTER_START=`curl -s http://127.0.0.1:${COMPACTLOG_BIND_PORT}/inclusion_request.json | jq --raw-output '.temporal_interval.start_inclusive'`
# Used in our generated monitor.json files if we're auto-generating them, e.g. now + years in simple UTC zoned RFC3339 format.
NOT_AFTER_LIMIT=`curl -s http://127.0.0.1:${COMPACTLOG_BIND_PORT}/inclusion_request.json | jq --raw-output '.temporal_interval.start_inclusive'`
# Log ID and public key...
COMPACTLOG_LOG_ID=`curl -s http://127.0.0.1:${COMPACTLOG_BIND_PORT}/inclusion_request.json | jq --raw-output '.log_id'`
COMPACTLOG_LOG_PUBLIC_KEY=`curl -s http://127.0.0.1:${COMPACTLOG_BIND_PORT}/inclusion_request.json | jq --raw-output '.key'`

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

echo "${MONITOR_RFC_JSON}" > "${COMPACTLOG_ROOT_DIRECTORY}/monitor-rfc6962.json"
echo "${MONITOR_STATIC_JSON}" > "${COMPACTLOG_ROOT_DIRECTORY}/monitor-static.json"
echo "${MONITOR_COMBINED_JSON}" > "${COMPACTLOG_ROOT_DIRECTORY}/monitor-combined.json"

# run testdata/insert.sh script - this runs in the background and *should* perform a loop waiting until compactlog has started before doing *things*.
export CTLOG_NAME=compactlog
export CTLOG_SUBMISSION_BASE_URL=http://127.0.0.1:${COMPACTLOG_BIND_PORT}/ct/v1
cd /compactlog/testdata
test -f /compactlog/testdata/insert.sh && /compactlog/testdata/insert.sh

# EOF
