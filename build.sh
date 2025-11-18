#!/bin/bash
# docker buildx build --platform linux/amd64,linux/arm64 --tag colinstubbs/compact_log:latest .
docker buildx build --platform linux/amd64,linux/arm64 --tag colinstubbs/compactlog:latest --push .
# EOF

