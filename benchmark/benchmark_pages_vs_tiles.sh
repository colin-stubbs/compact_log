#!/bin/bash

# Compare Pages Extension vs Static CT Tiles API
# Both fetch the same data (log entries) but in different formats

BASE_URL="${1:-http://localhost:8080}"

echo "Comparing Pages Extension vs Static CT Tiles at $BASE_URL"
echo ""

TREE_SIZE=$(curl -s "$BASE_URL/ct/v1/get-sth" | jq -r '.tree_size')
if [ -z "$TREE_SIZE" ] || [ "$TREE_SIZE" = "null" ]; then
    echo "Error: Could not get tree size. Is the server running?"
    exit 1
fi
echo "Tree size: $TREE_SIZE entries"
echo ""

PAGES_NEEDED=$(( (TREE_SIZE + 999) / 1000 ))
TILES_NEEDED=$(( (TREE_SIZE + 255) / 256 ))
LAST_PAGE_ENTRIES=$((TREE_SIZE % 1000))
if [ $LAST_PAGE_ENTRIES -eq 0 ] && [ $TREE_SIZE -gt 0 ]; then
    LAST_PAGE_ENTRIES=1000
fi
LAST_TILE_ENTRIES=$((TREE_SIZE % 256))
if [ $LAST_TILE_ENTRIES -eq 0 ] && [ $TREE_SIZE -gt 0 ]; then
    LAST_TILE_ENTRIES=256
fi

echo "Full tree requires:"
echo "  Pages: $PAGES_NEEDED"
echo "  Tiles: $TILES_NEEDED"
echo ""

ENTRIES_TO_TEST=$TREE_SIZE
PAGES_TO_FETCH=$PAGES_NEEDED
TILES_TO_FETCH=$TILES_NEEDED
echo "Fetching full tree..."

echo "=== Pages Extension API ==="
echo "Fetching $PAGES_TO_FETCH pages..."
START_TIME=$(date +%s)
PAGES_TOTAL_SIZE=0

for ((i=0; i<$PAGES_TO_FETCH; i++)); do
    SIZE=$(curl -s -w '%{size_download}' -o /dev/null \
        -H "Accept-Encoding: br, gzip, deflate" \
        "$BASE_URL/ct-pages/v1/page/$i")
    PAGES_TOTAL_SIZE=$((PAGES_TOTAL_SIZE + SIZE))
    if [ $((i % 10)) -eq 0 ]; then
        echo -n "."
    fi
done
echo ""

END_TIME=$(date +%s)
PAGES_TIME=$((END_TIME - START_TIME))

echo "Transfer size: $PAGES_TOTAL_SIZE bytes"
echo "Time: ${PAGES_TIME}s"
echo "Requests: $PAGES_TO_FETCH"
echo ""

echo "=== Static CT Tiles API ==="
echo "Fetching $TILES_TO_FETCH data tiles ($ENTRIES_TO_TEST entries)..."
START_TIME=$(date +%s)
TILES_TOTAL_SIZE=0

for ((i=0; i<$TILES_TO_FETCH; i++)); do
    if [ $i -lt 1000 ]; then
        tile_path=$(printf "%03d" $i)
    else
        thousands=$((i / 1000))
        remainder=$((i % 1000))
        tile_path=$(printf "x%03d/%03d" $thousands $remainder)
    fi
    
    if [ $i -eq $((TILES_TO_FETCH - 1)) ] && [ $LAST_TILE_ENTRIES -ne 256 ]; then
        tile_path="${tile_path}.p/${LAST_TILE_ENTRIES}"
    fi
    
    SIZE=$(curl -s -w '%{size_download}' -o /dev/null \
        -H "Accept-Encoding: br, gzip, deflate" \
        "$BASE_URL/tile/data/$tile_path")
    TILES_TOTAL_SIZE=$((TILES_TOTAL_SIZE + SIZE))
    if [ $((i % 25)) -eq 0 ]; then
        echo -n "."
    fi
done
echo ""

END_TIME=$(date +%s)
TILES_TIME=$((END_TIME - START_TIME))

echo "Transfer size: $TILES_TOTAL_SIZE bytes"
echo "Time: ${TILES_TIME}s"
echo "Requests: $TILES_TO_FETCH"
echo ""

echo "=== Summary ==="
echo "Pages Extension:"

PAGES_ENTRIES=$((PAGES_TO_FETCH * 1000))
if [ $PAGES_ENTRIES -gt $TREE_SIZE ]; then
    EXTRA_ENTRIES=$((PAGES_ENTRIES - TREE_SIZE))
    echo "  Entries fetched: $PAGES_ENTRIES (includes $EXTRA_ENTRIES beyond tree size)"
else
    echo "  Entries fetched: $PAGES_ENTRIES"
fi
echo "  Network transfer: $PAGES_TOTAL_SIZE bytes"
echo "  Bytes per entry: $((PAGES_TOTAL_SIZE / PAGES_ENTRIES)) bytes/entry"
echo "  Total requests: $PAGES_TO_FETCH"
echo "  Time: ${PAGES_TIME}s"
echo ""
echo "Static CT Tiles:"
echo "  Entries fetched: $ENTRIES_TO_TEST (exact, using partial tile)"
echo "  Network transfer: $TILES_TOTAL_SIZE bytes"
echo "  Bytes per entry: $((TILES_TOTAL_SIZE / ENTRIES_TO_TEST)) bytes/entry"
echo "  Total requests: $TILES_TO_FETCH"
echo "  Time: ${TILES_TIME}s"
echo ""

if [ $TILES_TOTAL_SIZE -gt 0 ]; then
    RATIO=$(echo "scale=2; ($PAGES_TOTAL_SIZE * 100) / $TILES_TOTAL_SIZE" | bc)
    echo "Pages Extension uses ${RATIO}% of the bandwidth compared to Static CT"
fi

echo ""
echo "=== Compression Test ==="
echo "Testing first page with different encodings:"
for encoding in "br" "gzip" "deflate" "identity"; do
    if [ "$encoding" = "identity" ]; then
        RESULT=$(curl -s -w 'Encoding: none, Size: %{size_download} bytes' \
            -o /dev/null "$BASE_URL/ct-pages/v1/page/0")
    else
        RESULT=$(curl -s -w "Encoding: $encoding, Size: %{size_download} bytes" \
            -H "Accept-Encoding: $encoding" \
            -o /dev/null "$BASE_URL/ct-pages/v1/page/0")
    fi
    echo "$RESULT"
done
