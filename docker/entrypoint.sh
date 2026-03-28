#!/bin/bash
set -euo pipefail

# Container entrypoint for wirecov.
# Runs tshark on pcap files, collects lcov coverage data, generates reports.
#
# Environment variables (set by host Python):
#   PER_PCAP=0|1     — capture per-pcap attribution data
#   PROTOCOLS=0|1    — collect protocol tree (frame.protocols) info
#   TSHARK_FLAGS     — extra tshark flags (default: "-V -x -2")
#   SINGLE_PCAP      — if set, process only this filename from /pcaps

MODE=${1:-run}
shift || true

SRC_DIR="/src/wireshark"
BUILD_DIR="/src/wireshark/build"
BASELINE="/src/baseline.info"
PCAP_DIR="/pcaps"
OUTPUT_DIR="/output"
TSHARK="$BUILD_DIR/run/tshark"
TSHARK_FLAGS="${TSHARK_FLAGS:--V -x -2}"
PER_PCAP="${PER_PCAP:-0}"
PROTOCOLS="${PROTOCOLS:-0}"
SINGLE_PCAP="${SINGLE_PCAP:-}"

# Create organized output directory structure
mkdir -p "$OUTPUT_DIR/lcov"
mkdir -p "$OUTPUT_DIR/metadata"
mkdir -p "$OUTPUT_DIR/reports"
mkdir -p "$OUTPUT_DIR/reports-diff"
mkdir -p "$OUTPUT_DIR/html-full"
mkdir -p "$OUTPUT_DIR/html-dissectors"
[ "$PER_PCAP" = "1" ] && mkdir -p "$OUTPUT_DIR/per-pcap"
[ "$PROTOCOLS" = "1" ] && mkdir -p "$OUTPUT_DIR/protocols"

# Copy dissector dates if available
if [ -f /src/dissector_dates.json ]; then
    cp /src/dissector_dates.json "$OUTPUT_DIR/metadata/dissector_dates.json"
fi

collect_pcaps() {
    local pcaps=()
    if [ -n "$SINGLE_PCAP" ]; then
        if [ -f "$PCAP_DIR/$SINGLE_PCAP" ]; then
            pcaps=("$PCAP_DIR/$SINGLE_PCAP")
        fi
    else
        while IFS= read -r -d '' f; do
            pcaps+=("$f")
        done < <(find "$PCAP_DIR" -type f \( -name '*.pcap' -o -name '*.pcapng' -o -name '*.cap' \) -print0 2>/dev/null | sort -z)
    fi
    printf '%s\n' "${pcaps[@]}"
}

lcov_capture() {
    local output_file="$1"
    lcov --capture \
        --directory "$BUILD_DIR" \
        --base-directory "$SRC_DIR" \
        --no-external \
        --output-file "$output_file" \
        --quiet 2>/dev/null || true
}

lcov_merge() {
    local output_file="$1"
    shift
    local args=()
    for f in "$@"; do
        [ -f "$f" ] && args+=("-a" "$f")
    done
    if [ ${#args[@]} -gt 0 ]; then
        lcov "${args[@]}" -o "$output_file" --quiet 2>/dev/null || true
    fi
}

# Detect the SF: path prefix used by lcov for this build
detect_path_prefix() {
    local info_file="$1"
    local first_sf
    first_sf=$(grep -m1 '^SF:' "$info_file" 2>/dev/null || echo "")
    echo "$first_sf" | sed 's|^SF:||' | sed 's|/epan/.*||' | sed 's|/wiretap/.*||' | sed 's|/wsutil/.*||'
}

lcov_extract() {
    local input_file="$1"
    local output_file="$2"
    shift 2
    local patterns=("$@")

    # Try with provided patterns first
    lcov --extract "$input_file" "${patterns[@]}" \
        --output-file "$output_file" --quiet 2>/dev/null || true

    # Check if extraction worked
    local count=0
    if [ -f "$output_file" ]; then
        count=$(grep -c '^SF:' "$output_file" 2>/dev/null || echo "0")
    fi

    # If empty, retry with detected prefix
    if [ "$count" = "0" ] || [ "$count" = "" ]; then
        local prefix
        prefix=$(detect_path_prefix "$input_file")
        if [ -n "$prefix" ]; then
            local prefixed_patterns=()
            for p in "${patterns[@]}"; do
                # Replace leading */ with actual prefix
                prefixed_patterns+=("${prefix}/${p#\*/}")
            done
            lcov --extract "$input_file" "${prefixed_patterns[@]}" \
                --output-file "$output_file" --quiet 2>/dev/null || true
        fi
    fi
}

run_coverage() {
    # ============================================================
    # Phase 1: Capture INIT coverage (tshark with empty pcap)
    # This measures code that runs during initialization (proto_register,
    # proto_handoff, etc.) — NOT from pcap dissection.
    # ============================================================
    echo "WIRECOV_STATUS: Capturing initialization coverage (empty pcap)..."
    find "$BUILD_DIR" -name '*.gcda' -delete 2>/dev/null || true

    # Create minimal empty pcap (just header, no packets)
    python3 -c "
import struct
header = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
open('/tmp/empty.pcap', 'wb').write(header)
"
    # Run tshark on empty pcap — exercises init code only
    # shellcheck disable=SC2086
    "$TSHARK" -r /tmp/empty.pcap $TSHARK_FLAGS > /dev/null 2>&1 || true

    lcov_capture /tmp/init.run.info
    if [ -f /tmp/init.run.info ]; then
        lcov_merge "$OUTPUT_DIR/lcov/init.info" "$BASELINE" /tmp/init.run.info
        rm -f /tmp/init.run.info
    fi
    find "$BUILD_DIR" -name '*.gcda' -delete 2>/dev/null || true

    # ============================================================
    # Phase 2: Run user's pcaps
    # ============================================================
    local pcap_list
    pcap_list=$(collect_pcaps)

    if [ -z "$pcap_list" ]; then
        echo "WIRECOV_ERROR: No pcap files found in $PCAP_DIR"
        exit 1
    fi

    local total
    total=$(echo "$pcap_list" | wc -l | tr -d ' ')
    local count=0

    echo "WIRECOV_TOTAL: $total"

    while IFS= read -r pcap; do
        [ -z "$pcap" ] && continue
        local pcap_name
        pcap_name=$(basename "$pcap" | sed 's/\.[^.]*$//')
        count=$((count + 1))

        echo "WIRECOV_PROCESSING: $pcap_name ($count/$total)"

        if [ "$PER_PCAP" = "1" ]; then
            find "$BUILD_DIR" -name '*.gcda' -delete 2>/dev/null || true
        fi

        # shellcheck disable=SC2086
        "$TSHARK" -r "$pcap" $TSHARK_FLAGS > /dev/null 2>&1 || {
            echo "WIRECOV_WARN: tshark failed on $pcap_name (possibly malformed)"
        }

        if [ "$PER_PCAP" = "1" ]; then
            lcov_capture "/tmp/${pcap_name}.run.info"
            if [ -f "/tmp/${pcap_name}.run.info" ]; then
                lcov_merge "$OUTPUT_DIR/per-pcap/${pcap_name}.info" \
                    "$BASELINE" "/tmp/${pcap_name}.run.info"
                rm -f "/tmp/${pcap_name}.run.info"
            fi
        fi

        if [ "$PROTOCOLS" = "1" ]; then
            "$TSHARK" -r "$pcap" -T fields -e frame.protocols 2>/dev/null \
                | sort -u \
                > "$OUTPUT_DIR/protocols/${pcap_name}.protocols" || true
        fi

        echo "WIRECOV_DONE: $pcap_name"
    done <<< "$pcap_list"

    # ============================================================
    # Phase 3: Capture aggregate coverage
    # ============================================================
    echo "WIRECOV_STATUS: Capturing aggregate coverage..."
    lcov_capture /tmp/final.run.info

    if [ -f /tmp/final.run.info ]; then
        lcov_merge "$OUTPUT_DIR/lcov/total.info" "$BASELINE" /tmp/final.run.info
        rm -f /tmp/final.run.info
    fi

    if [ ! -f "$OUTPUT_DIR/lcov/total.info" ]; then
        echo "WIRECOV_ERROR: Failed to capture coverage data"
        exit 1
    fi

    # Debug: show sample paths
    echo "WIRECOV_DEBUG: Sample SF paths:"
    grep '^SF:' "$OUTPUT_DIR/lcov/total.info" | head -5 > /tmp/sf_sample.txt 2>/dev/null || true
    while read -r line; do
        echo "WIRECOV_DEBUG:   $line"
    done < /tmp/sf_sample.txt
    echo "WIRECOV_DEBUG: Total source files: $(grep -c '^SF:' "$OUTPUT_DIR/lcov/total.info" 2>/dev/null || echo 0)"

    # ============================================================
    # Phase 4: Extract filtered tracefiles
    # ============================================================
    echo "WIRECOV_STATUS: Extracting coverage subsets..."

    lcov_extract "$OUTPUT_DIR/lcov/total.info" "$OUTPUT_DIR/lcov/dissectors.info" \
        '*/epan/dissectors/*'

    lcov_extract "$OUTPUT_DIR/lcov/total.info" "$OUTPUT_DIR/lcov/wireshark.info" \
        '*/epan/*' '*/wiretap/*' '*/wsutil/*'

    # Also extract init dissector coverage for diff
    if [ -f "$OUTPUT_DIR/lcov/init.info" ]; then
        lcov_extract "$OUTPUT_DIR/lcov/init.info" "$OUTPUT_DIR/lcov/init-dissectors.info" \
            '*/epan/dissectors/*'
    fi

    # ============================================================
    # Phase 5: Generate genhtml reports
    # ============================================================
    local prefix
    prefix=$(detect_path_prefix "$OUTPUT_DIR/lcov/total.info")

    # Full HTML report
    echo "WIRECOV_STATUS: Generating full HTML coverage report..."
    local html_source="$OUTPUT_DIR/lcov/total.info"
    if [ -f "$OUTPUT_DIR/lcov/wireshark.info" ] && [ -s "$OUTPUT_DIR/lcov/wireshark.info" ]; then
        html_source="$OUTPUT_DIR/lcov/wireshark.info"
    fi
    genhtml "$html_source" \
        --output-directory "$OUTPUT_DIR/html-full" \
        --title "wirecov - Full Wireshark Coverage" \
        ${prefix:+--prefix "$prefix"} \
        --legend \
        --quiet 2>/dev/null || true

    # Dissector-only HTML report
    if [ -f "$OUTPUT_DIR/lcov/dissectors.info" ] && [ -s "$OUTPUT_DIR/lcov/dissectors.info" ]; then
        echo "WIRECOV_STATUS: Generating dissector HTML coverage report..."
        genhtml "$OUTPUT_DIR/lcov/dissectors.info" \
            --output-directory "$OUTPUT_DIR/html-dissectors" \
            --title "wirecov - Dissector Coverage" \
            ${prefix:+--prefix "$prefix"} \
            --legend \
            --quiet 2>/dev/null || true
    fi

    echo "WIRECOV_COMPLETE"
}

case "$MODE" in
    run)
        run_coverage
        ;;
    *)
        echo "Unknown mode: $MODE"
        echo "Usage: entrypoint.sh run"
        exit 1
        ;;
esac
